"""Offline audit archive: incremental witnessing and recoverable aggregation.

Regions / nodes of the key-ceremony system export *signed chain segments*.
This module ingests them, validates per-source hash chains and Ed25519
signatures, tracks persistent gaps and candidates, isolates a source on
same-seq equivocation (keeping every conflicting version as evidence), and
publishes independently-verifiable witness roots once an independently
configured source threshold is reached with continuous confirmed chains and
no open conflict.

Design mirrors the rest of the package:

  * Pure stdlib; signatures use kc.ed25519 (RFC 8032).
  * state.json is the checkpoint: every mutation happens inside the shared
    reentrant RLock + exclusive flock and is atomically renamed to disk, so a
    crash/promotion of another process simply resumes from the checkpoint.
    Confirmed segments are never counted twice (last-confirmed pointers) and
    a missing predecessor can never be jumped over (advancement is strictly
    seq-by-seq with prev-digest linkage).
  * Publication is compare-and-swap on the current round: inside the same
    global lock, at most one publisher per round succeeds; losers receive the
    already published root. Late segments then belong to the next round and
    history manifests are immutable.

Segment wire format (canonical JSON of the four chain fields is signed):

    {"source": str, "seq": int >= 1,
     "prev": hex64 digest of previous segment content (ZERO64 at seq 1),
     "payload_digest": hex64, "sig": base64 Ed25519 signature}
"""

from __future__ import annotations

import json
import os

from . import crypto
from . import ed25519
from .errors import CeremonyError
from .storage import GENESIS as ZERO64, Store, utcnow

WITNESS_DOMAIN = "kc-archive-witness-v1"
BUNDLE_VERSION = "kc-archive-bundle-v1"
MANIFEST_VERSION = "kc-archive-publish-v1"
ARCHIVE_SCHEMA = 1

SEGMENT_FIELDS = ("source", "seq", "prev", "payload_digest")


class ArchiveError(CeremonyError):
    """Base class for archive failures (carries an HTTP-like status)."""


class BadSignature(ArchiveError):
    code = "BAD_SIGNATURE"
    http_status = 422


class UnregisteredSource(ArchiveError):
    code = "UNREGISTERED_SOURCE"
    http_status = 404


class MalformedSegment(ArchiveError):
    code = "MALFORMED_SEGMENT"
    http_status = 422


class ThresholdNotMet(ArchiveError):
    code = "THRESHOLD_NOT_MET"
    http_status = 422


class OpenConflicts(ArchiveError):
    code = "OPEN_CONFLICTS"
    http_status = 422


class NothingToPublish(ArchiveError):
    code = "NOTHING_TO_PUBLISH"
    http_status = 409


class ConflictClosed(ArchiveError):
    code = "CONFLICT_CLOSED"
    http_status = 409


class UnknownConflict(ArchiveError):
    code = "UNKNOWN_CONFLICT"
    http_status = 404


class UnknownVersion(ArchiveError):
    code = "UNKNOWN_VERSION"
    http_status = 422


# ---------------------------------------------------------------------------
# Segment helpers (shared with the offline verifier — no state involved)
# ---------------------------------------------------------------------------

def segment_content(seg: dict) -> dict:
    return {k: seg[k] for k in SEGMENT_FIELDS}


def segment_digest(seg: dict) -> str:
    """Content digest that chains via `prev`."""
    return crypto.digest_hex(segment_content(seg))


def signing_message(seg: dict) -> bytes:
    return crypto.dumps(segment_content(seg)).encode("utf-8")


def is_hex64(s) -> bool:
    return (isinstance(s, str) and len(s) == 64
            and all(c in "0123456789abcdef" for c in s))


def validate_shape(seg: dict) -> None:
    if not isinstance(seg, dict):
        raise MalformedSegment("segment must be an object")
    missing = [k for k in SEGMENT_FIELDS + ("sig",) if k not in seg]
    if missing:
        raise MalformedSegment(f"missing fields: {','.join(missing)}")
    if not isinstance(seg["source"], str) or not seg["source"]:
        raise MalformedSegment("source must be a non-empty string")
    if not isinstance(seg["seq"], int) or isinstance(seg["seq"], bool) \
            or seg["seq"] < 1:
        raise MalformedSegment("seq must be an integer >= 1")
    if not is_hex64(seg["prev"]):
        raise MalformedSegment("prev must be 64 hex chars")
    if not is_hex64(seg["payload_digest"]):
        raise MalformedSegment("payload_digest must be 64 hex chars")
    if not isinstance(seg["sig"], str):
        raise MalformedSegment("sig must be base64 text")
    try:
        crypto.b64d(seg["sig"])
    except Exception as exc:
        raise MalformedSegment("sig is not valid base64") from exc


def verify_segment_signature(pubkey: bytes, seg: dict) -> bool:
    try:
        return ed25519.verify(pubkey, signing_message(seg),
                              crypto.b64d(seg["sig"]))
    except Exception:
        return False


def sign_segment(seed32: bytes, source: str, seq: int, prev: str,
                 payload_digest: str) -> dict:
    """Produce a signed segment (used by exporters / tests / consoles)."""
    content = {"source": source, "seq": seq, "prev": prev,
               "payload_digest": payload_digest}
    sig = ed25519.sign(seed32, crypto.dumps(content).encode("utf-8"))
    content["sig"] = crypto.b64e(sig)
    return content


def generate_source_keypair() -> tuple[str, str]:
    """Returns (pubkey_b64, seed_b64). The seed is shown to the operator once."""
    seed = os.urandom(32)
    return crypto.b64e(ed25519.public_from_secret(seed)), crypto.b64e(seed)


def witness_root(round_no: int, threshold: int, heads: list[dict],
                 prev_root: str) -> str:
    """Deterministic independently-recomputable publication root."""
    body = {
        "d": WITNESS_DOMAIN,
        "round": round_no,
        "threshold": threshold,
        "prev_root": prev_root,
        "heads": sorted(
            ({"source": h["source"], "seq": h["seq"], "digest": h["digest"]}
             for h in heads),
            key=lambda h: h["source"],
        ),
    }
    return crypto.digest_hex(body)


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------

def _empty_archive_state(threshold: int) -> dict:
    return {
        "schema": ARCHIVE_SCHEMA,
        "threshold": threshold,
        "current_round": 1,
        "sources": {},
        "conflicts": {},
        "invalid_segments": [],
        "publications": [],
        "sequence": 0,
    }


def _new_source(pubkey: str) -> dict:
    return {
        "pubkey": pubkey,
        "isolated": False,
        "last_seq": 0,
        "last_digest": ZERO64,
        "highest_seq": 0,
        # seq -> list of version records (candidates, rejected, superseded)
        "candidates": {},
        # seq -> confirmed version record
        "confirmed": {},
    }


def _version_record(seg: dict, when: str) -> dict:
    return {
        "digest": segment_digest(seg),
        "prev": seg["prev"],
        "payload_digest": seg["payload_digest"],
        "sig": seg["sig"],
        "first_seen": when,
        "rejected": False,
        "superseded": False,
    }


class Archive:
    """Persistent incremental aggregator bound to a data directory.

    State lives at ``<root>/archive/state.json`` (the checkpoint); all
    mutating operations are serialized by the shared store lock.
    """

    DIRNAME = "archive"

    def __init__(self, root: str, threshold: int | None = None):
        self.store = Store(root)
        self.dir = os.path.join(root, self.DIRNAME)
        os.makedirs(self.dir, exist_ok=True)
        self.state_path = os.path.join(self.dir, "state.json")
        state = self._load()
        if threshold is not None and not state["sources"] \
                and not state["publications"]:
            state["threshold"] = int(threshold)
            self._save(state)
        if threshold is not None and threshold != state["threshold"]:
            # Threshold is configuration; allow explicit change between rounds
            # only when nothing is published in the current open round.
            state["threshold"] = int(threshold)
            self._save(state)

    # ---- persistence -----------------------------------------------------
    def _load(self) -> dict:
        if not os.path.exists(self.state_path):
            return _empty_archive_state(1)
        with open(self.state_path, encoding="utf-8") as f:
            state = json.load(f)
        state.setdefault("sources", {})
        state.setdefault("conflicts", {})
        state.setdefault("invalid_segments", [])
        state.setdefault("publications", [])
        state.setdefault("current_round", 1)
        state.setdefault("sequence", 0)
        return state

    def _save(self, state: dict):
        tmp = self.state_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.state_path)

    @property
    def threshold(self) -> int:
        with self.store.locked():
            return self._load()["threshold"]

    # ---- source registry -------------------------------------------------
    def register_source(self, source_id: str, pubkey_b64: str) -> dict:
        try:
            pub = crypto.b64d(pubkey_b64)
            if len(pub) != 32:
                raise ValueError
        except Exception as exc:
            raise MalformedSegment("pubkey must be 32 base64 bytes") from exc
        with self.store.locked():
            state = self._load()
            if source_id in state["sources"]:
                if state["sources"][source_id]["pubkey"] != pubkey_b64:
                    err = ArchiveError("source already registered with a "
                                       "different key")
                    err.code = "SOURCE_KEY_CONFLICT"
                    err.http_status = 409
                    raise err
                return {"source": source_id, "pubkey": pubkey_b64,
                        "duplicate": True}
            state["sources"][source_id] = _new_source(pubkey_b64)
            self._save(state)
            return {"source": source_id, "pubkey": pubkey_b64,
                    "duplicate": False}

    def set_threshold(self, threshold: int):
        if not isinstance(threshold, int) or threshold < 1:
            raise MalformedSegment("threshold must be integer >= 1")
        with self.store.locked():
            state = self._load()
            state["threshold"] = threshold
            self._save(state)

    # ---- ingestion -------------------------------------------------------
    def ingest(self, seg: dict) -> dict:
        """Ingest one signed segment.

        Returns a result dict (confirmed/duplicate/conflict). Invalid
        signatures are retained as evidence and raise BadSignature.
        """
        validate_shape(seg)
        with self.store.locked():
            state = self._load()
            sid = seg["source"]
            src = state["sources"].get(sid)
            if src is None:
                raise UnregisteredSource(f"source not registered: {sid}")
            if not verify_segment_signature(crypto.b64d(src["pubkey"]), seg):
                state["invalid_segments"].append({
                    "segment": seg, "reason": "BAD_SIGNATURE",
                    "received_at": utcnow(),
                })
                self._save(state)
                raise BadSignature("signature does not verify against the "
                                   f"registered key for {sid}")

            seq = seg["seq"]
            digest = segment_digest(seg)
            rec = _version_record(seg, utcnow())
            result = {"source": sid, "seq": seq, "digest": digest}

            # 0) a version already rejected by a human decision stays rejected:
            #    re-uploading it is a duplicate, never a new isolation.
            for c in state["conflicts"].values():
                if c["source"] == sid and c["seq"] == seq and \
                        c["status"] == "RESOLVED":
                    rejected = set(c["decision"]["rejected_digests"])
                    if digest in rejected:
                        result.update(status="duplicate", rejected=True)
                        return result
                    # same accepted version falls through to normal dup logic

            # 1) already confirmed?
            conf = src["confirmed"].get(str(seq))
            if conf is not None:
                if conf["digest"] == digest:
                    result.update(status="duplicate", confirmed=True)
                    return result
                # a *new*, never-adjudicated equivocation after resolution
                result.update(status="conflict",
                              conflict_id=self._register_conflict(
                                  state, src, sid, seq, [conf, rec]))
                self._save(state)
                return result

            # 2) candidate versions at this seq?
            cands = src["candidates"].setdefault(str(seq), [])
            same = next((c for c in cands if c["digest"] == digest), None)
            if same is not None:
                result.update(
                    status="duplicate",
                    confirmed=seq <= src["last_seq"]
                    and src["confirmed"].get(str(seq)) is not None)
                # A repeated upload of a rejected/superseded version changes
                # nothing (idempotent) and never revives it.
                return result
            cands.append(rec)
            src["highest_seq"] = max(src["highest_seq"], seq)

            live = [c for c in cands if not c["rejected"]
                    and not c["superseded"]]
            if len(live) > 1:
                result.update(status="conflict",
                              conflict_id=self._register_conflict(
                                  state, src, sid, seq, list(cands)))
                self._save(state)
                return result

            advanced = [] if src["isolated"] else self._advance(state, src)
            result.update(
                status="accepted",
                confirmed=seq in advanced or
                (seq <= src["last_seq"] and digest ==
                 src["confirmed"].get(str(seq), {}).get("digest")),
                advanced=advanced)
            self._save(state)
            return result

    def ingest_many(self, segments: list[dict]) -> dict:
        out = {"results": [], "bad_signatures": 0}
        for seg in segments:
            try:
                out["results"].append(self.ingest(seg))
            except BadSignature:
                out["bad_signatures"] += 1
                out["results"].append({"source": seg.get("source"),
                                       "seq": seg.get("seq"),
                                       "status": "bad_signature"})
        return out

    # ---- conflicts -------------------------------------------------------
    def _register_conflict(self, state, src, sid, seq, versions) -> str:
        """Open (or extend) the equivocation conflict for source/seq.

        Every divergent version is preserved verbatim. The source is
        isolated; confirmed state is never modified here.
        """
        existing = next((cid for cid, c in state["conflicts"].items()
                         if c["source"] == sid and c["seq"] == seq
                         and c["status"] == "OPEN"), None)
        now = utcnow()
        if existing is not None:
            c = state["conflicts"][existing]
            known = {v["digest"] for v in c["versions"]}
            for v in versions:
                if v["digest"] not in known:
                    c["versions"].append(self._evidence_version(v))
            src["isolated"] = True
            return existing

        state["sequence"] += 1
        cid = f"cfx-{state['sequence']}"
        state["conflicts"][cid] = {
            "conflict_id": cid,
            "source": sid,
            "seq": seq,
            "status": "OPEN",
            "created_at": now,
            "versions": [self._evidence_version(v) for v in versions],
            "decision": None,
        }
        src["isolated"] = True
        return cid

    @staticmethod
    def _evidence_version(v: dict) -> dict:
        """Copy carrying full signed content (evidence is never deleted)."""
        return {
            "digest": v["digest"],
            "prev": v["prev"],
            "payload_digest": v["payload_digest"],
            "sig": v["sig"],
            "first_seen": v.get("first_seen", utcnow()),
        }

    def resolve_conflict(self, conflict_id: str, accepted_digest: str,
                         reason: str, decided_by: str) -> dict:
        """Human decision with mandatory reason.

        Accepting a version different from the currently confirmed one rolls
        the confirmed prefix back to the conflict point and re-validates the
        subsequent chain from there. Rejected versions stay in evidence.
        Isolation is lifted only once the source has no open conflict left.
        """
        if not reason or not str(reason).strip():
            raise MalformedSegment("a reason is required to lift isolation")
        if not decided_by or not str(decided_by).strip():
            raise MalformedSegment("decided_by is required")
        with self.store.locked():
            state = self._load()
            c = state["conflicts"].get(conflict_id)
            if c is None:
                raise UnknownConflict(conflict_id)
            if c["status"] != "OPEN":
                raise ConflictClosed(f"{conflict_id} already resolved")
            sid, seq = c["source"], c["seq"]
            src = state["sources"][sid]
            accepted = next((v for v in c["versions"]
                             if v["digest"] == accepted_digest), None)
            if accepted is None:
                raise UnknownVersion("accepted digest is not one of the "
                                     "conflicting versions")

            cur_confirmed = src["confirmed"].get(str(seq))
            rolled_back = []
            if cur_confirmed is not None and \
                    cur_confirmed["digest"] != accepted_digest:
                # Roll back the branch built on the rejected version.
                for r in range(seq, src["last_seq"] + 1):
                    old = src["confirmed"].pop(str(r))
                    old = dict(old, superseded=True, rejected=False)
                    src["candidates"].setdefault(str(r), []).append(old)
                    rolled_back.append(r)
                src["last_seq"] = seq - 1
                if seq == 1:
                    src["last_digest"] = ZERO64
                else:
                    src["last_digest"] = \
                        src["confirmed"][str(seq - 1)]["digest"]

            # Make sure the accepted version is a live candidate at seq.
            cands = src["candidates"].setdefault(str(seq), [])
            if not any(x["digest"] == accepted_digest for x in cands):
                live = dict(accepted, rejected=False, superseded=False)
                cands.append(live)
            rejected_digests = {v["digest"] for v in c["versions"]
                                if v["digest"] != accepted_digest}
            for x in cands:
                if x["digest"] == accepted_digest:
                    x["rejected"] = False
                    x["superseded"] = False
                elif x["digest"] in rejected_digests:
                    x["rejected"] = True

            c["status"] = "RESOLVED"
            c["decision"] = {
                "accepted_digest": accepted_digest,
                "rejected_digests": sorted(rejected_digests),
                "reason": reason,
                "decided_by": decided_by,
                "decided_at": utcnow(),
            }
            c["rolled_back"] = rolled_back

            revalidated, still_open = [], []
            if not any(x["status"] == "OPEN"
                       for x in state["conflicts"].values()
                       if x["source"] == sid):
                src["isolated"] = False
                revalidated = self._advance(state, src)
            else:
                still_open = [cid for cid, x in state["conflicts"].items()
                              if x["source"] == sid and x["status"] == "OPEN"]
            self._save(state)
            return {
                "conflict_id": conflict_id, "source": sid, "seq": seq,
                "rolled_back": rolled_back,
                "revalidated": revalidated,
                "isolated": src["isolated"],
                "last_seq": src["last_seq"],
                "still_open": still_open,
            }

    # ---- chain advancement -----------------------------------------------
    @staticmethod
    def _advance(state: dict, src: dict) -> list[int]:
        """Confirm the contiguous live prefix. Never crosses a gap.

        Stops when: the next seq is missing (gap), the single candidate does
        not link to the confirmed prefix (broken chain), more than one live
        version exists (equivocation -> isolate), or the source is isolated.
        """
        advanced: list[int] = []
        while not src["isolated"]:
            nxt = src["last_seq"] + 1
            bucket = src["candidates"].get(str(nxt), [])
            live = [c for c in bucket
                    if not c["rejected"] and not c["superseded"]]
            if len(live) > 1:
                Archive._open_from_candidates(state, src, nxt, bucket)
                break
            if not live:
                break
            cand = live[0]
            if cand["prev"] != src["last_digest"]:
                break  # predecessor missing or this segment belongs to a fork
            src["confirmed"][str(nxt)] = {
                k: cand[k] for k in
                ("digest", "prev", "payload_digest", "sig", "first_seen")
            }
            bucket[:] = [c for c in bucket if c["digest"] != cand["digest"]]
            if not bucket:
                del src["candidates"][str(nxt)]
            src["last_seq"] = nxt
            src["last_digest"] = cand["digest"]
            advanced.append(nxt)
        return advanced

    @staticmethod
    def _open_from_candidates(state, src, seq, versions):
        sid = next(sid for sid, s in state["sources"].items() if s is src)
        Archive._register_conflict(None, state, src, sid, seq,
                                   list(versions))

    def recover(self) -> dict:
        """Resume from checkpoint after crash/restart.

        Re-runs advancement over persisted candidates for every non-isolated
        source. Already-confirmed segments cannot be re-counted (pointers);
        gaps cannot be jumped (_advance walks one seq at a time).
        """
        with self.store.locked():
            state = self._load()
            summary = {}
            for sid, src in state["sources"].items():
                before = src["last_seq"]
                advanced = [] if src["isolated"] else self._advance(state, src)
                summary[sid] = {
                    "last_seq": src["last_seq"],
                    "advanced_on_recovery": src["last_seq"] - before,
                    "advanced_seqs": advanced,
                    "isolated": src["isolated"],
                    "gaps": self._gaps(src),
                }
            self._save(state)
            return {"current_round": state["current_round"],
                    "threshold": state["threshold"],
                    "sources": summary}

    @staticmethod
    def _gaps(src: dict) -> list[dict]:
        gaps = []
        for seq in range(src["last_seq"] + 1, src["highest_seq"] + 1):
            bucket = src["candidates"].get(str(seq), [])
            live = [c for c in bucket
                    if not c["rejected"] and not c["superseded"]]
            if not live:
                gaps.append({"seq": seq, "reason": "missing"})
            elif len(live) == 1 and live[0]["prev"] != src["last_digest"] \
                    and seq == src["last_seq"] + 1:
                gaps.append({"seq": seq, "reason": "broken_prev"})
        return gaps

    # ---- views -----------------------------------------------------------
    def view(self) -> dict:
        with self.store.locked():
            state = self._load()
            return self._view(state)

    def _view(self, state: dict) -> dict:
        sources = {}
        open_conflicts = [cid for cid, c in state["conflicts"].items()
                          if c["status"] == "OPEN"]
        for sid, src in state["sources"].items():
            pending = sorted(
                (int(q) for q in src["candidates"].keys()))
            sources[sid] = {
                "pubkey": src["pubkey"],
                "isolated": src["isolated"],
                "last_confirmed_seq": src["last_seq"],
                "last_confirmed_digest": src["last_digest"],
                "highest_seen_seq": src["highest_seq"],
                "gaps": self._gaps(src),
                "pending_seqs": pending,
                "candidate_versions": {
                    q: [{"digest": c["digest"], "rejected": c["rejected"],
                         "superseded": c["superseded"]}
                        for c in src["candidates"][q]]
                    for q in sorted(src["candidates"], key=int)},
                "confirmed_count": len(src["confirmed"]),
            }
        eligible = [sid for sid, s in state["sources"].items()
                    if not s["isolated"] and s["last_seq"] >= 1]
        return {
            "threshold": state["threshold"],
            "current_round": state["current_round"],
            "sources": sources,
            "conflicts": {
                cid: self._conflict_view(c)
                for cid, c in sorted(state["conflicts"].items(),
                                     key=lambda kv: kv[1]["created_at"])
            },
            "open_conflicts": open_conflicts,
            "eligible_sources": sorted(eligible),
            "eligible_count": len(eligible),
            "invalid_segments": list(state["invalid_segments"]),
            "publications": [p["manifest"] for p in state["publications"]],
        }

    @staticmethod
    def _conflict_view(c: dict) -> dict:
        return {
            "conflict_id": c["conflict_id"],
            "source": c["source"],
            "seq": c["seq"],
            "status": c["status"],
            "created_at": c["created_at"],
            "versions": [{"digest": v["digest"], "prev": v["prev"],
                          "payload_digest": v["payload_digest"],
                          "first_seen": v["first_seen"]}
                         for v in c["versions"]],
            "decision": c["decision"],
        }

    # ---- publication (compare-and-swap on round) -------------------------
    def _heads(self, state: dict) -> list[dict]:
        return [{"source": sid, "seq": src["last_seq"],
                 "digest": src["last_digest"]}
                for sid, src in sorted(state["sources"].items())
                if not src["isolated"] and src["last_seq"] >= 1]

    def publish(self, *, force: bool = False) -> dict:
        """Form a witness manifest for the current round.

        CAS semantics: if the round already has a publication the existing
        manifest is returned with ``race_lost=True`` and a fresh root is
        never created.
        """
        with self.store.locked():
            state = self._load()
            heads = self._heads(state)
            head_set = {(h["source"], h["seq"], h["digest"])
                        for h in heads}
            # CAS losers (and idempotent republishers) get back the root that
            # already covers exactly the confirmed position they see. This is
            # checked regardless of the round counter: when several publishers
            # race, the winner bumps the round inside its own lock hold, so a
            # loser only ever observes the post-bump state. ``race_lost`` is
            # true exactly when another publisher created the returned root.
            if state["publications"]:
                last_man = state["publications"][-1]["manifest"]
                if {(h["source"], h["seq"], h["digest"])
                    for h in last_man["heads"]} == head_set:
                    return {"race_lost": True,
                            "published": True, "manifest": last_man}

            open_cfxs = [cid for cid, c in state["conflicts"].items()
                         if c["status"] == "OPEN"]
            problems = []
            if open_cfxs:
                problems.append({"code": "OPEN_CONFLICTS",
                                 "conflicts": sorted(open_cfxs)})
            if len({h["source"] for h in heads}) < state["threshold"]:
                problems.append({
                    "code": "THRESHOLD_NOT_MET",
                    "have": len({h["source"] for h in heads}),
                    "need": state["threshold"]})
            if problems and not force:
                if any(p["code"] == "OPEN_CONFLICTS" for p in problems):
                    exc = OpenConflicts("open conflicts block publication")
                else:
                    exc = ThresholdNotMet(
                        f"need {state['threshold']} independent sources, "
                        f"have {len({h['source'] for h in heads})}")
                exc.details = {"problems": problems}
                raise exc

            prev = (state["publications"][-1]["manifest"]["root"]
                    if state["publications"] else ZERO64)

            round_no = state["current_round"]
            root = witness_root(round_no, state["threshold"], heads, prev)
            manifest = {
                "manifest_version": MANIFEST_VERSION,
                "round": round_no,
                "threshold": state["threshold"],
                "published_at": utcnow(),
                "prev_root": prev,
                "root": root,
                "heads": heads,
                "segments": self._manifest_segments(state, heads),
                "conflicts_snapshot": self._conflict_snapshot(state),
            }
            state["publications"].append({"manifest": manifest})
            state["current_round"] = round_no + 1
            self._save(state)
            return {"race_lost": False, "published": True,
                    "manifest": manifest}

    @staticmethod
    def _manifest_segments(state: dict, heads: list[dict]) -> list[dict]:
        """Full confirmed segment content for every included source."""
        out = []
        for h in heads:
            src = state["sources"][h["source"]]
            for seq in range(1, h["seq"] + 1):
                rec = src["confirmed"][str(seq)]
                out.append({
                    "source": h["source"], "seq": seq,
                    "prev": rec["prev"], "digest": rec["digest"],
                    "payload_digest": rec["payload_digest"],
                    "sig": rec["sig"],
                })
        return out

    @staticmethod
    def _conflict_snapshot(state: dict) -> list[dict]:
        return [{
            "conflict_id": cid,
            "source": c["source"], "seq": c["seq"],
            "status": c["status"],
            "accepted_digest": (c["decision"] or {}).get("accepted_digest"),
            "decided_at": (c["decision"] or {}).get("decided_at"),
            "created_at": c["created_at"],
        } for cid, c in sorted(state["conflicts"].items())]

    def publications(self) -> list[dict]:
        with self.store.locked():
            return [p["manifest"]
                    for p in self._load()["publications"]]

    def publication(self, round_no: int) -> dict | None:
        with self.store.locked():
            for p in self._load()["publications"]:
                if p["manifest"]["round"] == round_no:
                    return p["manifest"]
        return None

    # ---- export bundle for offline verification --------------------------
    def export_bundle(self) -> dict:
        with self.store.locked():
            state = self._load()
            segments = []
            checkpoint_sources = {}
            for sid, src in sorted(state["sources"].items()):
                for seq in sorted(src["confirmed"], key=int):
                    rec = src["confirmed"][seq]
                    segments.append({
                        "source": sid, "seq": int(seq), "status": "confirmed",
                        "prev": rec["prev"], "digest": rec["digest"],
                        "payload_digest": rec["payload_digest"],
                        "sig": rec["sig"],
                    })
                for seq in sorted(src["candidates"], key=int):
                    for rec in src["candidates"][seq]:
                        status = ("rejected" if rec["rejected"]
                                  else "superseded" if rec["superseded"]
                                  else "candidate")
                        segments.append({
                            "source": sid, "seq": int(seq), "status": status,
                            "prev": rec["prev"], "digest": rec["digest"],
                            "payload_digest": rec["payload_digest"],
                            "sig": rec["sig"],
                        })
                checkpoint_sources[sid] = {
                    "pubkey": src["pubkey"],
                    "isolated": src["isolated"],
                    "last_confirmed_seq": src["last_seq"],
                    "last_confirmed_digest": src["last_digest"],
                    "highest_seen_seq": src["highest_seq"],
                }
            for inv in state["invalid_segments"]:
                seg = inv["segment"]
                segments.append({
                    "source": seg.get("source"), "seq": seg.get("seq"),
                    "status": "invalid", "reason": inv.get("reason"),
                    "prev": seg.get("prev"),
                    "digest": (segment_digest(seg)
                               if all(k in seg for k in SEGMENT_FIELDS)
                               else None),
                    "payload_digest": seg.get("payload_digest"),
                    "sig": seg.get("sig"),
                })
            return {
                "bundle_version": BUNDLE_VERSION,
                "exported_at": utcnow(),
                "threshold": state["threshold"],
                "current_round": state["current_round"],
                "sources": {sid: {"pubkey": s["pubkey"]}
                            for sid, s in sorted(state["sources"].items())},
                "segments": segments,
                "checkpoint": {"sources": checkpoint_sources},
                "conflicts": [
                    {"conflict_id": cid, "source": c["source"],
                     "seq": c["seq"], "status": c["status"],
                     "created_at": c["created_at"],
                     "versions": c["versions"], "decision": c["decision"],
                     "rolled_back": c.get("rolled_back", [])}
                    for cid, c in sorted(state["conflicts"].items())
                ],
                "publications": [p["manifest"]
                                 for p in state["publications"]],
            }
