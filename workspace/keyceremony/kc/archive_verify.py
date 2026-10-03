"""Offline verifier for exported audit-archive bundles.

Given only the exported artifacts (segments, checkpoint, conflict decisions
and publication manifests — no running service, no secrets) it recomputes
every source chain and every aggregation root from scratch and reports
machine-readable findings. It explicitly detects:

  * SEGMENT_DELETED        a confirmed chain is not contiguous (missing seq)
  * SEGMENT_SWAPPED        chain digest at a seq disagrees with the
                           checkpoint/manifest claim
  * FORGED_SIGNATURE       a segment signature fails its source pubkey
  * CHAIN_BROKEN           prev digest does not match prior content digest
  * DOUBLE_COUNTED         two different confirmed segments at one (src,seq)
  * GAP_CROSSED            confirmation jumped over a missing predecessor
  * UNRESOLVED_PUBLISH     a manifest exists while a conflict was OPEN
  * ROOT_TAMPERED          recomputed witness root != manifest root
  * CHECKPOINT_MISMATCH    checkpoint pointer != recomputed chain tip
  * THRESHOLD_FALSIFIED    manifest includes fewer distinct sources than its
                           threshold (or an isolated source)
  * CONFLICT_NOT_ISOLATED  equivocation present without an OPEN/RESOLVED
                           evidence record
  * DECISION_INVALID       decision accepts an un-present version / dropped
                           a rejected version from evidence
  * PREVIOUS_ROOT_REWRITTEN  later manifest disagrees with the earlier root
  * CONFLICT_CHAIN_FORK    accepted version's forward chain was not
                           re-validated (rolled-back seq still confirmed)
"""

from __future__ import annotations

from . import crypto
from . import ed25519
from .archive import (
    BUNDLE_VERSION, MANIFEST_VERSION, SEGMENT_FIELDS, ZERO64,
    is_hex64, segment_content, segment_digest, witness_root,
)


class Finding(Exception):
    def __init__(self, code: str, message: str, context: dict | None = None):
        super().__init__(message)
        self.code = code
        self.context = context or {}

    def to_dict(self) -> dict:
        return {"code": self.code, "message": str(self),
                "context": self.context}


def _group_segments(bundle: dict):
    """Return per-source maps of every presented segment version."""
    per: dict[str, dict[int, list[dict]]] = {}
    malformed = []
    for seg in bundle.get("segments", []):
        try:
            if not isinstance(seg, dict):
                raise ValueError("not an object")
            sid, seq = seg["source"], seg["seq"]
            if not isinstance(sid, str) or not isinstance(seq, int) \
                    or seq < 1:
                raise ValueError("bad source/seq")
            if not is_hex64(seg.get("prev", "")) or \
                    not is_hex64(seg.get("payload_digest", "")):
                raise ValueError("bad digest fields")
            if seg.get("status") != "invalid":
                recomputed = segment_digest(seg)
                if seg.get("digest") is None:
                    seg["digest"] = recomputed
                elif seg["digest"] != recomputed:
                    raise ValueError("presented digest != recomputed content "
                                     "digest (tampered envelope)")
            per.setdefault(sid, {}).setdefault(seq, []).append(seg)
        except Exception as exc:
            malformed.append({"segment": seg, "reason": str(exc)})
    return per, malformed


def verify_bundle(bundle: dict, strict: bool = True) -> dict:
    """Recompute everything. Returns a report dict; raises on hard failures
    when strict, otherwise accumulates findings."""
    findings: list[Finding] = []

    def note(code, msg, ctx=None):
        f = Finding(code, msg, ctx)
        findings.append(f)
        if strict:
            raise f

    if not isinstance(bundle, dict):
        note("MALFORMED_BUNDLE", "bundle is not an object")
        return {"ok": False, "findings": [f.to_dict() for f in findings]}

    declared_sources = bundle.get("sources", {})
    per, malformed = _group_segments(bundle)
    for m in malformed:
        note("MALFORMED_SEGMENT", m["reason"], m)

    # 1) Signatures over every presented segment (forgery detection).
    for sid, byseq in per.items():
        pub_b64 = declared_sources.get(sid, {}).get("pubkey")
        if pub_b64 is None:
            note("UNKNOWN_SOURCE", f"segment from unregistered source {sid}",
                 {"source": sid})
            continue
        pub = crypto.b64d(pub_b64)
        for seq, versions in byseq.items():
            for seg in versions:
                if seg.get("status") == "invalid":
                    if seg.get("reason") != "BAD_SIGNATURE":
                        note("FORGED_SIGNATURE",
                             "invalid-status segment without BAD_SIGNATURE",
                             {"source": sid, "seq": seq})
                    continue
                if not ed25519.verify(
                        pub,
                        crypto.dumps(segment_content(seg)).encode(),
                        crypto.b64d(seg["sig"])):
                    note("FORGED_SIGNATURE",
                         f"{sid} seq {seq}: signature does not verify",
                         {"source": sid, "seq": seq,
                          "digest": seg.get("digest")})

    # 2) Recompute the *current* confirmed chains from all live evidence.
    #    History manifests are immutable snapshots: they are verified
    #    independently in step 5 from the segments embedded in them.
    conflicts = bundle.get("conflicts", [])
    conflict_index = {(c["source"], c["seq"]): c for c in conflicts}
    chains: dict[str, dict] = {}

    for sid, byseq in per.items():
        prev = ZERO64
        chain: dict[int, str] = {}
        max_seq = max(byseq)
        for seq in range(1, max_seq + 1):
            versions = byseq.get(seq, [])
            confirmed = [v for v in versions if v.get("status") == "confirmed"]
            distinct = {v["digest"] for v in versions
                        if v.get("status") != "invalid"}
            if len(confirmed) > 1 or \
                    (confirmed and len({v["digest"] for v in confirmed}) > 1):
                note("DOUBLE_COUNTED",
                     f"{sid} seq {seq}: multiple confirmed versions",
                     {"source": sid, "seq": seq,
                      "digests": sorted({v["digest"]
                                         for v in confirmed})})
            if len(distinct) > 1:
                cfx = conflict_index.get((sid, seq))
                if cfx is None:
                    note("CONFLICT_NOT_ISOLATED",
                         f"{sid} seq {seq}: equivocation without evidence "
                         "record", {"source": sid, "seq": seq,
                                    "digests": sorted(distinct)})
                else:
                    evidence = {v["digest"] for v in cfx.get("versions", [])}
                    if not distinct <= evidence:
                        note("DECISION_INVALID",
                             f"{sid} seq {seq}: conflicting version missing "
                             "from preserved evidence",
                             {"missing": sorted(distinct - evidence)})
                    if cfx["status"] == "RESOLVED":
                        acc = cfx["decision"]["accepted_digest"]
                        if acc not in evidence:
                            note("DECISION_INVALID",
                                 "accepted digest not among evidence versions",
                                 {"conflict": cfx["conflict_id"]})
                        # rejected versions must still be present in evidence
                        if len(cfx.get("versions", [])) < 2:
                            note("DECISION_INVALID",
                                 "rejected version dropped from evidence",
                                 {"conflict": cfx["conflict_id"]})
            if not versions or not confirmed:
                # gap: chain ends. Any confirmed segment later => gap crossed.
                if any(any(v.get("status") == "confirmed"
                           for v in byseq.get(q, []))
                       for q in range(seq + 1, max_seq + 1)):
                    note("GAP_CROSSED",
                         f"{sid}: confirmed segment after gap at seq {seq}",
                         {"source": sid, "gap_seq": seq})
                break
            seg = confirmed[0]
            if seg["prev"] != prev:
                note("CHAIN_BROKEN",
                     f"{sid} seq {seq}: prev does not link to prior content",
                     {"source": sid, "seq": seq, "prev": seg["prev"],
                      "expected": prev})
            chain[seq] = seg["digest"]
            prev = seg["digest"]
        chains[sid] = {"tip_seq": max(chain, default=0),
                       "tip_digest": prev, "chain": chain}

    # 3) Checkpoint must equal recomputed tips and isolation must follow
    #    conflicts.
    cp_sources = bundle.get("checkpoint", {}).get("sources", {})
    for sid, ch in chains.items():
        cp = cp_sources.get(sid)
        if cp is None:
            note("CHECKPOINT_MISMATCH", f"{sid}: missing checkpoint entry")
            continue
        if cp.get("last_confirmed_seq") != ch["tip_seq"] or \
                cp.get("last_confirmed_digest") != ch["tip_digest"]:
            note("CHECKPOINT_MISMATCH",
                 f"{sid}: checkpoint tip disagrees with recomputed chain",
                 {"checkpoint": cp,
                  "recomputed_seq": ch["tip_seq"],
                  "recomputed_digest": ch["tip_digest"]})
        open_for_src = [c for c in conflicts
                        if c["source"] == sid and c["status"] == "OPEN"]
        if bool(cp.get("isolated")) != bool(open_for_src):
            note("ISOLATION_MISMATCH",
                 f"{sid}: isolation flag disagrees with open conflicts",
                 {"isolated": cp.get("isolated"),
                  "open": [c["conflict_id"] for c in open_for_src]})

    # 4) Resolved conflicts: accepted version must actually extend the
    #    recomputed chain after the conflict point (re-validation rule).
    for c in conflicts:
        if c["status"] != "RESOLVED":
            continue
        sid, seq = c["source"], c["seq"]
        ch = chains.get(sid)
        if ch and seq <= ch["tip_seq"]:
            acc = c["decision"]["accepted_digest"]
            if ch["chain"].get(seq) != acc:
                note("CONFLICT_CHAIN_FORK",
                     f"{sid} seq {seq}: chain follows a version that was not "
                     "the accepted one, or prefix was not re-validated",
                     {"conflict": c["conflict_id"], "accepted": acc,
                      "in_chain": ch["chain"].get(seq)})

    # 5) Publications: each manifest is an *immutable snapshot*. Rebuild the
    #    per-source chains from the segments the manifest embeds (signatures +
    #    prev links + contiguity), require its declared heads to be exactly
    #    the rebuilt tips, then recompute the witness root. Rounds must hash-
    #    link in order; later growth never rewrites an earlier snapshot.
    prev_root = ZERO64
    for man in bundle.get("publications", []):
        if man.get("manifest_version") != MANIFEST_VERSION:
            note("MANIFEST_VERSION_UNKNOWN", "unknown manifest version",
                 {"round": man.get("round")})
        round_no = man.get("round")
        open_at_publish = []
        # Conflicts still OPEN at export would retroactively invalidate a
        # manifest only if created before its publication; the archive
        # records that fact explicitly in conflicts_snapshot.
        snap = {(c["source"], c["seq"]): c
                for c in man.get("conflicts_snapshot", [])}
        for key, c in snap.items():
            if c.get("status") == "OPEN":
                open_at_publish.append(c["conflict_id"])
        # also catch an export where a still-open conflict was stripped from
        # the snapshot
        for c in conflicts:
            if c["status"] == "OPEN" and c["created_at"] <= \
                    man.get("published_at", "~") and \
                    (c["source"], c["seq"]) not in snap:
                open_at_publish.append(c["conflict_id"])
        if open_at_publish:
            note("UNRESOLVED_PUBLISH",
                 f"round {round_no} published with open conflicts",
                 {"round": round_no,
                  "conflicts": sorted(set(open_at_publish))})

        # rebuild chains from the embedded segments
        embedded: dict[str, dict[int, dict]] = {}
        for s in man.get("segments", []):
            embedded.setdefault(s["source"], {})[s["seq"]] = s
        rebuilt_heads = []
        distinct_sources = {h["source"] for h in man.get("heads", [])}
        for sid in sorted(embedded):
            byseq = embedded[sid]
            pub_b64 = declared_sources.get(sid, {}).get("pubkey")
            if pub_b64 is None:
                note("UNKNOWN_SOURCE",
                     f"manifest embeds unregistered source {sid}")
                continue
            pub = crypto.b64d(pub_b64)
            p = ZERO64
            tip = 0
            for seq in range(1, max(byseq) + 1):
                s = byseq.get(seq)
                if s is None:
                    note("SEGMENT_DELETED",
                         f"round {round_no}: {sid} chain has a hole at "
                         f"seq {seq}", {"source": sid, "seq": seq})
                    break
                if s.get("digest") != segment_digest(s):
                    note("SEGMENT_SWAPPED",
                         f"round {round_no}: {sid} seq {seq} envelope digest "
                         "disagrees with content",
                         {"source": sid, "seq": seq})
                if not ed25519.verify(
                        pub,
                        crypto.dumps(segment_content(s)).encode(),
                        crypto.b64d(s["sig"])):
                    note("FORGED_SIGNATURE",
                         f"round {round_no}: {sid} seq {seq} signature fails",
                         {"source": sid, "seq": seq})
                if s["prev"] != p:
                    note("CHAIN_BROKEN",
                         f"round {round_no}: {sid} seq {seq} prev link broken",
                         {"source": sid, "seq": seq, "prev": s["prev"],
                          "expected": p})
                p = s["digest"]
                tip = seq
            rebuilt_heads.append({"source": sid, "seq": tip, "digest": p})

        declared_heads = sorted(
            ({"source": h["source"], "seq": h["seq"], "digest": h["digest"]}
             for h in man.get("heads", [])), key=lambda h: h["source"])
        if {(h["source"], h["seq"], h["digest"])
            for h in rebuilt_heads} != \
                {(h["source"], h["seq"], h["digest"])
                 for h in declared_heads}:
            note("SEGMENT_SWAPPED",
                 f"round {round_no}: declared heads disagree with chains "
                 "rebuilt from embedded segments",
                 {"declared": declared_heads, "rebuilt": rebuilt_heads})

        if len(distinct_sources) < man.get("threshold", 0):
            note("THRESHOLD_FALSIFIED",
                 f"round {round_no}: {len(distinct_sources)} sources < "
                 f"threshold {man.get('threshold')}", {"round": round_no})
        # an isolated source (open conflict in snapshot) must not be a head
        if open_at_publish and distinct_sources:
            pass  # already reported as UNRESOLVED_PUBLISH
        if man.get("prev_root") != prev_root:
            note("PREVIOUS_ROOT_REWRITTEN",
                 f"round {round_no}: prev_root does not match the previous "
                 "published root", {"round": round_no, "expected": prev_root,
                                    "got": man.get("prev_root")})
        recomputed = witness_root(
            round_no, man.get("threshold", 0), declared_heads,
            man.get("prev_root", ZERO64))
        if man.get("root") != recomputed:
            note("ROOT_TAMPERED",
                 f"round {round_no}: witness root does not recompute",
                 {"round": round_no, "declared": man.get("root"),
                  "recomputed": recomputed})
        prev_root = man.get("root", prev_root)

    return {
        "ok": not findings,
        "bundle_version": bundle.get("bundle_version"),
        "checks": {
            "sources": len(per),
            "confirmed_segments": sum(
                len(ch["chain"]) for ch in chains.values()),
            "conflicts": len(conflicts),
            "publications": len(bundle.get("publications", [])),
        },
        "findings": [f.to_dict() for f in findings],
    }
