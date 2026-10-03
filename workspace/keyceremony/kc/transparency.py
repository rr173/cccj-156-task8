"""Caller-facing transparency log for the key version directory.

Every key lifecycle change (creation, activation, handover/retirement,
erasure) produces one *canonical leaf* binding:

    purpose, version, version id, public signing key + fingerprint,
    previous status / next status (state summary), ceremony id and the
    audit-entry hash that authorizes the change.

Only public material ever enters a leaf: signing public keys, fingerprints,
state summaries and audit references. Shares, signing seeds and sealed wraps
are never logged (the orchestrator constructs leaves from public fields).

Leaves enter an append-only RFC 6962-style Merkle tree. Each commit also
publishes a signed tree head {tree_size, root_hash, prev_head_hash,
issued_at}. Inclusion proofs and consistency proofs let a client holding an
old (size, root) confirm a new head is a strict append: truncation,
reordering, key substitution, forged state jumps and proofs spliced from
another tree all fail verification.

Single commit boundary
----------------------
"allocate index -> write leaf -> update tree nodes -> publish head" is one
durable transaction. An intent file (``pending/<txn>.json``) is fsynced
before the leaf line is appended; the checkpoint is published with a single
atomic rename. On reopen, an intent is rolled forward (leaf durable, rename
missed) or back (dangling leaf line truncated), so a process dying between
any two steps exposes only the complete old head or the complete new head.

The builder runs embedded in the orchestrator (checkpoint inside the main
locked ``state.json``; multi-process safety comes from the store flock and
atomic state rename) or standalone against its own directory (several
service processes appending under a dedicated flock).

Gossip / split-view
-------------------
External observers may submit signed heads they saw. A different root at the
same tree size (equivocation), or a larger head that is not a verifiable
consistency extension of a smaller local head, records a split-view event
and freezes publication. Freezing never invalidates historical signatures;
it blocks new key materialization/activation until an operator selects a
branch verifiably extending the last trusted head and records the reason.
Rejected heads stay on file as evidence.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import threading
import time

from . import crypto, ed25519
from .errors import CeremonyError

ZERO = "0" * 64
LEAF_PREFIX = 0x00
NODE_PREFIX = 0x01
HEAD_DOMAIN = "kc-transparency-head-v1"
CHECKPOINT_KEY = "transparency"

# lifecycle events recorded in leaves
CREATED = "CREATED"        # first-generation version materialized ACTIVE
STAGED = "STAGED"          # successor materialized during a handover window
ACTIVATED = "ACTIVATED"    # staged successor became the single current key
RETIRED = "RETIRED"        # predecessor displaced by a newer ACTIVE version
ERASED = "ERASED"          # private material zeroized; public material stays
NONE_STATE = "NONE"

ALLOWED_TRANSITIONS = {
    CREATED: (NONE_STATE,),
    STAGED: (NONE_STATE,),
    ACTIVATED: (STAGED, NONE_STATE),
    # a first-generation key is logged CREATED=ACTIVE directly and later
    # retires straight from that state; a rotated successor retires from
    # ACTIVATED.
    RETIRED: (ACTIVATED, CREATED),
    ERASED: (RETIRED, ACTIVATED, CREATED),
}

# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class TransparencyError(CeremonyError):
    code = "TRANSPARENCY_ERROR"
    http_status = 409


class DuplicateBusinessEvent(TransparencyError):
    """Same lifecycle change was already logged; original index is attached."""

    code = "TRANSPARENCY_DUPLICATE"
    http_status = 409

    def __init__(self, index: int, message: str = ""):
        super().__init__(message or f"business event already logged at {index}")
        self.leaf_index = index


class ContradictoryLifecycle(TransparencyError):
    """The same version would make a transition that cannot follow its prior
    logged state (or a different key already owns purpose/version)."""

    code = "TRANSPARENCY_CONTRADICTION"
    http_status = 409


class PublicationFrozen(TransparencyError):
    """A split-view is open: publication (and new key activation) is blocked
    until an operator resolves it with a recorded reason."""

    code = "TRANSPARENCY_FROZEN"
    http_status = 409

    def __init__(self, message: str = "", *, split_id: str | None = None):
        super().__init__(message or "transparency publication is frozen")
        self.split_id = split_id


class UnknownLeaf(TransparencyError):
    code = "TRANSPARENCY_UNKNOWN_LEAF"
    http_status = 404


class BadHead(TransparencyError):
    code = "TRANSPARENCY_BAD_HEAD"
    http_status = 422


class SplitResolutionRejected(TransparencyError):
    code = "TRANSPARENCY_RESOLUTION_REJECTED"
    http_status = 409


def utcnow_ts(clock) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))


# ===========================================================================
# canonical leaf / head construction (mirrored verbatim in transparency.html)
# ===========================================================================

def make_leaf(purpose: str, version: int, version_id: str,
              fingerprint: str, signing_pub: str, event: str,
              prev_state: str, ceremony_id: str, audit_ref: str) -> dict:
    return {
        "purpose": purpose,
        "version": int(version),
        "version_id": version_id,
        "fingerprint": fingerprint,
        "signing_pub": signing_pub,
        "event": event,
        "state": {"prev": prev_state, "next": event},
        "ceremony_id": ceremony_id,
        "audit_ref": audit_ref,
    }


def business_key(leaf: dict) -> str:
    """Identity of one business change. An audit entry authorizes exactly one
    leaf; re-delivery returns the already allocated index."""
    return f"{leaf['audit_ref']}|{leaf['version_id']}|{leaf['event']}"


def leaf_hash(leaf: dict) -> bytes:
    return hashlib.sha256(
        bytes([LEAF_PREFIX]) + crypto.dumps(leaf).encode("utf-8")).digest()


def leaf_hash_hex(leaf: dict) -> str:
    return leaf_hash(leaf).hex()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(bytes([NODE_PREFIX]) + left + right).digest()


def empty_root_hex() -> str:
    return hashlib.sha256(b"").hexdigest()


HEAD_FIELDS = ("domain", "tree_size", "root_hash", "issued_at",
               "prev_head_hash")


def head_content(size: int, root_hex: str, issued_at: str,
                 prev_head: str = ZERO) -> dict:
    return {"domain": HEAD_DOMAIN, "tree_size": int(size),
            "root_hash": root_hex, "issued_at": issued_at,
            "prev_head_hash": prev_head}


def head_hash(head: dict) -> str:
    return crypto.digest_hex({k: head[k] for k in HEAD_FIELDS})


def sign_head(seed: bytes, head: dict) -> str:
    return crypto.b64e(
        ed25519.sign(seed,
                     crypto.dumps({k: head[k] for k in HEAD_FIELDS}).encode()))


def verify_head_signature(pub: bytes, head: dict) -> bool:
    if not all(k in head for k in HEAD_FIELDS + ("tree_head_sig",)):
        return False
    if head["domain"] != HEAD_DOMAIN:
        return False
    try:
        return ed25519.verify(
            pub, crypto.dumps({k: head[k] for k in HEAD_FIELDS}).encode(),
            crypto.b64d(head["tree_head_sig"]))
    except Exception:
        return False


# ===========================================================================
# Merkle tree: root, inclusion proof, consistency proof
#
# All proof generators are deterministic functions of the ordered leaf hash
# list; the verifiers re-derive every node position from (size, index), so a
# server can choose hash values but cannot move nodes or splice another tree.
# The exhaustive tests in tests/test_transparency.py brute-force every tree
# size up to several hundred.
# ===========================================================================

def _mth(hashes: list[bytes], start: int, length: int) -> bytes:
    """Root of the perfect subtree covering [start, start+length); length a
    power of two."""
    if length == 1:
        return hashes[start]
    half = length >> 1
    return node_hash(_mth(hashes, start, half),
                     _mth(hashes, start + half, half))


def tree_root(hashes: list[bytes]) -> bytes:
    if not hashes:
        return hashlib.sha256(b"").digest()
    n = len(hashes)
    k = 1 << (n.bit_length() - 1)
    if k == n:
        return _mth(hashes, 0, n)
    return node_hash(_mth(hashes, 0, k), _subtree_range(hashes, k, n - k))


def _subtree_range(hashes: list[bytes], start: int, length: int) -> bytes:
    """Root over an arbitrary (non-power-of-two) trailing range: RFC fold of
    complete subtrees, largest first."""
    if length == 1:
        return hashes[start]
    k = 1 << (length.bit_length() - 1)
    if k == length:
        return _mth(hashes, start, length)
    return node_hash(_mth(hashes, start, k),
                     _subtree_range(hashes, start + k, length - k))


# ---- inclusion -------------------------------------------------------------

def _hp2(n: int) -> int:
    """largest power of two strictly smaller than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def inclusion_proof(index: int, size: int, hashes: list[bytes]) -> list[str]:
    if size <= 0 or not 0 <= index < size or len(hashes) < size:
        raise ValueError("leaf index out of range")

    def path(m: int, n: int, start: int) -> list[bytes]:
        if n == 1:
            return []
        k = _hp2(n)
        if m < k:
            return path(m, k, start) + [_subtree_range(hashes, start + k, n - k)]
        return [_mth(hashes, start, k)] + path(m - k, n - k, start + k)

    return [h.hex() for h in path(index, size, 0)]


def _as_node(v) -> bytes:
    """Proof nodes arrive as hex strings on the wire; accept raw bytes too
    so library callers can pass either form."""
    return bytes.fromhex(v) if isinstance(v, str) else bytes(v)


def verify_inclusion(index: int, size: int, proof,
                     leaf_h: bytes, root: bytes) -> bool:
    """Position-bound inclusion verifier. Every node position is derived from
    (index, size) using the same recursive decomposition as the generator; a
    server may supply sibling *hashes* but cannot move a node or splice in a
    path from a differently shaped tree. The recomputed root is compared."""
    try:
        if size <= 0 or not 0 <= index < size:
            return False

        it = iter(proof)

        def rebuild(m: int, n: int) -> bytes:
            if n == 1:
                return leaf_h
            k = _hp2(n)
            if m < k:
                return node_hash(rebuild(m, k), _as_node(next(it)))
            return node_hash(_as_node(next(it)), rebuild(m - k, n - k))

        computed = rebuild(index, size)
        if next(it, None) is not None:
            return False
        return computed == root
    except (ValueError, TypeError, StopIteration):
        return False


# ---- consistency -----------------------------------------------------------
#
# Derived from the same recursive tree decomposition as inclusion. Slots are
# fully determined by (old_size, new_size); the server only supplies hashes.
# The verifier rebuilds BOTH the old-region root and the new-region root and
# compares the old one to the client's pinned old root (preimage binding), so
# truncation, reordering and foreign-tree splicing all fail.
#
#   m == k : convergence subtree; its root is the pinned old root when the
#            initial m is itself a power of two, so that first slot is
#            implicit and omitted from the wire proof;
#   m <  k : recurse into the left block, then take the right sibling;
#   m >  k : take the trailing (new-only) right block, recurse into the
#            suffix, then take the shared complete left block.

def _consistency_slots(m: int, n: int, start: int = 0):
    if m == n:
        yield ("seed", start, m)
        return
    k = _hp2(n)
    if m > k:
        yield ("right", start + k, n - k)
        yield from _consistency_slots(m - k, n - k, start + k)
        yield ("left", start, k)
    elif m == k:
        yield ("seed", start, k)
        yield ("right", start + k, n - k)
    else:
        yield from _consistency_slots(m, k, start)
        yield ("right", start + k, n - k)


def consistency_proof(old_size: int, new_size: int,
                      hashes: list[bytes]) -> list[str]:
    if old_size < 0 or new_size < old_size or new_size > len(hashes):
        raise ValueError("size range invalid")
    if old_size in (0, new_size):
        return []
    out = []
    for i, (kind, start, length) in enumerate(
            _consistency_slots(old_size, new_size)):
        if kind == "seed" and i == 0 and (old_size & (old_size - 1)) == 0:
            continue  # implicit: equals the client's pinned old root
        out.append(_subtree_range(hashes, start, length).hex())
    return out


def verify_consistency(old_size: int, new_size: int, proof: list[str],
                       old_root: bytes, new_root: bytes) -> bool:
    try:
        if old_size < 0 or old_size > new_size:
            return False
        if old_size == 0:
            return old_root == hashlib.sha256(b"").digest() and proof == []
        if old_size == new_size:
            return old_root == new_root and proof == []
        it = iter(proof)
        implicit = (old_root if (old_size & (old_size - 1)) == 0 else None)

        def rebuild(m: int, n: int, seed):
            # returns (old_region_root, new_region_root)
            if m == n:
                h = seed if seed is not None else _as_node(next(it))
                return h, h
            k = _hp2(n)
            if m > k:
                right = _as_node(next(it))
                a, b = rebuild(m - k, n - k, None)
                if b != right:
                    # the server claimed a trailing block that its own suffix
                    # does not produce -> reject
                    return b"\x00" * 32, b"\x01" * 32
                left = _as_node(next(it))
                return node_hash(left, a), node_hash(left, b)
            if m == k:
                s = seed if seed is not None else _as_node(next(it))
                right = _as_node(next(it))
                return s, node_hash(s, right)
            a, b = rebuild(m, k, seed)
            right = _as_node(next(it))
            return a, node_hash(b, right)

        old_h, new_h = rebuild(old_size, new_size, implicit)
        if next(it, None) is not None:
            return False
        return old_h == old_root and new_h == new_root
    except (ValueError, TypeError, StopIteration, IndexError):
        return False


# ===========================================================================
# durable builder
# ===========================================================================

_LOCKS: dict[str, threading.RLock] = {}
_LOCKS_GUARD = threading.Lock()


def _process_lock_for(path: str) -> threading.RLock:
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(os.path.realpath(path), threading.RLock())


def _fresh_checkpoint() -> dict:
    return {
        "size": 0,
        "root": empty_root_hex(),
        "heads": [],            # signed heads, index n-1 for size n
        "zero_head": None,      # lazily-signed size-0 head
        "business": {},         # business_key -> leaf index (dedup)
        "version_states": {},   # purpose|version -> state summary
        "version_index": {},    # purpose|version -> latest leaf index
        "leaf_records": [],     # embedded mode durable leaf bodies
        "frozen": None,         # split-view record when publication frozen
        "splits": [],           # all split-view events (evidence)
        "observations": [],     # gossip observations retained as evidence
        "resolutions": [],      # operator branch decisions with reasons
        "trusted_size": 0,      # last verified extension anchor
        "trusted_root": empty_root_hex(),
    }


class TransparencyLog:
    """Append-only transparency builder.

    embedded=True stores checkpoint/evidence inside the orchestrator state
    dict (caller provides lock + persistence); embedded=False is a standalone
    directory with its own flock, leaves file and atomic checkpoint.
    """

    def __init__(self, path: str | None = None, service_seed: bytes | None =
                 None, state: dict | None = None, clock=time.time,
                 embedded: bool = False):
        self.clock = clock
        self.embedded = embedded
        if embedded:
            if state is None:
                raise ValueError("embedded log needs the shared state dict")
            self.path = None
            self.state_root = state
            self.seed = service_seed
            if CHECKPOINT_KEY not in self.state_root:
                self.state_root[CHECKPOINT_KEY] = _fresh_checkpoint()
            self.cp = self.state_root[CHECKPOINT_KEY]
        else:
            if path is None:
                raise ValueError("standalone log needs a directory")
            self.path = path
            os.makedirs(os.path.join(path, "pending"), exist_ok=True)
            self.leaves_path = os.path.join(path, "leaves.log")
            self.cp_path = os.path.join(path, "checkpoint.json")
            self.lock_path = os.path.join(path, ".lock")
            self._lock_f = None
            self.seed = service_seed or self._service_seed(path)
            # The constructor runs *before* the caller takes the lock, so it
            # must not resolve intents (that would race another process).
            # A cheap read gives an initial view; locked() reloads and runs
            # crash recovery while holding the exclusive flock.
            self.cp = self._load_checkpoint()

    # ---- standalone locking ------------------------------------------------
    @contextlib.contextmanager
    def locked(self):
        if self.embedded:
            yield self
            return
        rlock = _process_lock_for(self.lock_path)
        rlock.acquire()
        lf = open(self.lock_path, "w")
        fcntl.flock(lf.fileno(), fcntl.LOCK_EX)
        try:
            self._recover()           # resolve intents, then reload latest
            yield self
        finally:
            fcntl.flock(lf.fileno(), fcntl.LOCK_UN)
            lf.close()
            rlock.release()

    @staticmethod
    def _service_seed(path: str) -> bytes:
        ident = os.path.join(path, "log.identity")
        os.makedirs(path, exist_ok=True)
        # Atomically claim the identity: the first process to create the file
        # wins; every other process reads the winner's seed so all log
        # signatures share one key even under concurrent bootstrap.
        seed = os.urandom(32)
        try:
            fd = os.open(ident, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, seed)
                os.fsync(fd)
            finally:
                os.close(fd)
        except FileExistsError:
            pass
        with open(ident, "rb") as f:
            return f.read()

    # ---- persistence -------------------------------------------------------
    def _load_checkpoint(self) -> dict:
        if os.path.exists(self.cp_path):
            with open(self.cp_path, encoding="utf-8") as f:
                return json.load(f)
        return _fresh_checkpoint()

    def _read_leaves(self) -> list[dict]:
        if not os.path.exists(self.leaves_path):
            return []
        out = []
        with open(self.leaves_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def _recover(self):
        """Reopen rule: resolve any prepared-but-not-committed transaction so
        only a complete old/new head is ever visible."""
        if self.embedded:
            return
        self.cp = self._load_checkpoint()
        leaves = self._read_leaves()
        pending_dir = os.path.join(self.path, "pending")
        # Complete intents only; a sibling *.tmp is another process's
        # in-progress prepare and must never be read or removed here. Sorted
        # by target index so a chain of crashed serial commits replays in
        # order (recovery itself runs under the exclusive flock).
        def _intent_index(name: str) -> int:
            try:
                with open(os.path.join(pending_dir, name),
                          encoding="utf-8") as f:
                    return int(json.load(f).get("index", 0))
            except (OSError, ValueError):
                return 0

        names = [n for n in (os.listdir(pending_dir)
                             if os.path.isdir(pending_dir) else [])
                 if n.endswith(".json")]
        pendings = sorted(names, key=_intent_index)
        committed = self.cp["size"]
        if not pendings:
            if len(leaves) > committed:
                self._rewrite_leaves(leaves[:committed])
            return
        # Resolve intents in commit order; each advances the committed size
        # by exactly one. Intents whose index is already committed (e.g. the
        # post-rename pre-cleanup crash) are simply discarded.
        for pname in pendings:
            ipath = os.path.join(pending_dir, pname)
            try:
                with open(ipath, encoding="utf-8") as f:
                    intent = json.load(f)
            except FileNotFoundError:
                continue  # a concurrent lock-holder finished it
            if intent["index"] < self.cp["size"]:
                self._safe_remove(ipath)
                continue
            leaves = self._read_leaves()
            if len(leaves) >= intent["new_size"]:
                self.cp = self._commit_checkpoint(
                    intent["leaf"], intent["index"], intent["new_root"],
                    persist_leaves=False, head=intent["head"])
            else:
                self._rewrite_leaves(leaves[:self.cp["size"]])
            self._safe_remove(ipath)

    @staticmethod
    def _safe_remove(path: str):
        try:
            os.remove(path)
        except FileNotFoundError:
            pass

    def _rewrite_leaves(self, leaves: list[dict]):
        tmp = f"{self.leaves_path}.tmp.{os.getpid()}.{os.urandom(6).hex()}"
        with open(tmp, "w", encoding="utf-8") as f:
            for lf in leaves:
                f.write(json.dumps(lf, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.leaves_path)

    def _append_leaf_line(self, leaf: dict):
        with open(self.leaves_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(leaf, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _persist_checkpoint(self):
        tmp = f"{self.cp_path}.tmp.{os.getpid()}.{os.urandom(6).hex()}"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.cp, f, indent=2, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.cp_path)
        self._crash_hook("after-checkpoint-rename", -1)

    # ---- crash injection hooks (tests kill the process at each boundary) --
    def _crash_hook(self, point: str, index: int):
        # Only armed inside the fault-injecting worker process (env switch);
        # recovery on a fresh reopen must complete instead of re-crashing.
        if not os.environ.get("KC_TLOG_CRASH"):
            return
        marker = os.path.join(self.path or "/nonexistent", "crash-" + point)
        if self.path and os.path.exists(marker):
            os._exit(17)

    # ---- append ------------------------------------------------------------
    def require_unfrozen(self):
        """Gate for any operation that must append a transparency leaf (new
        key materialization/activation). Raises while a split-view is open."""
        if self.cp.get("frozen"):
            raise PublicationFrozen(
                "transparency log is frozen pending split-view resolution",
                split_id=self.cp["frozen"]["split_id"])

    def record(self, leaf: dict) -> dict:
        """Idempotent lifecycle append. Returns {index, leaf, head,
        duplicate}. Raises PublicationFrozen while a split-view is open and
        ContradictoryLifecycle on illegal/reordered state changes."""
        if self.cp.get("frozen"):
            raise PublicationFrozen(
                "transparency log is frozen pending split-view resolution",
                split_id=self.cp["frozen"]["split_id"])
        bk = business_key(leaf)
        if bk in self.cp["business"]:
            idx = self.cp["business"][bk]
            return {"index": idx, "leaf": self.leaf_at(idx),
                    "head": self.current_head(), "duplicate": True}
        self._validate_transition(leaf)
        index = self.cp["size"]
        return self._commit(leaf, index, crash_point=None)

    def _validate_transition(self, leaf: dict):
        key = f"{leaf['purpose']}|{leaf['version']}"
        prev, nxt = leaf["state"]["prev"], leaf["state"]["next"]
        allowed = ALLOWED_TRANSITIONS.get(nxt, ())
        if prev not in allowed:
            raise ContradictoryLifecycle(
                f"{key}: {prev} -> {nxt} is not an allowed lifecycle edge")
        stored = self.cp["version_states"].get(key)
        if stored is None:
            if prev != NONE_STATE:
                raise ContradictoryLifecycle(
                    f"{key}: first leaf must start from NONE, claims {prev}")
        elif stored != prev:
            raise ContradictoryLifecycle(
                f"{key}: leaf prev {prev} contradicts logged state {stored}")
        # a (purpose, version) pair is bound forever to one public key:
        # substituting the key after the first leaf is a contradiction, not
        # a valid lifecycle change, and must block the new head.
        prior_idx = self.cp["version_index"].get(key)
        if prior_idx is not None:
            prior = self._committed_leaves()[prior_idx]
            if prior["signing_pub"] != leaf["signing_pub"] or \
                    prior["fingerprint"] != leaf["fingerprint"]:
                raise ContradictoryLifecycle(
                    f"{key}: public key/fingerprint differs from the leaf "
                    f"already logged at index {prior_idx} (key substitution)")

    def _commit(self, leaf: dict, index: int, crash_point: str | None):
        new_size = index + 1
        hashes = [leaf_hash(l) for l in self._committed_leaves()] + \
            [leaf_hash(leaf)]
        new_root = tree_root(hashes).hex()
        prev_head_hash = self.cp["heads"][-1]["head_hash"] \
            if self.cp["heads"] else ZERO
        head = head_content(new_size, new_root,
                            utcnow_ts(self.clock), prev_head_hash)
        head["tree_head_sig"] = sign_head(self.seed, head)
        head["head_hash"] = head_hash(head)

        intent = {"index": index, "new_size": new_size,
                  "new_root": new_root, "leaf": leaf,
                  "head": head, "txn": os.urandom(12).hex()}

        if self.embedded:
            # single durability boundary is the caller's state.json rename;
            # the leaf body lives in the checkpoint too.
            return self._commit_embedded(leaf, index, new_size, new_root,
                                         head, intent)

        # standalone: intent -> append leaf -> checkpoint rename
        pending_dir = os.path.join(self.path, "pending")
        ipath = os.path.join(pending_dir, intent["txn"] + ".json")
        itmp = f"{ipath}.{os.getpid()}.tmp"
        with open(itmp, "w", encoding="utf-8") as f:
            json.dump(intent, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(itmp, ipath)
        self._crash_hook("after-intent", index)      # near leaf write
        self._append_leaf_line(leaf)
        self._crash_hook("after-leaf", index)        # near tree-node update
        cp = self._commit_checkpoint(leaf, index, new_root,
                                     persist_leaves=False, head=head)
        self._crash_hook("after-head", index)        # near head publish
        self._safe_remove(ipath)
        self.cp = cp
        return {"index": index, "leaf": leaf, "head": head,
                "duplicate": False}

    def _commit_embedded(self, leaf, index, new_size, new_root, head, intent):
        cp = self.cp
        cp["size"] = new_size
        cp["root"] = new_root
        cp.setdefault("leaf_records", []).append(leaf)
        cp["business"][business_key(leaf)] = index
        key = f"{leaf['purpose']}|{leaf['version']}"
        cp["version_states"][key] = leaf["state"]["next"]
        cp["version_index"][key] = index
        cp["heads"].append(head)
        if new_size == 1:
            cp["trusted_size"] = new_size
            cp["trusted_root"] = new_root
        return {"index": index, "leaf": leaf, "head": head,
                "duplicate": False}

    def _commit_checkpoint(self, leaf, index, new_root, *,
                           persist_leaves=True, head=None):
        leaves = self._read_leaves()
        new_size = index + 1
        if persist_leaves:
            self._append_leaf_line(leaf)
        if head is None:
            prev_head_hash = self.cp["heads"][-1]["head_hash"] \
                if self.cp["heads"] else ZERO
            head = head_content(new_size, new_root,
                                utcnow_ts(self.clock), prev_head_hash)
            head["tree_head_sig"] = sign_head(self.seed, head)
            head["head_hash"] = head_hash(head)
        cp = json.loads(json.dumps(self.cp))  # deep copy
        cp["size"] = new_size
        cp["root"] = new_root
        cp["business"][business_key(leaf)] = index
        key = f"{leaf['purpose']}|{leaf['version']}"
        cp["version_states"][key] = leaf["state"]["next"]
        cp["version_index"][key] = index
        cp["heads"].append(head)
        if new_size == 1:
            cp["trusted_size"] = new_size
            cp["trusted_root"] = new_root
        self.cp = cp
        self._persist_checkpoint()
        return cp

    def _committed_leaves(self) -> list[dict]:
        if self.embedded:
            return self.cp.get("leaf_records", [])
        return self._read_leaves()[:self.cp["size"]]

    # ---- queries -----------------------------------------------------------
    @property
    def size(self) -> int:
        return self.cp["size"]

    def state_of(self, purpose: str, version: int) -> str | None:
        """Last logged lifecycle state for a purpose/version, or None."""
        return self.cp["version_states"].get(f"{purpose}|{version}")

    def leaf_hashes(self) -> list[bytes]:
        return [leaf_hash(l) for l in self._committed_leaves()]

    def leaf_at(self, index: int) -> dict:
        leaves = self._committed_leaves()
        if not 0 <= index < len(leaves):
            raise UnknownLeaf(f"no leaf at {index}")
        return leaves[index]

    def _zero_head(self) -> dict:
        h = self.cp.get("zero_head")
        if h is not None:
            return h
        h = head_content(0, self.cp.get("root", empty_root_hex()),
                         utcnow_ts(self.clock), ZERO)
        h["tree_head_sig"] = sign_head(self.seed, h)
        h["head_hash"] = head_hash(h)
        self.cp["zero_head"] = h
        return h

    def current_head(self) -> dict:
        if self.cp["heads"]:
            return self.cp["heads"][-1]
        return self._zero_head()

    def head_at_size(self, size: int) -> dict:
        if size == 0:
            return self._zero_head()
        if size > self.cp["size"]:
            raise UnknownLeaf(f"tree only has {self.cp['size']} leaves")
        return self.cp["heads"][size - 1]

    def inclusion_for(self, *, purpose: str | None = None,
                      version: int | None = None,
                      version_id: str | None = None,
                      audit_ref: str | None = None,
                      leaf_index: int | None = None) -> dict:
        idx = leaf_index
        leaves = self._committed_leaves()
        if idx is None:
            # precedence: exact audit ref > version id > purpose+version.
            # A purpose/version can have several lifecycle leaves; return the
            # latest one (the current public state) unless an audit ref pins
            # a specific change.
            if audit_ref:
                for i, lf in enumerate(leaves):
                    if lf["audit_ref"] == audit_ref:
                        idx = i
                        break
            elif version_id:
                for i in range(len(leaves) - 1, -1, -1):
                    if leaves[i]["version_id"] == version_id:
                        idx = i
                        break
            elif purpose is not None and version is not None:
                for i in range(len(leaves) - 1, -1, -1):
                    if leaves[i]["purpose"] == purpose and \
                            leaves[i]["version"] == version:
                        idx = i
                        break
        if idx is None or not 0 <= idx < len(leaves):
            raise UnknownLeaf("no matching transparency leaf")
        hashes = [leaf_hash(l) for l in leaves]
        return {"leaf_index": idx, "leaf": leaves[idx],
                "leaf_hash": hashes[idx].hex(),
                "tree_size": len(hashes),
                "inclusion_path": inclusion_proof(idx, len(hashes), hashes),
                "head": self.current_head()}

    def consistency(self, old_size: int) -> dict:
        new_size = self.cp["size"]
        hashes = self.leaf_hashes()
        return {"old_size": old_size, "tree_size": new_size,
                "consistency_path": consistency_proof(
                    old_size, new_size, hashes),
                "head": self.current_head()}

    # ---- gossip / split-view ----------------------------------------------
    def observe_head(self, observed: dict, observer: str = "external") -> dict:
        """Submit a signed head seen by an external monitor. Returns the
        observation record; a conflicting view freezes publication.

        A head carrying an invalid log signature is an attestation attack:
        the attempt is retained as evidence AND opens a split-view freeze
        ("continue to save conflicts and stop new publication" for forged
        attestation input). The 422 BadHead response is preserved for callers
        that only want to know the input was rejected.
        """
        pub = ed25519.public_from_secret(self.seed)
        size = int(observed.get("tree_size", -1)) \
            if isinstance(observed, dict) else -1
        root = observed.get("root_hash") if isinstance(observed, dict) else None
        rec = {"observer": observer, "submitted_at": utcnow_ts(self.clock),
               "size": size, "root": root, "head": observed}
        self.cp.setdefault("observations", []).append(rec)
        if not verify_head_signature(pub, observed):
            # Forged attestation: keep the conflict evidence, freeze new
            # publication (identical gating to an equivocation), then still
            # answer BadHead so existing clients/API contract see rejection.
            split = None
            if not self.cp.get("frozen"):
                split = self._split_record(
                    "INVALID_HEAD_SIGNATURE", observed,
                    {"size": max(size, 0),
                     "local_size": self.cp["size"],
                     "local_root": self.cp["root"],
                     "observed_root": root})
                split["observation"] = {
                    "observer": observer, "submitted_at": rec["submitted_at"]}
                self.cp["frozen"] = split
                self.cp.setdefault("splits", []).append(split)
                if not self.embedded:
                    self._persist_checkpoint()
            raise BadHead(
                "observed head has an invalid log signature")
        split = self._detect_split(observed)
        if split and not self.cp.get("frozen"):
            self.cp["frozen"] = split
            self.cp.setdefault("splits", []).append(split)
            if not self.embedded:
                self._persist_checkpoint()
        return {"observation": rec, "split": split,
                "frozen": bool(self.cp.get("frozen"))}

    def _detect_split(self, observed: dict) -> dict | None:
        size = int(observed["tree_size"])
        root = observed["root_hash"]
        # equivocation: same size, different root already published
        if 0 < size <= self.cp["size"]:
            local = self.cp["heads"][size - 1]
            if local["root_hash"] != root:
                return self._split_record(
                    "SAME_SIZE_DIFFERENT_ROOT", observed,
                    {"size": size,
                     "local_root": local["root_hash"],
                     "observed_root": root})
        # non-extension: larger head must follow a smaller local head
        if size > self.cp["size"] and self.cp["size"] > 0:
            return self._split_record(
                "LARGER_HEAD_NOT_EXTENSION", observed,
                {"smaller_size": self.cp["size"],
                 "smaller_root": self.cp["root"],
                 "larger_size": size, "larger_root": root})
        return None

    def _split_record(self, kind: str, observed: dict, detail: dict) -> dict:
        return {"split_id": "split_" + os.urandom(8).hex(),
                "kind": kind, "detected_at": utcnow_ts(self.clock),
                "detail": detail,
                "observed_head": observed,
                "status": "OPEN"}

    def status(self) -> dict:
        leaves = self._committed_leaves()
        latest = {}
        for lf in leaves:
            latest[lf["purpose"]] = {
                "version": lf["version"], "version_id": lf["version_id"],
                "state": lf["state"]["next"], "fingerprint": lf["fingerprint"],
                "leaf_index": self.cp["version_index"].get(
                    f"{lf['purpose']}|{lf['version']}")}
        pending = []
        for key, state in self.cp.get("version_states", {}).items():
            if state in (STAGED, ACTIVATED):
                purpose, version = key.rsplit("|", 1)
                pending.append({"purpose": purpose, "version": int(version),
                                "state": state})
        return {
            "tree_size": self.cp["size"],
            "root": self.cp["root"],
            "head": self.current_head(),
            "frozen": self.cp.get("frozen"),
            "splits": self.cp.get("splits", []),
            "resolutions": self.cp.get("resolutions", []),
            "latest_by_purpose": latest,
            "pending_events": pending,
            "trusted": {"size": self.cp.get("trusted_size", 0),
                        "root": self.cp.get("trusted_root")},
        }

    def resolve_split(self, split_id: str, chosen: dict, reason: str,
                      decided_by: str) -> dict:
        """Operator picks a branch. The chosen head must be a signed head that
        verifiably extends the last trusted head; the other branch is retained
        as rejected evidence."""
        frozen = self.cp.get("frozen")
        if not frozen or frozen["split_id"] != split_id:
            raise SplitResolutionRejected("no open split-view with that id")
        # Resolve the *stored* record in the splits list: after a state reload
        # `frozen` is a separate deserialized copy, so mutating it would leave
        # the evidence record OPEN.
        split = next((s for s in self.cp.get("splits", [])
                      if s["split_id"] == split_id), frozen)
        if not reason or not decided_by:
            raise SplitResolutionRejected("reason and operator are required")
        pub = ed25519.public_from_secret(self.seed)
        if not verify_head_signature(pub, chosen):
            raise SplitResolutionRejected("chosen head signature invalid")
        trusted_size = self.cp.get("trusted_size", 0)
        # chosen branch must be the local branch or a verifiable extension of
        # the last trusted anchor.
        chosen_size = int(chosen["tree_size"])
        chosen_root = chosen["root_hash"]
        local_ok = chosen_size == self.cp["size"] and \
            chosen_root == self.cp["root"]
        if not local_ok:
            if chosen_size <= trusted_size:
                raise SplitResolutionRejected(
                    "chosen branch must extend the last trusted head")
            raise SplitResolutionRejected(
                "chosen branch is not the locally verifiable extension; "
                "import its leaves and proofs first")
        resolution = {
            "split_id": split_id, "decided_by": decided_by, "reason": reason,
            "at": utcnow_ts(self.clock),
            "chosen_size": chosen_size, "chosen_root": chosen_root,
            "rejected": {"size": split["detail"].get("size")
                         or split["detail"].get("larger_size"),
                         "root": split["detail"].get("observed_root")
                         or split["detail"].get("larger_root")},
        }
        split["status"] = "RESOLVED"
        split["resolution"] = resolution
        self.cp.setdefault("resolutions", []).append(resolution)
        self.cp["frozen"] = None
        self.cp["trusted_size"] = chosen_size
        self.cp["trusted_root"] = chosen_root
        if not self.embedded:
            self._persist_checkpoint()
        return resolution
