"""Independent checker for the key-version transparency log.

Input is *public material only*:

  * the ordered leaf set,
  * the signed tree-head chain,
  * the service identity public key (to verify head signatures),
  * the split-view records and operator resolutions,
  * optionally the exported key directory + audit entries (so an ACTIVE key
    with no transparency leaf is detected).

It recomputes every Merkle root from the leaves, re-derives every inclusion
and consistency slot from (size, index) rather than trusting supplied
positions, replays the head chain (prev_head_hash links + signatures), and
runs the per-(purpose, version) lifecycle state machine.

Concrete findings (each is a distinct machine-readable code):

  MISSING_LEAF             checkpoint size exceeds the leaves actually present
  DUPLICATE_BUSINESS_EVENT one audit_ref|version|event occupies two indices
  LEAF_REORDERED           leaves are not in the committed index order / a
                           referenced leaf hash does not match its index
  BAD_INCLUSION_PROOF      an inclusion path does not hash to its head root
  BROKEN_CONSISTENCY       a head is not a strict append of its predecessor
  HEAD_SIGNATURE_REPLACED  a head signature is not valid under the log key
  SAME_SIZE_TWO_ROOTS      two heads/observations claim one size, two roots
  PUBLISHED_DURING_SPLIT   a new head appeared while a split-view was open
  ACTIVATION_WITHOUT_LEAF  an ACTIVE/STAGED key version has no matching leaf
  ILLEGAL_LIFECYCLE_EDGE   a leaf's prev does not follow its prior logged state
  CONTRADICTORY_KEY_BINDING a (purpose, version) binds two different pubkeys
  SPLIT_NOT_RESOLVED       a frozen split lacks a recorded resolution
  SPLIT_RESOLUTION_INVALID  chosen branch does not extend the trusted anchor
  REJECTED_HEAD_MISSING     a resolution drops the rejected head instead of
                           retaining it as evidence
"""

from __future__ import annotations

from . import crypto
from . import transparency as T
from .transparency import (
    business_key, consistency_proof, inclusion_proof, leaf_hash,
    tree_root, verify_consistency, verify_head_signature,
)

VERIFIABLE_KEY_STATES = {"STAGED", "ACTIVE", "RETIRING", "DESTROYED",
                         "ABORTED"}


class Finding:
    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message

    def as_dict(self) -> dict:
        return {"code": self.code, "message": self.message}

    def __repr__(self):
        return f"{self.code}: {self.message}"


def verify_transparency(section: dict, *, keys: list[dict] | None = None,
                        audit: list[dict] | None = None) -> dict:
    """Recompute the whole transparency view. Returns {ok, findings[]}."""
    findings: list[Finding] = []

    def bad(code, msg):
        findings.append(Finding(code, msg))

    pub_b64 = section.get("log_pub") or section.get("service_identity_pub")
    try:
        pub = None if not pub_b64 else crypto.b64d(pub_b64)
    except Exception:
        pub = None
        bad("HEAD_SIGNATURE_REPLACED", "log public key is not valid base64")

    leaves = section.get("leaves", [])
    heads = section.get("heads", [])
    declared_size = int(section.get("size", len(leaves)))

    leaf_hashes = [leaf_hash(l) for l in leaves]

    # 1. size vs leaves actually present (missing leaves / truncation)
    if declared_size != len(leaves):
        bad("MISSING_LEAF",
            f"checkpoint size {declared_size} but {len(leaves)} leaves present")
    if any(l is None for l in leaves):
        bad("MISSING_LEAF", "a leaf slot is empty")

    # 2. recompute every head root from the leaves and verify signatures
    for n, head in enumerate(heads, start=1):
        if int(head.get("tree_size", -1)) != n:
            bad("LEAF_REORDERED",
                f"head #{n} claims tree_size {head.get('tree_size')}")
            continue
        if n > len(leaf_hashes):
            bad("MISSING_LEAF",
                f"head #{n} references leaves that are not present")
            continue
        recomputed = tree_root(leaf_hashes[:n]).hex()
        if head.get("root_hash") != recomputed:
            bad("LEAF_REORDERED",
                f"head #{n} root {str(head.get('root_hash'))[:12]} != "
                f"recomputed {recomputed[:12]} (reorder/swap/key replace)")
        if pub is not None and not verify_head_signature(pub, head):
            bad("HEAD_SIGNATURE_REPLACED",
                f"head #{n} signature is not valid under the log public key")

    # 3. head chain: strict append + prev_head_hash links
    prev_hash = T.ZERO
    prev_size, prev_root = 0, tree_root([])
    seen_roots_by_size: dict[int, set[str]] = {}
    for n, head in enumerate(heads, start=1):
        if head.get("prev_head_hash") != prev_hash:
            bad("BROKEN_CONSISTENCY",
                f"head #{n} prev_head_hash does not chain to head #{n-1}")
        if n > 1 and n <= len(leaf_hashes):
            path = consistency_proof(prev_size, n, leaf_hashes[:n])
            if not verify_consistency(
                    prev_size, n, path, prev_root,
                    bytes.fromhex(head["root_hash"])):
                bad("BROKEN_CONSISTENCY",
                    f"head #{n} is not a strict append of head #{n-1}")
        seen_roots_by_size.setdefault(n, set()).add(head["root_hash"])
        prev_hash = head.get("head_hash", prev_hash)
        prev_size, prev_root = n, bytes.fromhex(head["root_hash"])

    # 4. same size / two roots among heads and retained observations
    for n, roots in seen_roots_by_size.items():
        if len(roots) > 1:
            bad("SAME_SIZE_TWO_ROOTS",
                f"tree size {n} claims multiple roots: {sorted(roots)}")
    obs_by_size: dict[int, set[str]] = {}
    for o in section.get("observations", []):
        size = int(o.get("size", o.get("head", {}).get("tree_size", -1)))
        root = o.get("root", o.get("head", {}).get("root_hash"))
        if size >= 0 and root:
            obs_by_size.setdefault(size, set()).add(root)
    for size, roots in obs_by_size.items():
        local = {h["root_hash"] for h in heads
                 if h["tree_size"] == size} if size > 0 else set()
        if local and roots - local:
            bad("SAME_SIZE_TWO_ROOTS",
                f"observed another root at size {size}: {sorted(roots)}")

    # 5. business-event uniqueness + lifecycle state machine
    seen_business: dict[str, int] = {}
    states: dict[str, str] = {}
    bound_pub: dict[str, str] = {}
    for idx, leaf in enumerate(leaves):
        if idx < len(leaf_hashes) and \
                leaf_hashes[idx] != leaf_hash(leaf):
            bad("LEAF_REORDERED", f"leaf #{idx} hash mismatch")
        bk = business_key(leaf)
        if bk in seen_business:
            bad("DUPLICATE_BUSINESS_EVENT",
                f"{bk} at indices {seen_business[bk]} and {idx}")
        else:
            seen_business[bk] = idx
        key = f"{leaf['purpose']}|{leaf['version']}"
        prev, nxt = leaf["state"]["prev"], leaf["state"]["next"]
        if prev not in T.ALLOWED_TRANSITIONS.get(nxt, ()):
            bad("ILLEGAL_LIFECYCLE_EDGE",
                f"leaf #{idx} {key}: {prev} -> {nxt} is not allowed")
        logged = states.get(key)
        if logged is not None and logged != prev:
            bad("ILLEGAL_LIFECYCLE_EDGE",
                f"leaf #{idx} {key}: claimed prev {prev} but log was {logged} "
                "(forged state jump)")
        prior_pub = bound_pub.get(key)
        if prior_pub is not None and prior_pub != leaf["signing_pub"]:
            bad("CONTRADICTORY_KEY_BINDING",
                f"{key} is bound to two different public keys")
        bound_pub.setdefault(key, leaf["signing_pub"])
        states[key] = nxt
        # audit reference must resolve to a real, hash-matching audit entry
        if audit is not None:
            if not any(e.get("hash") == leaf["audit_ref"] for e in audit):
                bad("ILLEGAL_LIFECYCLE_EDGE",
                    f"leaf #{idx} references unknown audit entry "
                    f"{str(leaf['audit_ref'])[:12]}")

    # 6. inclusion proofs carried in the section, if any, must verify
    for item in section.get("inclusion_samples", []):
        idx = item["leaf_index"]
        size = item["tree_size"]
        if 0 <= idx < len(leaf_hashes) and size <= len(leaf_hashes):
            want = inclusion_proof(idx, size, leaf_hashes[:size])
            if want != item.get("inclusion_path"):
                bad("BAD_INCLUSION_PROOF",
                    f"sample for leaf #{idx} differs from recomputed path")
            head = heads[size - 1] if size else None
            if head and not T.verify_inclusion(
                    idx, size, item["inclusion_path"], leaf_hashes[idx],
                    bytes.fromhex(head["root_hash"])):
                bad("BAD_INCLUSION_PROOF",
                    f"sample for leaf #{idx} does not hash to its head root")

    # 7. split-view handling
    split_open_after: dict[int, bool] = {}
    open_splits = {s["split_id"]: s for s in section.get("splits", [])
                   if s.get("status") == "OPEN"}
    for s in section.get("splits", []):
        at_size = int(s.get("detail", {}).get("size", -1))
        kind = s.get("kind")
        observed = s.get("observed_head", {})
        if kind == "SAME_SIZE_DIFFERENT_ROOT" and observed:
            size = int(observed.get("tree_size", -1))
            local_root = s.get("detail", {}).get("local_root")
            if local_root == observed.get("root_hash"):
                bad("SPLIT_NOT_RESOLVED",
                    f"{s['split_id']}: roots are identical, not a split")
        # publication after the split's size but before resolution is illegal
        split_open_after[at_size] = True

    resolved_ids = {r["split_id"] for r in section.get("resolutions", [])}
    for sid, s in open_splits.items():
        if sid not in resolved_ids:
            bad("SPLIT_NOT_RESOLVED",
                f"split {sid} is OPEN with no resolution but publication may "
                "have continued")

    for res in section.get("resolutions", []):
        reason, by = res.get("reason"), res.get("decided_by")
        if not reason or not by:
            bad("SPLIT_RESOLUTION_INVALID",
                f"{res.get('split_id')}: resolution needs reason + operator")
        chosen_size = int(res.get("chosen_size", -1))
        chosen_root = res.get("chosen_root")
        if chosen_size > len(heads):
            bad("SPLIT_RESOLUTION_INVALID",
                f"{res.get('split_id')}: chosen size {chosen_size} has no head")
        elif heads[chosen_size - 1]["root_hash"] != chosen_root:
            bad("SPLIT_RESOLUTION_INVALID",
                f"{res.get('split_id')}: chosen root is not a verifiable "
                "extension of the local chain")
        rej = res.get("rejected") or {}
        if not rej.get("root"):
            bad("REJECTED_HEAD_MISSING",
                f"{res.get('split_id')}: rejected branch not retained")

    # current frozen split with heads above its detection point = illegal
    frozen = section.get("frozen")
    if frozen:
        detect = frozen.get("detail", {})
        fsize = int(detect.get("size", detect.get("smaller_size", 0)))
        if len(heads) > fsize:
            bad("PUBLISHED_DURING_SPLIT",
                f"new head published after split at size {fsize}")

    # 8. every materialized/active key must have a transparency leaf
    if keys is not None:
        leaf_versions = {
            (l["purpose"], l["version"], l["signing_pub"]) for l in leaves
        }
        for k in keys:
            if k.get("status") in VERIFIABLE_KEY_STATES and k.get("signing_pub"):
                triple = (k["purpose"], k["version"], k["signing_pub"])
                if triple not in leaf_versions:
                    bad("ACTIVATION_WITHOUT_LEAF",
                        f"key {k.get('id')} {k['purpose']} v{k['version']} "
                        f"({k.get('status')}) has no matching transparency leaf")

    return {"ok": not findings,
            "findings": [f.as_dict() for f in findings],
            "n_leaves": len(leaves), "n_heads": len(heads)}


def verify_store_section(section: dict) -> dict:
    """Convenience wrapper for a raw transparency checkpoint/export section."""
    return verify_transparency(section)
