"""Tests for the caller-facing key-directory transparency log.

Covers:
  * RFC-style Merkle inclusion + consistency algorithms (exhaustive sizes),
  * canonical public-only leaves and the lifecycle state machine,
  * business-event idempotency (one index per audit change),
  * multi-process concurrent append (single committed order, no gaps),
  * crash atomicity around leaf-write / tree-update / head-publish,
  * split-view freeze (same-size two roots / non-extension), activation
    blocking with historical verification intact, operator resolution that
    retains the rejected branch,
  * the independent checker's detection codes,
  * the embedded log inside the orchestrator (create/rotate/destroy leaves).
"""

import hashlib
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from kc import crypto, ed25519, policy as P
from kc.attestation import provision_device
from kc.ceremony import Orchestrator
from kc.console import DeviceContext
from kc.storage import Store
from kc import transparency as T
from kc.transparency import (
    ACTIVATED, CREATED, ERASED, NONE_STATE, RETIRED, STAGED,
    ContradictoryLifecycle, PublicationFrozen,
    TransparencyLog, head_content, inclusion_proof, consistency_proof,
    leaf_hash, make_leaf, tree_root, verify_consistency,
    verify_head_signature, verify_inclusion,
)
from kc.transparency_verify import verify_transparency

ROLES = [("alice", P.ROOT_OWNER), ("bruno", P.KEY_STEWARD),
         ("carla", P.WITNESS_SHAREHOLDER), ("diego", P.ENCLAVE_OPERATOR)]
PIDS = [p for p, _ in ROLES]
CONFIRMERS = ("alice", "bruno", "carla")


def lhash(i):
    return hashlib.sha256(bytes([0]) + f"leaf-{i}".encode()).digest()


class TestMerkleAlgorithms(unittest.TestCase):
    """Brute-force every tree geometry so a position bug cannot hide."""

    N = 260

    def setUp(self):
        self.hs = [lhash(i) for i in range(self.N)]

    def test_roots_match_stack_fold(self):
        def naive(hs):
            if not hs:
                return hashlib.sha256(b"").digest()
            stack = []
            for h in hs:
                w, cur = 1, h
                while stack and stack[-1][0] == w:
                    pw, ph = stack.pop()
                    w *= 2
                    cur = T.node_hash(ph, cur)
                stack.append((w, cur))
            root = stack[-1][1]
            for _, h in reversed(stack[:-1]):
                root = T.node_hash(h, root)
            return root
        for n in range(self.N + 1):
            self.assertEqual(tree_root(self.hs[:n]), naive(self.hs[:n]))

    def test_inclusion_proofs_all_positions(self):
        bogus = hashlib.sha256(b"not-a-leaf").digest()
        for n in range(1, self.N + 1):
            root = tree_root(self.hs[:n])
            for i in range(n):
                p = inclusion_proof(i, n, self.hs[:n])
                self.assertTrue(verify_inclusion(i, n, p, self.hs[i], root))
                self.assertFalse(verify_inclusion(i, n, p, bogus, root))
                if n >= 2:
                    j = (i + 1) % n
                    self.assertFalse(
                        verify_inclusion(j, n, p, self.hs[j], root))
                if p:
                    self.assertFalse(
                        verify_inclusion(i, n, p[:-1], self.hs[i], root))
                    self.assertFalse(
                        verify_inclusion(i, n, p + [p[0]], self.hs[i], root))
                    x = bytes.fromhex(p[0])
                    flipped = [(bytes([x[0] ^ 1]) + x[1:]).hex()] + p[1:]
                    self.assertFalse(
                        verify_inclusion(i, n, flipped, self.hs[i], root))

    def test_consistency_proofs_all_pairs(self):
        for n in range(1, self.N + 1):
            new = tree_root(self.hs[:n])
            for m in range(n + 1):
                old = tree_root(self.hs[:m])
                p = consistency_proof(m, n, self.hs[:n])
                self.assertTrue(verify_consistency(m, n, p, old, new), (m, n))
                if m > 0:
                    b = bytes([old[0] ^ 1]) + old[1:]
                    self.assertFalse(verify_consistency(m, n, p, b, new))
                if p:
                    x = bytes.fromhex(p[0])
                    flipped = [(bytes([x[0] ^ 1]) + x[1:]).hex()] + p[1:]
                    self.assertFalse(
                        verify_consistency(m, n, flipped, old, new))
                    self.assertFalse(
                        verify_consistency(m, n, p[:-1], old, new))
                    self.assertFalse(
                        verify_consistency(m, n, p + [p[0]], old, new))
                if len(p) >= 2:
                    sw = [p[1], p[0]] + p[2:]
                    self.assertFalse(verify_consistency(m, n, sw, old, new))

    def test_truncation_reorder_splice_fail(self):
        # truncated history presented as a later head
        for n in range(2, self.N):
            p = consistency_proof(n - 1, n, self.hs[:n])
            self.assertFalse(verify_consistency(
                n - 1, n, p, tree_root(self.hs[:n - 1]),
                tree_root(self.hs[:n - 2])))
        # path spliced from a different tree
        for n in range(3, 40):
            other = [hashlib.sha256(
                bytes([0]) + f"x-{i}".encode()).digest()
                for i in range(n)]
            p = consistency_proof(n - 1, n, other)
            self.assertFalse(verify_consistency(
                n - 1, n, p, tree_root(self.hs[:n - 1]),
                tree_root(self.hs[:n])))


class StandaloneBase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="tlog-")
        self.log = TransparencyLog(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def leaf(self, i, event=CREATED, prev=NONE_STATE, ver=1, purpose="p"):
        return make_leaf(purpose, ver, f"v{ver}-{i}", f"fp{ver}",
                         f"PUB{ver}", event, prev, "cer", f"audit-{i}")


class TestAppendAndLifecycle(StandaloneBase):
    def test_leaves_are_public_only(self):
        with self.log.locked() as l:
            l.record(self.leaf(0))
            body = open(os.path.join(self.dir, "leaves.log")).read()
        for secret in ("seed", "share", "wrap", "ct", "nonce"):
            self.assertNotIn(secret, body)
        leaf = json.loads(body.strip().splitlines()[0])
        self.assertEqual(set(leaf), {
            "purpose", "version", "version_id", "fingerprint", "signing_pub",
            "event", "state", "ceremony_id", "audit_ref"})

    def test_heads_chain_and_signatures(self):
        with self.log.locked() as l:
            for i in range(4):
                l.record(self.leaf(i, ver=i + 1, prev=NONE_STATE))
            pub = ed25519.public_from_secret(l.seed)
            prev = T.ZERO
            for n, h in enumerate(l.cp["heads"], 1):
                self.assertEqual(h["tree_size"], n)
                self.assertEqual(h["prev_head_hash"], prev)
                self.assertTrue(verify_head_signature(pub, h))
                prev = h["head_hash"]

    def test_duplicate_business_event_returns_same_index(self):
        with self.log.locked() as l:
            r1 = l.record(self.leaf(7))
            r2 = l.record(self.leaf(7))
            self.assertEqual(r1["index"], r2["index"])
            self.assertTrue(r2["duplicate"])
            self.assertEqual(l.size, 1)

    def test_contradictory_state_change_is_blocked_not_picked(self):
        with self.log.locked() as l:
            l.record(make_leaf("p", 1, "v1", "fp1", "P1", CREATED,
                               NONE_STATE, "c", "a0"))
            # valid retirement
            l.record(make_leaf("p", 1, "v1", "fp1", "P1", RETIRED,
                               CREATED, "c", "a1"))
            # a competing change claiming a different prior state must not
            # become a new head
            with self.assertRaises(ContradictoryLifecycle):
                l.record(make_leaf("p", 1, "v1", "fp1", "P1", RETIRED,
                                   ACTIVATED, "c", "a2"))
            self.assertEqual(l.size, 2)

    def test_same_purpose_version_cannot_bind_new_key(self):
        with self.log.locked() as l:
            l.record(self.leaf(0))
            evil = make_leaf("p", 1, "v1", "fp1", "DIFFERENT-PUB",
                             RETIRED, CREATED, "c", "a1")
            with self.assertRaises(ContradictoryLifecycle):
                l.record(evil)

    def test_queries_inclusion_and_consistency(self):
        with self.log.locked() as l:
            for i in range(6):
                l.record(self.leaf(i, ver=i + 1))
            old = l.current_head()
            ip = l.inclusion_for(purpose="p", version=3)
            self.assertEqual(ip["tree_size"], 6)
            self.assertTrue(verify_inclusion(
                ip["leaf_index"], 6,
                [bytes.fromhex(x) for x in ip["inclusion_path"]],
                bytes.fromhex(ip["leaf_hash"]),
                bytes.fromhex(ip["head"]["root_hash"])))
            for k in range(7, 10):
                l.record(self.leaf(k, ver=k + 1))
            cc = l.consistency(old["tree_size"])
            self.assertTrue(verify_consistency(
                old["tree_size"], cc["tree_size"],
                [bytes.fromhex(x) for x in cc["consistency_path"]],
                bytes.fromhex(old["root_hash"]),
                bytes.fromhex(cc["head"]["root_hash"])))

    def test_erased_public_material_still_queryable(self):
        with self.log.locked() as l:
            l.record(make_leaf("p", 1, "v1", "fp1", "P1", CREATED,
                               NONE_STATE, "c", "a0"))
            l.record(make_leaf("p", 1, "v1", "fp1", "P1", RETIRED,
                               CREATED, "c", "a1"))
            l.record(make_leaf("p", 1, "v1", "fp1", "P1", ERASED,
                               RETIRED, "c", "a2"))
            ip = l.inclusion_for(purpose="p", version=1)
            self.assertEqual(ip["leaf"]["signing_pub"], "P1")
            self.assertEqual(ip["leaf"]["event"], ERASED)


def _mp_append(args):
    kind, i, root = args
    from kc.transparency import TransparencyLog, make_leaf
    if kind == "leaf":
        leaf = make_leaf("mp", i + 1, f"v{i}", f"fp{i}", f"PUB{i}",
                         CREATED if i == 0 else STAGED, NONE_STATE,
                         "c", f"unique-{i}")
    else:
        leaf = make_leaf("mp", 99, "dup", "fpd", "PDUP", STAGED,
                         NONE_STATE, "c", "dup-event")
    with TransparencyLog(root).locked() as log:
        r = log.record(leaf)
        return kind, i, r["index"], r["duplicate"], r["head"]["tree_size"]


class TestMultiProcessCommit(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="tlog-mp-")

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def test_concurrent_appenders_single_order_and_heads(self):
        jobs = [("leaf", i, self.dir) for i in range(16)] + \
               [("dup", k, self.dir) for k in range(6)]
        with multiprocessing.get_context("fork").Pool(6) as p:
            outs = p.map(_mp_append, jobs)
        with TransparencyLog(self.dir).locked() as log:
            size, heads = log.size, log.cp["heads"]
            leaves = log._committed_leaves()
            prev = T.ZERO
            for n, h in enumerate(heads, 1):
                self.assertEqual(h["tree_size"], n)
                self.assertEqual(h["prev_head_hash"], prev)
                prev = h["head_hash"]
        inserted = sorted(i for k, j, i, d, s in outs if not d)
        self.assertEqual(inserted, list(range(17)))
        self.assertEqual(size, 17)
        self.assertEqual(len(leaves), 17)
        dup = [(i, d, s) for k, j, i, d, s in outs if k == "dup"]
        winners = [r for r in dup if not r[1]]
        followers = [r for r in dup if r[1]]
        self.assertEqual(len(winners), 1)
        self.assertEqual(len(followers), 5)
        wi = winners[0][0]
        self.assertTrue(all(i == wi and s == 17 for i, d, s in followers))
        self.assertEqual(
            sorted(l["audit_ref"] for l in leaves),
            sorted([f"unique-{i}" for i in range(16)] + ["dup-event"]))


_CRASH_WORKER = r'''
import os, sys
sys.path.insert(0, "__REPO__")
from kc.transparency import TransparencyLog, make_leaf
D, POINT = sys.argv[1], sys.argv[2]
lf = lambda i: make_leaf("p", i + 1, f"v{i}", f"f{i}", "P%d" % i,
                         "CREATED" if i == 0 else "STAGED",
                         "NONE", "c", "a%d" % i)
with TransparencyLog(D).locked() as L:
    L.record(lf(0))
open(os.path.join(D, "crash-" + POINT), "w").close()
with TransparencyLog(D).locked() as L:
    L.record(lf(1))
'''


class TestCrashAtomicity(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="tlog-crash-")
        self.repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _crash_at(self, point, expect_size):
        shutil.rmtree(self.dir, ignore_errors=True)
        os.makedirs(self.dir, exist_ok=True)
        env = dict(os.environ, KC_TLOG_CRASH="1")
        p = subprocess.run([sys.executable, "-c",
                            _CRASH_WORKER.replace("__REPO__", repr(self.repo)),
                            self.dir, point],
                           capture_output=True, text=True, env=env)
        self.assertEqual(p.returncode, 17, p.stderr)
        with TransparencyLog(self.dir).locked() as log:
            leaves = log._committed_leaves()
            size = log.size
            pending = os.listdir(os.path.join(self.dir, "pending"))
            root = tree_root([leaf_hash(l) for l in leaves]).hex()
            head = log.current_head()
            pub = ed25519.public_from_secret(log.seed)
        marker = os.path.join(self.dir, "crash-" + point)
        if os.path.exists(marker):
            os.remove(marker)
        self.assertEqual(size, expect_size)
        self.assertEqual(len(leaves), expect_size)
        self.assertEqual(head["tree_size"], size)
        self.assertEqual(root, log.cp["root"])
        self.assertTrue(verify_head_signature(pub, head))
        self.assertEqual(pending, [])

    def test_crash_after_intent_rolls_back(self):
        self._crash_at("after-intent", 1)

    def test_crash_after_leaf_rolls_forward(self):
        self._crash_at("after-leaf", 2)

    def test_crash_near_head_publishes_full_new_head(self):
        self._crash_at("after-head", 2)

    def test_crash_after_checkpoint_rename_rolls_forward(self):
        self._crash_at("after-checkpoint-rename", 2)


def _forged_head(seed, size, root, issued, prev):
    h = head_content(size, root, issued, prev)
    h["tree_head_sig"] = crypto.b64e(ed25519.sign(
        seed, crypto.dumps(
            {k: h[k] for k in T.HEAD_FIELDS}).encode()))
    return h


class TestSplitView(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="tlog-split-")
        self.log = TransparencyLog(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def _grow(self, n):
        with self.log.locked() as l:
            for i in range(n):
                l.record(make_leaf(
                    "p", i + 1, f"v{i}", f"fp{i}", f"PUB{i}",
                    CREATED if i == 0 else STAGED, NONE_STATE, "c",
                    f"a{i}"))

    def test_same_size_different_root_freezes(self):
        self._grow(3)
        with self.log.locked() as l:
            head = l.current_head()
            bad = _forged_head(l.seed, 3, "b" * 64,
                               head["issued_at"], head["prev_head_hash"])
            r = l.observe_head(bad, "witness-1")
            self.assertEqual(r["split"]["kind"],
                             "SAME_SIZE_DIFFERENT_ROOT")
            self.assertTrue(l.cp["frozen"])
            with self.assertRaises(PublicationFrozen):
                l.record(make_leaf("p", 4, "v4", "fp4", "P4", STAGED,
                                   NONE_STATE, "c", "ax"))

    def test_larger_head_without_extension_freezes(self):
        self._grow(2)
        with self.log.locked() as l:
            bad = _forged_head(l.seed, 9, "c" * 64, "2026-10-02T00:00:00Z",
                               T.ZERO)
            r = l.observe_head(bad, "witness-2")
            self.assertEqual(r["split"]["kind"],
                             "LARGER_HEAD_NOT_EXTENSION")
            self.assertTrue(l.cp["frozen"])

    def test_resolution_keeps_rejected_branch_and_unfreezes(self):
        self._grow(2)
        with self.log.locked() as l:
            head = l.current_head()
            bad = _forged_head(l.seed, 2, "b" * 64,
                               head["issued_at"], head["prev_head_hash"])
            split = l.observe_head(bad, "w")["split"]
            # cannot resolve without reason or against a non-local branch
            with self.assertRaises(T.SplitResolutionRejected):
                l.resolve_split(split["split_id"], l.current_head(), "", "alice")
            remote = _forged_head(l.seed, 5, "d" * 64,
                                  "2026-10-02T00:00:00Z", T.ZERO)
            with self.assertRaises(T.SplitResolutionRejected):
                l.resolve_split(split["split_id"], remote,
                                "pick the remote", "alice")
            res = l.resolve_split(split["split_id"], l.current_head(),
                                  "verified local extension out of band",
                                  "alice")
            self.assertEqual(res["rejected"]["root"], "b" * 64)
            self.assertIsNone(l.cp["frozen"])
            # rejected head remains evidence
            self.assertEqual(l.cp["splits"][0]["status"], "RESOLVED")
            self.assertIn(res, l.cp["resolutions"])
            # publication resumes and the chain continues
            l.record(make_leaf("p", 3, "v3", "fp3", "P3", STAGED,
                               NONE_STATE, "c", "a3"))
            self.assertEqual(l.size, 3)

    def test_invalid_signature_observation_freezes_and_keeps_evidence(self):
        # A forged attestation is untrusted input: the API still answers
        # BadHead, but the attempt is retained as evidence, publication is
        # frozen, historical verification stays intact, and an owner can
        # recover from the provable local branch with a reason.
        self._grow(2)
        with self.log.locked() as l:
            h = l.current_head()
            before = len(l.cp.get("observations", []))
            forged = dict(h)
            forged["tree_head_sig"] = "x" + h["tree_head_sig"][1:]
            with self.assertRaises(T.BadHead):
                l.observe_head(forged, "monitor-forged")
            self.assertTrue(l.cp["frozen"])
            split = l.cp["frozen"]
            self.assertEqual(split["kind"], "INVALID_HEAD_SIGNATURE")
            self.assertEqual(split["status"], "OPEN")
            # evidence kept: observation + split record
            self.assertGreaterEqual(
                len(l.cp.get("observations", [])), before + 1)
            self.assertIn(split, l.cp["splits"])
            # publication paused
            with self.assertRaises(PublicationFrozen):
                l.record(make_leaf("p", 3, "v3", "fp3", "P3", STAGED,
                                   NONE_STATE, "c", "ax"))
            # historical heads/verification unaffected by the bad input
            pub = ed25519.public_from_secret(l.seed)
            self.assertTrue(verify_head_signature(pub, l.head_at_size(1)))
            self.assertTrue(verify_head_signature(pub, l.head_at_size(2)))
            self.assertEqual(l.size, 2)
            # another observation while frozen does not replace the conflict
            with self.assertRaises(T.BadHead):
                l.observe_head(forged, "monitor-retry")
            self.assertEqual(l.cp["frozen"]["split_id"],
                             split["split_id"])
            # reason-gated recovery from the local branch
            with self.assertRaises(T.SplitResolutionRejected):
                l.resolve_split(split["split_id"], l.current_head(), "",
                                "alice")
            res = l.resolve_split(split["split_id"], l.current_head(),
                                  "forged attestation rejected; local log "
                                  "verified out of band", "alice")
            self.assertEqual(res["chosen_size"], 2)
            self.assertIsNone(l.cp["frozen"])
            self.assertEqual(split["status"], "RESOLVED")
            # publication resumes and extends the same chain
            l.record(make_leaf("p", 3, "v3", "fp3", "P3", STAGED,
                               NONE_STATE, "c", "ax"))
            self.assertEqual(l.size, 3)
            self.assertTrue(verify_head_signature(pub, l.current_head()))

    def test_freeze_from_forged_attestation_survives_reopen(self):
        self._grow(1)
        with self.log.locked() as l:
            h = l.current_head()
            forged = dict(h)
            forged["tree_head_sig"] = "y" + h["tree_head_sig"][1:]
            with self.assertRaises(T.BadHead):
                l.observe_head(forged, "w")
            sid = l.cp["frozen"]["split_id"]
        log2 = TransparencyLog(self.dir)
        with log2.locked() as l2:
            self.assertEqual(l2.cp["frozen"]["split_id"], sid)
            self.assertEqual(l2.cp["frozen"]["kind"],
                             "INVALID_HEAD_SIGNATURE")

    def test_freeze_survives_reopen(self):
        self._grow(1)
        with self.log.locked() as l:
            head = l.current_head()
            sid = l.observe_head(
                _forged_head(l.seed, 1, "b" * 64,
                             head["issued_at"], head["prev_head_hash"]),
                "w")["split"]["split_id"]
        log2 = TransparencyLog(self.dir)
        with log2.locked() as l2:
            self.assertEqual(l2.cp["frozen"]["split_id"], sid)


# ---------------------------------------------------------------------------
# embedded orchestrator integration (acceptance scenarios 1, 5, 6 lifecycle)
# ---------------------------------------------------------------------------

class OrchestratorWorld:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="kc-tl-")
        self.store = Store(self.root)
        self.ctx = {}
        with self.store.locked():
            self.o = Orchestrator(self.store)
            slots = []
            for pid, role in ROLES:
                self.o.enroll_participant(pid, pid, role)
                w = provision_device("dev_" + pid, pid)
                self.ctx[pid] = DeviceContext(w)
                self.o.bind_device(pid, w, role)
                slots.append((pid, role, "dev_" + pid))
            self.o.create_policy(
                "pol", "pol", 3, slots,
                purposes=("root-signing", "svc-a", "svc-b", "svc-c"))
            self.o.save()

    def drive(self, cid, kind, confirmers=CONFIRMERS):
        for pid in PIDS:
            self.ctx[pid].attest(self.o, cid)
        if kind != P.DESTROY:
            for pid in PIDS:
                self.ctx[pid].receive_share(self.o, cid)
        for pid in confirmers:
            self.ctx[pid].confirm(self.o, cid)

    def reopen(self):
        with self.store.locked():
            self.o = Orchestrator(self.store)
        return self.o


class TestEmbeddedLifecycle(unittest.TestCase):
    def setUp(self):
        self.w = OrchestratorWorld()

    def tearDown(self):
        shutil.rmtree(self.w.root, ignore_errors=True)

    def test_create_and_rotate_leaves_and_client_proofs(self):
        o, w = self.w.o, self.w
        with w.store.locked():
            cid = o.open_ceremony(P.GENERATE, "pol", "root-signing",
                                  "alice")["id"]
            w.drive(cid, P.GENERATE)
            o.commit(cid, "alice")
            versions = o.dir.versions_for_purpose("root-signing")
            v1 = versions[0]
            old_head = o.tlog.current_head()
            old_size = o.tlog.size
            old = o.dir.active_id("root-signing")
            cid = o.open_ceremony(P.ROTATE, "pol", "root-signing",
                                  "alice")["id"]
            w.drive(cid, P.ROTATE)
            o.commit(cid, "alice")
            o.publish_rotation(cid, "alice", old)
            v2 = [k for k in o.dir.versions_for_purpose("root-signing")
                  if k["version"] == 2][0]
            o.save()

        # reopen as independent client processes would
        o = self.w.reopen()
        with self.w.store.locked():
            events = [(l["event"], l["version"])
                      for l in o.tlog._committed_leaves()]
            self.assertEqual(
                events,
                [(CREATED, 1), (STAGED, 2), (ACTIVATED, 2), (RETIRED, 1)])
            for kv in (v1, v2):
                ip = o.tlog.inclusion_for(version_id=kv["id"])
                self.assertTrue(verify_inclusion(
                    ip["leaf_index"], ip["tree_size"],
                    [bytes.fromhex(x) for x in ip["inclusion_path"]],
                    bytes.fromhex(ip["leaf_hash"]),
                    bytes.fromhex(ip["head"]["root_hash"])))
            cc = o.tlog.consistency(old_size)
            self.assertTrue(verify_consistency(
                old_size, cc["tree_size"],
                [bytes.fromhex(x) for x in cc["consistency_path"]],
                bytes.fromhex(old_head["root_hash"]),
                bytes.fromhex(cc["head"]["root_hash"])))

    def test_consistency_after_many_changes_from_old_head(self):
        o, w = self.w.o, self.w
        with w.store.locked():
            cid = o.open_ceremony(P.GENERATE, "pol", "root-signing",
                                  "alice")["id"]
            w.drive(cid, P.GENERATE)
            o.commit(cid, "alice")
            pinned = o.tlog.current_head()
            for purpose in ("svc-a", "svc-b", "svc-c"):
                cid = o.open_ceremony(P.GENERATE, "pol", purpose,
                                      "alice")["id"]
                w.drive(cid, P.GENERATE)
                o.commit(cid, "alice")
            cc = o.tlog.consistency(pinned["tree_size"])
            self.assertTrue(verify_consistency(
                pinned["tree_size"], cc["tree_size"],
                [bytes.fromhex(x) for x in cc["consistency_path"]],
                bytes.fromhex(pinned["root_hash"]),
                bytes.fromhex(cc["head"]["root_hash"])))

    def test_freeze_blocks_activation_but_not_historical_verify(self):
        o, w = self.w.o, self.w
        with w.store.locked():
            cid = o.open_ceremony(P.GENERATE, "pol", "root-signing",
                                  "alice")["id"]
            w.drive(cid, P.GENERATE)
            o.commit(cid, "alice")
            msg, sig = b"frozen-check", None
            r = o.sign("root-signing", msg)
            sig = r["sig"]
            head = o.tlog.current_head()
            bad = _forged_head(o.seed, o.tlog.size, "b" * 64,
                               head["issued_at"], head["prev_head_hash"])
            split = o.tlog.observe_head(bad, "monitor")["split"]
            # historical signature verifies while frozen
            self.assertTrue(o.verify("root-signing", msg, sig)["valid"])
            # new staged material commit is blocked
            old = o.dir.active_id("root-signing")
            cid2 = o.open_ceremony(P.ROTATE, "pol", "root-signing",
                                   "alice")["id"]
            w.drive(cid2, P.ROTATE)
            with self.assertRaises(PublicationFrozen):
                o.commit(cid2, "alice")
            o.abort(cid2, "alice", "frozen")
            o.tlog.resolve_split(split["split_id"], o.tlog.current_head(),
                                 "local branch verified", "alice")
            # activation works again after resolution
            cid3 = o.open_ceremony(P.ROTATE, "pol", "root-signing",
                                   "alice")["id"]
            w.drive(cid3, P.ROTATE)
            o.commit(cid3, "alice")
            o.publish_rotation(cid3, "alice", old)
            self.assertEqual(o.dir.active("root-signing")["version"], 2)

    def test_destroyed_public_material_queryable(self):
        o, w = self.w.o, self.w
        with w.store.locked():
            cid = o.open_ceremony(P.GENERATE, "pol", "root-signing",
                                  "alice")["id"]
            w.drive(cid, P.GENERATE)
            o.commit(cid, "alice")
            old = o.dir.active_id("root-signing")
            cid = o.open_ceremony(P.ROTATE, "pol", "root-signing",
                                  "alice")["id"]
            w.drive(cid, P.ROTATE)
            o.commit(cid, "alice")
            o.publish_rotation(cid, "alice", old)
            cid = o.open_ceremony(P.DESTROY, "pol", "root-signing",
                                  "alice", target_version=old)["id"]
            w.drive(cid, P.DESTROY)
            o.commit(cid, "alice")
            ip = o.tlog.inclusion_for(version_id=old)
            self.assertEqual(ip["leaf"]["event"], ERASED)
            self.assertTrue(ip["leaf"]["signing_pub"])


# ---------------------------------------------------------------------------
# independent checker
# ---------------------------------------------------------------------------

def _clean_section(seed, leaves=None):
    leaves = leaves or []
    heads = []
    prev = T.ZERO
    hashes = [leaf_hash(l) for l in leaves]
    for n, l in enumerate(leaves, 1):
        h = head_content(n, tree_root(hashes[:n]).hex(),
                         "2026-10-02T00:00:00Z", prev)
        h["tree_head_sig"] = crypto.b64e(ed25519.sign(
            seed, crypto.dumps({k: h[k] for k in T.HEAD_FIELDS}).encode()))
        h["head_hash"] = T.head_hash(h)
        heads.append(h)
        prev = h["head_hash"]
    return {"log_pub": crypto.b64e(ed25519.public_from_secret(seed)),
            "size": len(leaves), "leaves": leaves, "heads": heads,
            "observations": [], "splits": [], "resolutions": [],
            "frozen": None}


def _chain(seed, n):
    leaves = []
    for i in range(n):
        if i == 0:
            event, prev = CREATED, NONE_STATE
        else:
            event, prev = STAGED, NONE_STATE
        leaves.append(make_leaf("p", i + 1, f"v{i}", f"fp{i}",
                                f"PUB{i}", event, prev, "c", f"a{i}"))
    return leaves, _clean_section(seed, leaves)


class TestIndependentChecker(unittest.TestCase):
    def setUp(self):
        self.seed = os.urandom(32)
        self.leaves, self.section = _chain(self.seed, 5)

    def codes(self, mutate=None, keys=None):
        import copy
        sec = copy.deepcopy(self.section)
        keys = keys or []
        if mutate:
            mutate(sec, keys)
        v = verify_transparency(sec, keys=keys)
        return v["ok"], {f["code"] for f in v["findings"]}

    def test_clean_passes(self):
        ok, codes = self.codes()
        self.assertTrue(ok, codes)

    def test_missing_leaf(self):
        def m(s, k):
            s["leaves"].pop()
        ok, codes = self.codes(m)
        self.assertFalse(ok)
        self.assertIn("MISSING_LEAF", codes)

    def test_duplicate_business_event(self):
        def m(s, k):
            import copy
            s["leaves"].append(copy.deepcopy(s["leaves"][-1]))
            s["size"] = len(s["leaves"])
            prev = s["heads"][-1]["head_hash"]
            h = head_content(6, tree_root(
                [leaf_hash(l) for l in s["leaves"]]).hex(),
                "2026-10-02T00:00:00Z", prev)
            h["tree_head_sig"] = crypto.b64e(ed25519.sign(
                self.seed,
                crypto.dumps({k: h[k] for k in T.HEAD_FIELDS}).encode()))
            h["head_hash"] = T.head_hash(h)
            s["heads"].append(h)
        ok, codes = self.codes(m)
        self.assertIn("DUPLICATE_BUSINESS_EVENT", codes)

    def test_leaf_reordered_or_key_swapped(self):
        def m(s, k):
            s["leaves"][0], s["leaves"][1] = s["leaves"][1], s["leaves"][0]
        ok, codes = self.codes(m)
        self.assertIn("LEAF_REORDERED", codes)

        def m2(s, k):
            s["leaves"][-1]["signing_pub"] = "SWAPPED-PUB"
        ok, codes = self.codes(m2)
        self.assertIn("LEAF_REORDERED", codes)

    def test_bad_consistency_or_truncation(self):
        def m(s, k):
            # drop a head but keep a later one: breaks the append chain
            del s["heads"][2]
            for n, h in enumerate(s["heads"], 1):
                h["tree_size"] = n
        ok, codes = self.codes(m)
        self.assertTrue({"BROKEN_CONSISTENCY", "MISSING_LEAF"} & codes)

    def test_head_signature_replaced(self):
        def m(s, k):
            s["heads"][-1]["tree_head_sig"] = \
                "A" + s["heads"][-1]["tree_head_sig"][1:]
        ok, codes = self.codes(m)
        self.assertIn("HEAD_SIGNATURE_REPLACED", codes)

    def test_same_size_two_roots(self):
        import copy
        sec = copy.deepcopy(self.section)
        other = copy.deepcopy(sec["heads"][-1])
        other["root_hash"] = "f" * 64
        sec["observations"].append(
            {"size": 5, "root": "f" * 64, "head": other})
        v = verify_transparency(sec)
        self.assertIn("SAME_SIZE_TWO_ROOTS",
                      {f["code"] for f in v["findings"]})

    def test_published_during_split_flagged(self):
        import copy
        sec = copy.deepcopy(self.section)
        sec["frozen"] = {"split_id": "s1",
                         "detail": {"size": 2}, "status": "OPEN"}
        sec["splits"].append(sec["frozen"])
        v = verify_transparency(sec)
        self.assertIn("PUBLISHED_DURING_SPLIT",
                      {f["code"] for f in v["findings"]})

    def test_illegal_lifecycle_edge(self):
        def m(s, k):
            s["leaves"][-1]["state"]["prev"] = ACTIVATED
        ok, codes = self.codes(m)
        self.assertIn("ILLEGAL_LIFECYCLE_EDGE", codes)

    def test_activation_without_leaf(self):
        keys = [{"id": "kv_ghost", "purpose": "ghost", "version": 9,
                 "status": "ACTIVE", "signing_pub": "GHOST-PUB"}]
        ok, codes = self.codes(keys=keys)
        self.assertIn("ACTIVATION_WITHOUT_LEAF", codes)

    def test_resolution_without_reason_or_missing_rejected(self):
        import copy
        sec = copy.deepcopy(self.section)
        split = {"split_id": "s1", "status": "RESOLVED",
                 "detail": {"size": 5, "observed_root": "b" * 64,
                            "local_root": sec["heads"][-1]["root_hash"]},
                 "observed_head": {"tree_size": 5, "root_hash": "b" * 64}}
        sec["splits"].append(split)
        sec["resolutions"].append(
            {"split_id": "s1", "decided_by": "alice", "reason": "",
             "chosen_size": 5,
             "chosen_root": sec["heads"][-1]["root_hash"],
             "rejected": {"size": 5, "root": "b" * 64}})
        v = verify_transparency(sec)
        codes = {f["code"] for f in v["findings"]}
        self.assertIn("SPLIT_RESOLUTION_INVALID", codes)

    def test_forged_attestation_split_open_flagged_and_resolved_clean(self):
        """An INVALID_HEAD_SIGNATURE conflict (forged monitor input) retained
        as an OPEN split must be flagged like any unresolved freeze; once an
        owner resolves it from the local branch with a reason and the rejected
        evidence is kept, the offline checker passes."""
        import copy
        # OPEN forged-attestation freeze -> must be flagged
        sec = copy.deepcopy(self.section)
        open_split = {
            "split_id": "s_forged", "kind": "INVALID_HEAD_SIGNATURE",
            "status": "OPEN",
            "detail": {"size": 5, "local_size": 5,
                       "local_root": sec["heads"][-1]["root_hash"],
                       "observed_root": sec["heads"][-1]["root_hash"]},
            "observed_head": {"tree_size": 5,
                              "root_hash": sec["heads"][-1]["root_hash"]}}
        sec["splits"].append(open_split)
        sec["frozen"] = open_split
        v = verify_transparency(sec)
        codes = {f["code"] for f in v["findings"]}
        self.assertIn("SPLIT_NOT_RESOLVED", codes)
        # PUBLISHED_DURING_SPLIT must NOT fire: no head exists above the
        # detection size (publication really was paused).
        self.assertNotIn("PUBLISHED_DURING_SPLIT", codes)

        # after a reason-gated recovery to the provable local branch the
        # checker is clean again (rejected evidence retained).
        sec2 = copy.deepcopy(sec)
        resolved = copy.deepcopy(open_split)
        resolved["status"] = "RESOLVED"
        sec2["splits"][-1] = resolved
        sec2["frozen"] = None
        sec2["resolutions"].append(
            {"split_id": "s_forged", "decided_by": "alice",
             "reason": "forged attestation; local branch verified",
             "chosen_size": 5,
             "chosen_root": sec["heads"][-1]["root_hash"],
             "rejected": {"size": 5,
                          "root": sec["heads"][-1]["root_hash"]}})
        v2 = verify_transparency(sec2)
        self.assertTrue(v2["ok"], v2["findings"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
