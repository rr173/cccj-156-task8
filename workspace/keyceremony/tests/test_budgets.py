"""Acceptance scenarios for verifiable signing-quota budgets.

Covers, in order:
  * continuous draw down to zero + concurrent contention for the last unit,
  * same request id re-submission returns the first signature/settlement,
  * worker exit after the reservation (signature written / not written),
  * shrinking the total and concurrent revision conflicts,
  * pause/resume, revoked subject, retired key version, expired window,
  * old-version signatures keep verifying,
  * purposes without a budget order use the legacy signing path,
  * manual handling of hung reservations (operator/reason/quantities),
  * the complete archive verifies, and every class of modified archive is
    detected by the independent verifier.
"""

import json
import multiprocessing as mp
import os
import shutil
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import policy as P
from kc import crypto
from kc.budgets import (
    BudgetManager, HELD, CONSUMED, RELEASED, DEFAULT_LEASE_SECONDS,
)
from kc.budget_verify import verify_budget_audit
from kc.ceremony import Orchestrator
from kc.errors import (
    ConflictState, Forbidden, PolicyViolation, RevisionConflict,
)
from kc.storage import Store
from kc import export as export_mod

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_ceremonies import World  # noqa: E402


class Clock:
    """Deterministic monotonic time source."""

    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt
        return self.t


def make_world(root="/tmp/kc-test-budgets", total=10, *, lease=30,
               batch_cap=1, clock=None, subject="svc-bill",
               purpose="root-signing", valid_for=3600, register=True):
    w = World(root)
    clock = clock or Clock()
    w.clock = clock
    with w.store.locked():
        w.generate(purpose)
        w.orch.budgets = BudgetManager(
            w.orch.state, w.orch.audit,
            keys_by_id=w.orch.state["keys"], clock=clock,
            persist=w.orch.save)
        o = w.orch
        if register:
            o.budgets.register_subject(subject, "Billing service")
            kv = o.dir.active(purpose)
            o.budgets.create_budget(
                purpose=purpose, key_version_id=kv["id"], subject=subject,
                total=total, batch_cap=batch_cap,
                valid_from=clock.t - 10, valid_until=clock.t + valid_for,
                actor="alice", lease_seconds=lease)
        o.save()
    return w


def reopen(w, clock=None):
    clock = clock or w.clock
    with w.store.locked():
        o = Orchestrator(w.store, clock=clock)
        o.budgets = BudgetManager(
            o.state, o.audit, keys_by_id=o.state["keys"], clock=clock,
            persist=o.save)
        w.orch = o
    return o


def _mp_contend(root, request_id, outq):
    """Separate OS process contending for the final budget unit."""
    try:
        store = Store(root)
        with store.locked():
            o = Orchestrator(store)
            r = o.budgeted_sign(
                purpose="root-signing", message=request_id.encode(),
                request_id=request_id, subject="svc-proc")
            o.save()
        outq.put(("ok", r["settlement_state"]))
    except ConflictState as e:
        outq.put((e.code, None))
    except Exception as e:  # noqa: BLE001
        import traceback
        outq.put(("ERROR:" + repr(e) + "\n" + traceback.format_exc(), None))
    # close/flush the queue feeder thread before the process ends so the
    # result is never lost (os._exit would skip that flush).
    outq.close()
    outq.join_thread()


class TestExhaustionAndReplay(unittest.TestCase):
    def setUp(self):
        self.w = make_world("/tmp/kc-budget-exhaust", total=3, lease=60)

    def test_draw_down_to_zero(self):
        o = self.w.orch
        with self.w.store.locked():
            for i in range(3):
                r = o.budgeted_sign(purpose="root-signing",
                                    message=f"m{i}".encode(),
                                    request_id=f"req-{i}",
                                    subject="svc-bill")
                self.assertEqual(r["settlement_state"], CONSUMED)
            c = o.budgets.list_budgets()[0]
            self.assertEqual((c["total"], c["consumed"], c["available"]),
                             (3, 3, 0))
            with self.assertRaises(ConflictState) as cm:
                o.budgeted_sign(purpose="root-signing", message=b"m3",
                                request_id="req-3", subject="svc-bill")
            self.assertEqual(cm.exception.code, "QUOTA_EXHAUSTED")

    def test_replay_returns_first_signature_and_settlement(self):
        o = self.w.orch
        with self.w.store.locked():
            r1 = o.budgeted_sign(purpose="root-signing", message=b"same",
                                 request_id="dup-1", subject="svc-bill")
            settled_at = r1["settled_at"]
            r2 = o.budgeted_sign(purpose="root-signing", message=b"same",
                                 request_id="dup-1", subject="svc-bill")
            self.assertTrue(r2["replay"])
            self.assertEqual(r2["sig"], r1["sig"])
            self.assertEqual(r2["signature_audit_digest"],
                             r1["signature_audit_digest"])
            self.assertEqual(r2["settled_at"], settled_at)
            c = o.budgets.list_budgets()[0]
            self.assertEqual(c["consumed"], 1)  # charged once

    def test_concurrent_last_unit_contention_threads(self):
        w = make_world("/tmp/kc-budget-lastunit", total=2, lease=60)
        o = w.orch
        results = []

        def worker(i, barrier):
            barrier.wait()
            try:
                with w.store.locked():
                    r = o.budgeted_sign(
                        purpose="root-signing", message=f"c{i}".encode(),
                        request_id=f"c-{i}", subject="svc-bill")
                    results.append((i, "ok", r["settlement_state"]))
            except ConflictState as e:
                results.append((i, e.code, None))

        barrier = threading.Barrier(8)
        ts = [threading.Thread(target=worker, args=(i, barrier))
              for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        with w.store.locked():
            c = o.budgets.list_budgets()[0]
            self.assertEqual(c["consumed"], 2)
            self.assertEqual(c["available"], 0)
            self.assertEqual(sum(1 for _, s, _ in results if s == "ok"), 2)
            self.assertEqual(sum(1 for _, s, _ in results
                                 if s == "QUOTA_EXHAUSTED"), 6)


    def test_concurrent_last_unit_contention_processes(self):
        # Real OS processes (flock contention), each with its own store
        # handle and fresh audit log, fighting for the final unit. Children
        # run on the wall clock, so build the order against real time.
        w = World("/tmp/kc-budget-lastunit-proc")
        with w.store.locked():
            w.generate("root-signing")
            o = w.orch
            o.budgets = BudgetManager(
                o.state, o.audit, keys_by_id=o.state["keys"],
                clock=time.time, persist=o.save)
            o.budgets.register_subject("svc-proc", "proc")
            kv = o.dir.active("root-signing")
            o.budgets.create_budget(
                purpose="root-signing", key_version_id=kv["id"],
                subject="svc-proc", total=1, batch_cap=1,
                valid_from=time.time() - 60,
                valid_until=time.time() + 3600, actor="alice",
                lease_seconds=60)
            o.save()
        ctx = mp.get_context("spawn")
        q = ctx.Queue()
        ps = [ctx.Process(target=_mp_contend,
                          args=(w.root, f"p-{i}", q))
              for i in range(6)]
        for p in ps:
            p.start()
        results = [q.get(timeout=60) for _ in ps]
        for p in ps:
            p.join(30)
        oks = [r for r in results if r[0] == "ok"]
        nos = [r for r in results if r[0] == "QUOTA_EXHAUSTED"]
        self.assertEqual(len(oks), 1, results)
        self.assertEqual(len(nos), 5, results)
        with w.store.locked():
            o = Orchestrator(w.store)
            c = o.budgets.list_budgets()[0]
            self.assertEqual((c["consumed"], c["held"], c["available"]),
                             (1, 0, 0))


def _crash_worker(root, request_id, after, purpose, subject, message,
                  clock_offset=0.0):
    """Subprocess: reproduce a worker dying between durable steps.

    Every manager step fsyncs an audit entry and atomically renames
    state.json before the crash, so the takeover reads durable evidence.
    """
    store = Store(root)
    clock = Clock(time.time())
    clock.t = _crash_worker.base_t + clock_offset
    with store.locked():
        o = Orchestrator(store, clock=clock)
        o.budgets = BudgetManager(o.state, o.audit,
                                  keys_by_id=o.state["keys"], clock=clock,
                                  persist=o.save)
        try:
            o.budgeted_sign(purpose=purpose, message=message.encode(),
                            request_id=request_id, subject=subject,
                            crash_after=after)
        except SystemExit:
            raise
        os._exit(0)


class TestCrashTakeover(unittest.TestCase):
    def test_crash_after_signature_is_settled_by_takeover(self):
        w = make_world("/tmp/kc-budget-crash-sig", total=2, lease=2)
        root, base_t = w.root, w.clock.t
        _crash_worker.base_t = base_t
        p = mp.Process(target=_crash_worker,
                       args=(root, "r-crash-sig", "signature",
                             "root-signing", "svc-bill", "msg"))
        p.start(); p.join()
        self.assertEqual(p.exitcode, 17)
        with w.store.locked():
            o = reopen(w)
            rec = o.state["sign_requests"]["r-crash-sig"]
            self.assertEqual(rec["state"], HELD)          # died before settle
            self.assertIsNotNone(rec["signature"])        # signature durable
            # while still HELD, releasing the signed hold is refused outright
            with self.assertRaises(ConflictState) as cm:
                o.budgets.release_expired(request_id="r-crash-sig",
                                          actor="x")
            self.assertEqual(cm.exception.code,
                             "RESERVATION_HAS_SIGNATURE")
            verdict = o.budgets.take_over(request_id="r-crash-sig",
                                          actor="takeover-2")
            self.assertEqual(verdict["action"],
                             "settled_signature")
            c = o.budgets.list_budgets()[0]
            self.assertEqual(c["consumed"], 1)
            self.assertEqual(c["held"], 0)
            # after settlement the quota can never be released/reused
            with self.assertRaises(ConflictState) as cm2:
                o.budgets.release_expired(request_id="r-crash-sig",
                                          actor="x")
            self.assertEqual(cm2.exception.code,
                             "RESERVATION_NOT_HELD")

    def test_crash_after_hold_without_signature_is_released(self):
        w = make_world("/tmp/kc-budget-crash-hold", total=2, lease=1)
        root = w.root
        w.clock.advance(80)
        _crash_worker.base_t = w.clock.t
        p = mp.Process(target=_crash_worker,
                       args=(root, "r-crash-hold", "hold",
                             "root-signing", "svc-bill", "msg"))
        p.start(); p.join()
        self.assertEqual(p.exitcode, 17)
        # takeover runs strictly after the (1s) lease has elapsed
        w.clock.advance(12)
        with w.store.locked():
            o = reopen(w)
            rec = o.state["sign_requests"]["r-crash-hold"]
            self.assertEqual(rec["state"], HELD)
            self.assertIsNone(rec["signature"])
            verdict = o.budgets.take_over(request_id="r-crash-hold",
                                          actor="takeover-2")
            self.assertEqual(verdict["action"], "released_expired")
            c = o.budgets.list_budgets()[0]
            self.assertEqual((c["consumed"], c["held"], c["available"]),
                             (0, 0, 2))

    def test_replay_after_signature_crash_completes(self):
        w = make_world("/tmp/kc-budget-crash-rep", total=2, lease=30)
        root, base_t = w.root, w.clock.t
        _crash_worker.base_t = base_t
        p = mp.Process(target=_crash_worker,
                       args=(root, "r-rep", "signature",
                             "root-signing", "svc-bill", "hello"))
        p.start(); p.join()
        with w.store.locked():
            o = reopen(w)
            # client retries with the same request id: gets original sig +
            # the settlement record, no second charge
            r = o.budgeted_sign(purpose="root-signing", message=b"hello",
                                request_id="r-rep", subject="svc-bill")
            self.assertTrue(r["replay"])
            self.assertEqual(r["settlement_state"], CONSUMED)
            self.assertIsNotNone(r["sig"])

    def test_recovery_rebuilds_from_fsynced_audit_only(self):
        # simulate the crash window: audit entry durably appended+fsynced,
        # state.json still showing the pre-append snapshot.
        w = make_world("/tmp/kc-budget-torn", total=3, lease=60)
        o = w.orch
        with w.store.locked():
            o.budgets.hold(request_id="t1", purpose="root-signing",
                           subject="svc-bill")
            good = json.loads(json.dumps(o.state))
            # another hold lands in the audit log only
            o.budgets.hold(request_id="t2", purpose="root-signing",
                           subject="svc-bill")
            o.save()
            # roll state.json back to the t1 snapshot; audit keeps both
            w.store.save_state(good)
            o2 = reopen(w)
            self.assertIn("t2", o2.state["sign_requests"])
            self.assertEqual(o2.budgets.held(
                o2.budgets.list_budgets()[0]["budget_id"]), 2)

    def test_sweep_expired_mixed(self):
        w = make_world("/tmp/kc-budget-sweep", total=4, lease=10)
        o = w.orch
        with w.store.locked():
            o.budgets.hold(request_id="h1", purpose="root-signing",
                           subject="svc-bill")
            o.budgets.hold(request_id="h2", purpose="root-signing",
                           subject="svc-bill")
            cred1 = o.state["sign_requests"]["h1"]["credential"]
            kv = o.dir.active("root-signing")
            o.budgets.record_signature(
                request_id="h1", credential=cred1,
                key_version_id=kv["id"], message_digest="d1", signature="s1")
            w.clock.advance(50)
            verdicts = o.budgets.sweep_expired()
            actions = {v["request_id"]: v["action"] for v in verdicts}
            self.assertEqual(actions,
                             {"h1": "settled_signature",
                              "h2": "released_expired"})


class TestRevisionChainAndGates(unittest.TestCase):
    def setUp(self):
        self.w = make_world("/tmp/kc-budget-rev", total=10, lease=60)

    def test_concurrent_revision_conflict_returns_diff(self):
        o = self.w.orch
        with self.w.store.locked():
            bid = o.budgets.list_budgets()[0]["budget_id"]
            o.budgets.revise_budget(bid, base_revision=1, actor="alice",
                                   total=8, reason="shrink a")
            with self.assertRaises(RevisionConflict) as cm:
                o.budgets.revise_budget(bid, base_revision=1, actor="alice",
                                       total=5, reason="stale shrink")
            self.assertEqual(cm.exception.current_revision, 2)
            self.assertEqual(cm.exception.base_revision, 1)
            self.assertEqual(cm.exception.current_snapshot["total"], 8)
            # the newer decision stands; retrying at base 2 succeeds
            o.budgets.revise_budget(bid, base_revision=2, actor="alice",
                                   total=6)
            self.assertEqual(o.budgets.public_budget(bid)["revision"], 3)

    def test_shrink_cannot_go_below_consumed_plus_held(self):
        o = self.w.orch
        with self.w.store.locked():
            bid = o.budgets.list_budgets()[0]["budget_id"]
            o.budgeted_sign(purpose="root-signing", message=b"a",
                            request_id="a1", subject="svc-bill")
            o.budgeted_sign(purpose="root-signing", message=b"b",
                            request_id="a2", subject="svc-bill")
            o.budgets.hold(request_id="a3", purpose="root-signing",
                           subject="svc-bill")
            with self.assertRaises(ConflictState) as cm:
                o.budgets.revise_budget(bid, base_revision=1, actor="alice",
                                       total=2)
            self.assertEqual(cm.exception.code,
                             "SHRINK_BELOW_CONSUMED_PLUS_HELD")
            self.assertEqual(cm.exception.details["floor"], 3)
            # exactly at the floor is allowed
            o.budgets.revise_budget(bid, base_revision=1, actor="alice",
                                   total=3)

    def test_pause_blocks_new_holds_then_resume(self):
        o = self.w.orch
        with self.w.store.locked():
            bid = o.budgets.list_budgets()[0]["budget_id"]
            o.budgets.pause(bid, "alice", "incident")
            with self.assertRaises(ConflictState) as cm:
                o.budgeted_sign(purpose="root-signing", message=b"p",
                                request_id="p1", subject="svc-bill")
            self.assertEqual(cm.exception.code, "BUDGET_PAUSED")
            o.budgets.resume(bid, "alice", "cleared")
            r = o.budgeted_sign(purpose="root-signing", message=b"p",
                                request_id="p1", subject="svc-bill")
            self.assertEqual(r["settlement_state"], CONSUMED)

    def test_revoked_subject_and_window(self):
        w = make_world("/tmp/kc-budget-revoke", total=5, lease=60,
                       valid_for=100)
        o = w.orch
        with w.store.locked():
            o.budgets.revoke_subject("svc-bill", "alice", "offboarded")
            with self.assertRaises(ConflictState) as cm:
                o.budgeted_sign(purpose="root-signing", message=b"x",
                                request_id="x1", subject="svc-bill")
            self.assertEqual(cm.exception.code, "SUBJECT_REVOKED")
            w.clock.advance(500)
            # re-register-free: even a different subject cannot use it
            o.budgets.register_subject("svc-other", "other")
            with self.assertRaises(Forbidden):
                o.budgeted_sign(purpose="root-signing", message=b"x",
                                request_id="x2", subject="svc-other")

    def test_expired_window_blocks_hold_but_history_verifies(self):
        w = make_world("/tmp/kc-budget-window", total=5, lease=60,
                       valid_for=100)
        o = w.orch
        with w.store.locked():
            r = o.budgeted_sign(purpose="root-signing", message=b"early",
                                request_id="early", subject="svc-bill")
            w.clock.advance(300)
            with self.assertRaises(ConflictState) as cm:
                o.budgeted_sign(purpose="root-signing", message=b"late",
                                request_id="late", subject="svc-bill")
            self.assertEqual(cm.exception.code, "BUDGET_WINDOW_EXPIRED")
            # the completed signature still verifies
            v = o.verify("root-signing", b"early", r["sig"])
            self.assertTrue(v["valid"])

    def test_batch_cap(self):
        w = make_world("/tmp/kc-budget-batch", total=10, lease=60,
                       batch_cap=3)
        o = w.orch
        with w.store.locked():
            view = o.reservation(purpose="root-signing", request_id="b1",
                                 subject="svc-bill", quantity=3)
            self.assertEqual(view["state"], HELD)
            with self.assertRaises(ConflictState) as cm:
                o.reservation(purpose="root-signing", request_id="b2",
                              subject="svc-bill", quantity=4)
            self.assertEqual(cm.exception.code, "BATCH_CAP_EXCEEDED")
            # batch settle: one signature audit over the ordered sig list,
            # then the whole reserved quantity is consumed at once
            cred = o.state["sign_requests"]["b1"]["credential"]
            view = o.settle_reservation(
                request_id="b1", credential=cred,
                signatures=["sig-a", "sig-b", "sig-c"])
            self.assertEqual(view["state"], CONSUMED)
            c = o.budgets.list_budgets()[0]
            self.assertEqual(c["consumed"], 3)
            self.assertIsNotNone(view["signature"])
            # presenting the wrong number of signatures is refused
            o.reservation(purpose="root-signing", request_id="b3",
                          subject="svc-bill", quantity=2)
            cred3 = o.state["sign_requests"]["b3"]["credential"]
            with self.assertRaises(PolicyViolation):
                o.settle_reservation(request_id="b3", credential=cred3,
                                     signatures=["only-one"])

    def test_credential_required_and_inflight_guard(self):
        w = make_world("/tmp/kc-budget-cred", total=5, lease=60)
        o = w.orch
        with w.store.locked():
            o.budgets.hold(request_id="f1", purpose="root-signing",
                           subject="svc-bill")
            # forged credential cannot settle or attach a signature
            with self.assertRaises(Forbidden):
                o.budgets.settle(request_id="f1", credential="forged")
            kv = o.dir.active("root-signing")
            with self.assertRaises(Forbidden):
                o.budgets.record_signature(
                    request_id="f1", credential="forged",
                    key_version_id=kv["id"], message_digest="d",
                    signature="s")
            # a concurrent worker re-submitting the live request id is told
            # it is in flight (it may not take a second hold under that id)
            with self.assertRaises(ConflictState) as cm:
                o.budgeted_sign(purpose="root-signing", message=b"f",
                                request_id="f1", subject="svc-bill")
            self.assertEqual(cm.exception.code, "REQUEST_IN_FLIGHT")
            # nothing was consumed; the one hold still stands
            c = o.budgets.list_budgets()[0]
            self.assertEqual((c["held"], c["consumed"]), (1, 0))

    def test_expired_unsigned_hold_is_releasable_but_not_before(self):
        w = make_world("/tmp/kc-budget-early", total=3, lease=10)
        o = w.orch
        with w.store.locked():
            o.budgets.hold(request_id="e1", purpose="root-signing",
                           subject="svc-bill")
            with self.assertRaises(ConflictState) as cm:
                o.budgets.release_expired(request_id="e1")
            self.assertEqual(cm.exception.code, "LEASE_NOT_EXPIRED")
            w.clock.advance(11)
            view = o.budgets.release_expired(request_id="e1")
            self.assertEqual(view["state"], RELEASED)
            c = o.budgets.list_budgets()[0]
            self.assertEqual(c["available"], 3)


class TestLegacyAndKeys(unittest.TestCase):
    def test_purpose_without_budget_signs_as_before(self):
        w = World("/tmp/kc-budget-legacy")
        with w.store.locked():
            w.generate("root-signing")
            o = w.orch
            r = o.sign("root-signing", b"legacy message")
            self.assertFalse(r["budgeted"])
            v = o.verify("root-signing", b"legacy message", r["sig"])
            self.assertTrue(v["valid"])

    def test_retired_key_blocks_new_reservation_old_sig_verifies(self):
        w = make_world("/tmp/kc-budget-retire", total=10, lease=60)
        o = w.orch
        with w.store.locked():
            old_sig = o.budgeted_sign(purpose="root-signing",
                                      message=b"v1msg",
                                      request_id="v1",
                                      subject="svc-bill")
            # rotate: old becomes RETIRING, new ACTIVE
            w.rotate("root-signing")
            # budget order pins the retired version -> new holds refused
            with self.assertRaises(ConflictState) as cm:
                o.budgeted_sign(purpose="root-signing",
                                message=b"v2msg",
                                request_id="v2", subject="svc-bill")
            self.assertEqual(cm.exception.code, "KEY_VERSION_RETIRED")
            # the signature produced under the old version still verifies
            v = o.verify("root-signing", b"v1msg", old_sig["sig"])
            self.assertTrue(v["valid"])
            self.assertEqual(v["status"], "RETIRING")

    def test_destroyed_old_version_signature_still_verifies(self):
        w = make_world("/tmp/kc-budget-destroy", total=10, lease=60)
        o = w.orch
        with w.store.locked():
            r = o.budgeted_sign(purpose="root-signing", message=b"keepme",
                                request_id="k1", subject="svc-bill")
            old_id = o.state["purposes"]["root-signing"]
            # rotate: the first version becomes RETIRING, then destroy it
            w.rotate("root-signing")
            o.dir.destroy(old_id, "manual")
            v = o.verify("root-signing", b"keepme", r["sig"])
            self.assertTrue(v["valid"])
            self.assertEqual(v["status"], "DESTROYED")


class TestManualHandling(unittest.TestCase):
    def test_manual_release_records_operator_reason_quantities(self):
        w = make_world("/tmp/kc-budget-manual", total=3, lease=60)
        o = w.orch
        with w.store.locked():
            o.budgets.hold(request_id="m1", purpose="root-signing",
                           subject="svc-bill")
            view = o.budgets.manual_release(
                request_id="m1", operator="alice",
                reason="worker host decommissioned; no signature produced")
            self.assertEqual(view["state"], RELEASED)
            rel = [e for e in o.audit.entries
                   if e["event"] == "budget_reservation_released"][-1]
            p = rel["payload"]
            self.assertEqual(p["released_by"], "alice")
            self.assertIn("decommissioned", p["manual_reason"])
            self.assertEqual((p["held_total_before"],
                              p["held_total_after"]), (1, 0))
            with self.assertRaises(PolicyViolation):
                o.budgets.hold(request_id="m2", purpose="root-signing",
                               subject="svc-bill")
                o.budgets.manual_release(request_id="m2", operator="alice",
                                         reason="   ")

    def test_manual_release_refused_after_signature(self):
        w = make_world("/tmp/kc-budget-manual2", total=3, lease=60)
        o = w.orch
        with w.store.locked():
            view = o.budgeted_sign(purpose="root-signing", message=b"z",
                                   request_id="z1", subject="svc-bill")
            # it is already consumed; a release attempt must fail
            with self.assertRaises(ConflictState) as cm:
                o.budgets.manual_release(request_id="z1", operator="alice",
                                         reason="try to free signed quota")
            self.assertEqual(cm.exception.code, "RESERVATION_NOT_HELD")
            c = o.budgets.list_budgets()[0]
            self.assertEqual(c["consumed"], 1)


# ---------------------------------------------------------------------------
# archive verification: complete passes, every modified archive is caught
# ---------------------------------------------------------------------------

def _budget_entries(o):
    names = {"budget_subject_registered", "budget_subject_revoked",
             "budget_created", "budget_revised", "budget_paused",
             "budget_resumed", "budget_reservation_held",
             "budget_signature_issued", "budget_reservation_settled",
             "budget_reservation_released"}
    return [e for e in o.audit.entries if e["event"] in names]


def _clone_entries(entries):
    return json.loads(json.dumps(entries))


def _rechain(entries):
    """Recompute prev/hash after a payload edit (simulate a naive forger);
    service signatures are left stale/absent so the check relies on the
    budget-specific replay logic, not merely on audit signatures."""
    from kc.storage import GENESIS
    from kc import crypto as _c
    import hashlib
    prev = GENESIS
    for e in entries:
        e["prev"] = prev
        e.pop("svc_sig", None)
        m = hashlib.sha256()
        m.update(e["prev"].encode())
        m.update(_c.dumps(e["payload"]).encode())
        m.update(str(e["ts"]).encode())
        m.update(str(e["seq"]).encode())
        e["hash"] = m.hexdigest()
        prev = e["hash"]
    return entries


def _find(entries, event, nth=0):
    out = [e for e in entries if e["event"] == event]
    return out[nth]


class TestArchiveVerification(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        w = make_world("/tmp/kc-budget-archive", total=6, lease=300)
        o = w.orch
        with w.store.locked():
            o.budgeted_sign(purpose="root-signing", message=b"a",
                            request_id="ar-1", subject="svc-bill")
            o.budgeted_sign(purpose="root-signing", message=b"b",
                            request_id="ar-2", subject="svc-bill")
            bid = o.budgets.list_budgets()[0]["budget_id"]
            o.budgets.revise_budget(bid, base_revision=1, actor="alice",
                                   total=5, reason="tighten")
            # one released (expired, unsigned) hold for coverage
            o.budgets.hold(request_id="ar-3", purpose="root-signing",
                           subject="svc-bill")
            w.clock.advance(400)
            o.budgets.release_expired(request_id="ar-3")
            o.save()
        cls.w = w
        cls.entries = _budget_entries(o)
        v = verify_budget_audit(o.audit.entries,
                                security_leads=frozenset({"alice"}))
        cls.assert_ok = v

    def test_complete_archive_verifies(self):
        self.assertTrue(self.assert_ok["ok"],
                        self.assert_ok["findings"])

    def test_full_export_bundle_verifies(self):
        with self.w.store.locked():
            bundle = export_mod.build_bundle(self.w.orch)
        verdict = export_mod.verify_bundle(bundle)
        self.assertTrue(verdict["checks"]["sign_budgets_ok"],
                        verdict["problems"])
        self.assertTrue(verdict["ok"], verdict["problems"])

    def _expect(self, entries, code):
        v = verify_budget_audit(entries,
                                security_leads=frozenset({"alice"}))
        self.assertFalse(v["ok"])
        self.assertIn(code, {f["code"] for f in v["findings"]},
                      [f["code"] for f in v["findings"]])

    def test_forged_budget(self):
        # budget created by someone who is not a recorded security lead
        es = _clone_entries(self.entries)
        _find(es, "budget_created")["payload"]["by"] = "mallory"
        self._expect(_rechain(es), "FORGED_BUDGET")

    def test_revision_rollback(self):
        es = _clone_entries(self.entries)
        rev = _find(es, "budget_revised")
        rev["payload"]["revision"] = 1  # must be 2
        self._expect(_rechain(es), "REVISION_ROLLBACK")

    def test_shrink_below_floor(self):
        es = _clone_entries(self.entries)
        _find(es, "budget_revised")["payload"]["total"] = 0
        self._expect(_rechain(es), "SHRINK_BELOW_FLOOR")

    def test_double_spend(self):
        es = _clone_entries(self.entries)
        settled = _find(es, "budget_reservation_settled")
        # insert a duplicate settle for the same request
        dup = json.loads(json.dumps(settled))
        dup["seq"] = max(e["seq"] for e in es) + 10
        es.append(dup)
        self._expect(es, "DOUBLE_SPEND")

    def test_over_budget(self):
        es = _clone_entries(self.entries)
        # inflate the first hold quantity beyond the total
        _find(es, "budget_reservation_held")["payload"]["quantity"] = 100
        self._expect(_rechain(es), "OVER_BUDGET")

    def test_cross_subject_diversion(self):
        es = _clone_entries(self.entries)
        _find(es, "budget_reservation_held")["payload"]["subject"] = \
            "svc-other"
        self._expect(_rechain(es), "CROSS_SUBJECT_DIVERSION")

    def test_reservation_after_window(self):
        es = _clone_entries(self.entries)
        # move the first hold past the window end (valid_until is ~+3600)
        _find(es, "budget_reservation_held")["payload"]["held_at"] = 9e9
        self._expect(_rechain(es), "RESERVATION_AFTER_WINDOW")

    def test_release_with_signature(self):
        es = _clone_entries(self.entries)
        # ar-1 produced a signature; delete its settlement so the replay
        # sees a SIGNED hold, then append a forged release for that request.
        st = next(e for e in es
                  if e["event"] == "budget_reservation_settled"
                  and e["payload"]["request_id"] == "ar-1")
        es.remove(st)
        signed_hold = next(e for e in es
                           if e["event"] == "budget_reservation_held"
                           and e["payload"]["request_id"] == "ar-1")
        rel = {
            "event": "budget_reservation_released",
            "seq": max(e["seq"] for e in es) + 20,
            "ts": signed_hold["ts"], "prev": "0" * 64,
            "payload": {
                "request_id": "ar-1",
                "reservation_id": signed_hold["payload"]["reservation_id"],
                "budget_id": signed_hold["payload"]["budget_id"],
                "subject": "svc-bill", "purpose": "root-signing",
                "quantity": 1, "released_at": 9e9,
                "released_by": "mallory", "release_reason": "lease_expired",
                "lease_expires_at": 0.0,
                "held_total_before": 0, "held_total_after": -1}}
        es.append(rel)
        self._expect(es, "RELEASE_WITH_SIGNATURE")

    def test_consume_without_signature(self):
        es = _clone_entries(self.entries)
        # remove the signature issuance for ar-1 but keep its settlement
        sig = next(e for e in es
                   if e["event"] == "budget_signature_issued"
                   and e["payload"]["request_id"] == "ar-1")
        es.remove(sig)
        self._expect(_rechain(es), "CONSUME_WITHOUT_SIGNATURE")

    def test_signature_without_settlement(self):
        es = _clone_entries(self.entries)
        st = next(e for e in es
                  if e["event"] == "budget_reservation_settled"
                  and e["payload"]["request_id"] == "ar-1")
        es.remove(st)
        self._expect(_rechain(es), "SIGNATURE_WITHOUT_SETTLEMENT")

    def test_unknown_hold_reference(self):
        es = _clone_entries(self.entries)
        st = _find(es, "budget_reservation_settled")
        st["payload"]["request_id"] = "never-held"
        self._expect(_rechain(es), "BAD_RESERVATION_CREDENTIAL")

    def test_ledger_recomputes_every_change(self):
        v = verify_budget_audit(self.entries,
                                security_leads=frozenset({"alice"}))
        ledgers = list(v["budgets"].values())[0]["ledger"]
        # every quantity-changing event appears in order with exact counters
        events = [x["event"] for x in ledgers]
        self.assertEqual(events.count("budget_reservation_held"), 3)
        self.assertEqual(events.count("budget_reservation_settled"), 2)
        self.assertEqual(events.count("budget_reservation_released"), 1)
        for row in ledgers:
            self.assertGreaterEqual(row["available"], 0)
            self.assertEqual(
                row["available"],
                row["total"] - row["consumed"] - row["held"])


if __name__ == "__main__":
    mp.set_start_method("fork", force=True)
    unittest.main(verbosity=2)
