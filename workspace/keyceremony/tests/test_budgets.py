"""Acceptance tests for verifiable signing-usage budgets.

Covers the acceptance scenarios from the specification:
  1. continuous drain to zero;
  2. concurrent contention for the very last quota units (workers + procs);
  3. identical request_id replayed -> first signature + settlement;
  4. crash after reserve with the signature already written (takeover);
  5. crash after reserve before signing (expired hold safely returned);
  6. shrinking quota and concurrent revision conflict;
  7. pause then resume;
  8. signatures under old/retired versions keep verifying;
  9. purposes without a budget keep signing the legacy way (compatibility);
 10. complete archive verifies; tampered archives are detected (forged
     budget, double consumption, over-quota, cross-subject, after-window
     reserve, revision regression, signed-release, consumption-without-
     signature, signature-without-settlement).
"""

import copy
import multiprocessing
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import budgets as B
from kc import crypto
from kc.budget_verify import verify_budgets
from kc.ceremony import Orchestrator
from kc.errors import (
    BudgetCredentialInvalid, BudgetExhausted, BudgetPaused,
    BudgetRevisionConflict, BudgetWindowClosed, KeyVersionRetired,
    ReservationExpired, ReservationHasSignature, ReservationState,
    SubjectRevoked,
)
from kc.export import build_bundle
from kc.storage import Store

class Clock:
    def __init__(self, t=1_700_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, dt):
        self.t += dt


def make_world(total=5, cap=5, lease=30, subject="svc-a", *,
               purpose="root-signing", window=100000, tmp=None):
    """Bootstrap an orchestrator with a real ACTIVE key (via the directory
    shortcut used across this suite) + an officer + subject + signed budget."""
    tmp = tmp or tempfile.mkdtemp()
    store = Store(tmp)
    clk = Clock()
    with store.locked():
        o = Orchestrator(store, clock=clk)
        seed, pub = crypto.gen_signing_keypair()
        # register_version gives an ACTIVE first generation
        kv = o.dir.register_version(purpose, seed, pub, [1, 2], [], "cer_1")
        bm = o.budgets
        oseed, opub = B.new_officer_keypair()
        bm.register_officer("sec", opub, "security lead")
        bm.register_subject(subject, "caller")
        now = clk()
        fields = dict(purpose=purpose, key_version_id=kv["id"],
                      subject=subject, total=total, per_batch_cap=cap,
                      effective_at=now - 10, deadline=now + window,
                      lease_seconds=lease, label="acceptance")
        sig = B.sign_officer_body(
            oseed, B.officer_body("budget-issue-v1", fields))
        b = bm.create_budget(officer_id="sec", officer_sig=sig, **fields)
        o.save()
    return {"tmp": tmp, "store": store, "clock": clk, "key": kv,
            "officer_seed": oseed, "budget_id": b["id"],
            "purpose": purpose, "subject": subject}


def orch(world):
    return Orchestrator(world["store"], clock=world["clock"])


def _relink_from(bundle, start_idx: int):
    """Re-stamp prev/hash/seq from ``start_idx`` so an inserted/fabricated
    event is chain-consistent. This models an insider with audit write
    access: the hash chain alone cannot catch it, so the semantic budget
    replay MUST. Service signatures from start_idx are dropped (a genuine
    attacker cannot forge them); the verifier's semantic checks still run.
    """
    from kc.budget_verify import _audit_hash
    audit = bundle["audit"]
    prev = audit[start_idx - 1]["hash"] if start_idx > 0 else "0" * 64
    for i in range(start_idx, len(audit)):
        e = audit[i]
        e["seq"] = i
        e["prev"] = prev
        e.setdefault("ts", "2026-01-01T00:00:00Z")
        e.pop("svc_sig", None)
        e["hash"] = _audit_hash(e)
        prev = e["hash"]
    return bundle


def governed_sign(o, world, rid, msg, *, amount=1, subject=None):
    return o.sign_governed(
        purpose=world["purpose"], subject=subject or world["subject"],
        request_id=rid, message=msg, amount=amount)


def _proc_grab(args):
    """Module-level worker so multiprocessing can pickle it. Uses a fixed
    clock matching the created world (forked children otherwise see wall
    time, which would trivially fail the budget window check)."""
    root, purpose, subject, i, frozen_at = args
    store = Store(root)

    class _FixedClock:
        def __call__(self):
            return frozen_at

    with store.locked():
        o = Orchestrator(store, clock=_FixedClock())
        try:
            o.reserve_signing(purpose=purpose, subject=subject,
                              request_id=f"p-{i}", amount=1)
            o.save()
            return "ok"
        except BudgetExhausted:
            return "exhausted"


class BudgetAcceptance(unittest.TestCase):
    # ------------------------------------------------------------------ 1
    def test_01_drain_to_zero(self):
        w = make_world(total=3, cap=1)
        with w["store"].locked():
            o = orch(w)
            for i in range(3):
                out = governed_sign(o, w, f"r{i}", f"msg{i}".encode())
                self.assertEqual(out["reservation_status"], "CONSUMED")
                self.assertEqual(out["settlement"]["consumed"], 1)
            b = o.budgets._find_budget(w["budget_id"])
            view = o.budgets.budget_view(b)
            self.assertEqual(view["consumed"], 3)
            self.assertEqual(view["available"], 0)
            self.assertEqual(view["reserved"], 0)
            with self.assertRaises(BudgetExhausted):
                o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                                  request_id="r-over", amount=1)

    # ------------------------------------------------------------------ 2
    def test_02_last_quota_concurrent_threads(self):
        w = make_world(total=1, cap=1)
        results = []

        def worker(i):
            with w["store"].locked():
                o = orch(w)
                try:
                    o.reserve_signing(purpose=w["purpose"],
                                      subject=w["subject"],
                                      request_id=f"last-{i}", amount=1)
                    results.append("ok")
                except BudgetExhausted:
                    results.append("exhausted")
                o.save()

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("exhausted"), 7)

    def test_02b_last_quota_concurrent_processes(self):
        w = make_world(total=2, cap=1)
        args = [(w["tmp"], w["purpose"], w["subject"], i, w["clock"]())
                for i in range(12)]
        with multiprocessing.get_context("fork").Pool(6) as p:
            res = p.map(_proc_grab, args)
        self.assertEqual(sorted(res).count("ok"), 2)
        self.assertEqual(sorted(res).count("exhausted"), 10)

    # ------------------------------------------------------------------ 3
    def test_03_same_request_id_replays_first(self):
        w = make_world(total=2, cap=2)
        with w["store"].locked():
            o = orch(w)
            first = governed_sign(o, w, "dup-1", b"hello")
            self.assertFalse(first["duplicate"])
            sig_digests = list(first["sig_digests"])
            settle = first["settlement"]
            second = governed_sign(o, w, "dup-1", b"hello")
            self.assertTrue(second["duplicate"])
            self.assertEqual(second["sig_digests"], sig_digests)
            self.assertEqual(second["settlement"], settle)
            # only one consumption happened
            b = o.budgets._find_budget(w["budget_id"])
            self.assertEqual(o.budgets.budget_view(b)["consumed"], 1)

    def test_03b_request_id_reuse_with_different_params_conflicts(self):
        from kc.errors import ReplayError
        w = make_world(total=2, cap=2)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "rid-x", b"hello")
            with self.assertRaises(ReplayError):
                o.reserve_signing(purpose=w["purpose"],
                                  subject=w["subject"], request_id="rid-x",
                                  amount=2)  # different amount

    # ------------------------------------------------------------------ 4
    def test_04_crash_after_reserve_signature_written(self):
        w = make_world(total=2, cap=2, lease=30)
        with w["store"].locked():
            o = orch(w)
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="crash-signed", amount=2)
            v = o.sign_reserved("crash-signed", [b"m"])
            sig = v["signatures_b64"][0]
            o.save()
        # process dies (no settle). takeover decides from signature audit.
        with w["store"].locked():
            o = orch(w)
            take = o.budgets.takeover("crash-signed")
            self.assertEqual(take["takeover"], "signed-pending-settle")
            # lease still live -> quota is held and cannot be released
            with self.assertRaises(ReservationHasSignature):
                o.budgets.manual_release("crash-signed", "admin", "try")
            settled = o.budgets.manual_settle(
                "crash-signed", "admin", "worker died after signing")
            self.assertEqual(settled["status"], "CONSUMED")
            self.assertEqual(settled["consumed_amount"], 1)
            # the signature still verifies
            vr = o.verify(w["purpose"], b"m", sig)
            self.assertTrue(vr["valid"])
            # quantity bookkeeping includes manual handling record
            self.assertIn("before", settled["manual_handling"])
            self.assertIn("after", settled["manual_handling"])

    def test_04b_expired_signed_reservation_is_consumed_not_released(self):
        w = make_world(total=2, cap=2, lease=30)
        with w["store"].locked():
            o = orch(w)
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="exp-signed", amount=2)
            o.sign_reserved("exp-signed", [b"m"])
            o.save()
        w["clock"].advance(31)
        with w["store"].locked():
            o = orch(w)
            take = o.budgets.takeover("exp-signed")
            self.assertEqual(take["takeover"], "completed")
            self.assertEqual(take["status"], "CONSUMED")
            self.assertEqual(take["consumed_amount"], 1)
            b = o.budgets._find_budget(w["budget_id"])
            view = o.budgets.budget_view(b)
            self.assertEqual(view["consumed"], 1)
            self.assertEqual(view["reserved"], 0)

    # ------------------------------------------------------------------ 5
    def test_05_crash_after_reserve_no_signature(self):
        w = make_world(total=2, cap=2, lease=30)
        with w["store"].locked():
            o = orch(w)
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="crash-unsigned", amount=2)
            o.save()
        # lease lapses with no signature
        w["clock"].advance(31)
        with w["store"].locked():
            o = orch(w)
            take = o.budgets.takeover("crash-unsigned")
            self.assertEqual(take["takeover"], "released")
            self.assertEqual(take["status"], "RELEASED")
            b = o.budgets._find_budget(w["budget_id"])
            view = o.budgets.budget_view(b)
            self.assertEqual(view["reserved"], 0)
            self.assertEqual(view["available"], 2)
            # a fresh reservation can now use the returned quota
            nr = o.reserve_signing(purpose=w["purpose"],
                                   subject=w["subject"],
                                   request_id="new-after-return", amount=2)
            self.assertFalse(nr["duplicate"])

    def test_05b_manual_release_unsigned_records_quantities(self):
        w = make_world(total=2, cap=2, lease=300)
        with w["store"].locked():
            o = orch(w)
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="hung", amount=2)
            out = o.budgets.manual_release("hung", "admin1",
                                           "worker stuck; no sig audit")
            self.assertEqual(out["status"], "RELEASED")
            mh = out["manual_handling"]
            self.assertEqual(mh["operator"], "admin1")
            self.assertEqual(mh["before"]["available"], 0)
            self.assertEqual(mh["after"]["available"], 2)
            with self.assertRaises(ReservationState):
                o.budgets.manual_release("hung", "admin1", "again")

    # ------------------------------------------------------------------ 6
    def test_06_shrink_and_revision_conflict(self):
        w = make_world(total=10, cap=4)
        with w["store"].locked():
            o = orch(w)
            # consume 3, hold 2 -> floor 5
            governed_sign(o, w, "c1", b"a")
            governed_sign(o, w, "c2", b"b")
            governed_sign(o, w, "c3", b"c")
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="hold1", amount=2)
            # shrink to 5 is exactly at floor -> ok
            self._revise(o, w, 5, 4, base=1)
            # shrink to 4 below floor -> rejected
            with self.assertRaises(Exception) as cm:
                self._revise(o, w, 4, 4, base=2)
            self.assertIn("cannot be below", str(cm.exception))
            # concurrent admin holds stale base revision 1 while current=2
            with self.assertRaises(BudgetRevisionConflict) as cm2:
                self._revise(o, w, 8, 4, base=1)
            self.assertEqual(cm2.exception.current_revision, 2)
            self.assertEqual(cm2.exception.base_revision, 1)
            self.assertEqual(cm2.exception.current_snapshot["total"], 5)
            self.assertEqual(cm2.exception.current_snapshot["consumed"], 3)
            self.assertEqual(cm2.exception.current_snapshot["reserved"], 2)
            # current sheet untouched by the rejected edits
            b = o.budgets._find_budget(w["budget_id"])
            self.assertEqual(b["total"], 5)
            self.assertEqual(b["revision"], 2)

    def _revise(self, o, w, total, cap, *, base, reason="t"):
        b = o.budgets._find_budget(w["budget_id"])
        fields = {"budget_id": b["id"], "base_revision": base,
                  "revision": base + 1, "total": total,
                  "per_batch_cap": cap,
                  "effective_at": b["effective_at"], "deadline": b["deadline"],
                  "lease_seconds": b["lease_seconds"], "reason": reason}
        sig = B.sign_officer_body(
            w["officer_seed"], B.officer_body("budget-revise-v1", fields))
        return o.budgets.revise_budget(
            b["id"], base_revision=base, total=total, per_batch_cap=cap,
            effective_at=b["effective_at"], deadline=b["deadline"],
            lease_seconds=b["lease_seconds"],
            officer_id="sec", officer_sig=sig, reason=reason)

    # ------------------------------------------------------------------ 7
    def test_07_pause_and_resume(self):
        w = make_world(total=3, cap=2)
        with w["store"].locked():
            o = orch(w)
            o.budgets.pause_budget(w["budget_id"], "sec", "incident")
            with self.assertRaises(BudgetPaused):
                o.reserve_signing(purpose=w["purpose"],
                                  subject=w["subject"],
                                  request_id="p1", amount=1)
            o.budgets.resume_budget(w["budget_id"], "sec", "resolved")
            out = o.reserve_signing(purpose=w["purpose"],
                                    subject=w["subject"],
                                    request_id="p2", amount=1)
            self.assertFalse(out["duplicate"])
            b = o.budgets._find_budget(w["budget_id"])
            self.assertEqual(b["revision"], 3)  # issue, pause, resume

    # ------------------------------------------------------------------ 8
    def test_08_old_version_signatures_still_verify(self):
        w = make_world(total=3, cap=2)
        with w["store"].locked():
            o = orch(w)
            r = o.reserve_signing(purpose=w["purpose"],
                                  subject=w["subject"],
                                  request_id="v1-sig", amount=1)
            v = o.sign_reserved("v1-sig", [b"history"])
            old_sig = v["signatures_b64"][0]
            old_vid = v["version_id"]
            o.settle_signing("v1-sig")
            # rotation happens strictly after the historical reservation
            w["clock"].advance(5)
            # rotate: a second generation becomes ACTIVE; the old is RETIRING
            seed2, pub2 = crypto.gen_signing_keypair()
            staged = o.dir.register_version(w["purpose"], seed2, pub2,
                                            [3, 4], [], "cer_2")
            newkv, old = o.dir.activate(staged["id"], "cer_2")
            self.assertEqual(old["id"], old_vid)
            self.assertEqual(old["status"], "RETIRING")
            # the existing budget is pinned to the now-retired version, so
            # new reservations against it are refused (key retired)
            with self.assertRaises(KeyVersionRetired):
                o.budgets.reserve(purpose=w["purpose"],
                                  key_version_id=old_vid,
                                  subject=w["subject"],
                                  request_id="oldver", amount=1)
            # but the historical signature still verifies under the RETIRING
            # version (verify accepts all recognized versions)
            res = o.verify(w["purpose"], b"history", old_sig)
            self.assertTrue(res["valid"])
            self.assertEqual(res["version_id"], old_vid)
            self.assertEqual(res["status"], "RETIRING")
            self.assertFalse(res["active"])
            o.save()
        # archive replay must not flag the historical reserve against a
        # version that retired only afterwards
        with w["store"].locked():
            bundle = build_bundle(orch(w))
        res = verify_budgets(bundle)
        retired_findings = [f for f in res["findings"]
                            if f["code"] == "KEY_RETIRED_RESERVE"]
        self.assertEqual(retired_findings, [])
        self.assertTrue(res["ok"], res["findings"])

    # ------------------------------------------------------------------ 9
    def test_09_no_budget_purpose_legacy_compatible(self):
        w = make_world(total=3, cap=2)
        with w["store"].locked():
            o = orch(w)
            # an unrelated purpose with an ACTIVE key but NO budget sheet
            seed, pub = crypto.gen_signing_keypair()
            kv = o.dir.register_version("free-purpose", seed, pub,
                                        [1], [], "cer_free")
            legacy = o.sign("free-purpose", b"anything")
            self.assertFalse(legacy["budget_governed"])
            self.assertEqual(legacy["status"], "ACTIVE")
            # verify works and an exempt audit record exists
            vr = o.verify("free-purpose", b"anything", legacy["sig"])
            self.assertTrue(vr["valid"])
            exempt = [e for e in o.audit.entries
                      if e["event"] == "budget_exempt_signature"]
            self.assertEqual(len(exempt), 1)
            # the governed purpose cannot use the legacy shortcut
            with self.assertRaises(Exception):
                o.sign(w["purpose"], b"governed")

    def test_09b_window_closed_blocks_reserve(self):
        w = make_world(total=3, cap=2, window=100)
        w["clock"].advance(200)
        with w["store"].locked():
            o = orch(w)
            with self.assertRaises(BudgetWindowClosed):
                o.reserve_signing(purpose=w["purpose"],
                                  subject=w["subject"],
                                  request_id="late", amount=1)

    def test_09c_subject_revoked_blocks_reserve(self):
        w = make_world(total=3, cap=2)
        with w["store"].locked():
            o = orch(w)
            o.budgets.revoke_subject(w["subject"], "offboarded", "sec")
            with self.assertRaises(SubjectRevoked):
                o.reserve_signing(purpose=w["purpose"],
                                  subject=w["subject"],
                                  request_id="rx", amount=1)

    def test_09d_settle_within_lease_rejects_expired(self):
        w = make_world(total=3, cap=2, lease=10)
        with w["store"].locked():
            o = orch(w)
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="ttl", amount=1)
            o.save()
        w["clock"].advance(11)
        with w["store"].locked():
            o = orch(w)
            with self.assertRaises(ReservationExpired):
                o.sign_reserved("ttl", [b"late"])


class BudgetArchiveVerification(unittest.TestCase):
    def _bundle(self, w):
        with w["store"].locked():
            o = orch(w)
            return build_bundle(o)

    # ------------------------------------------------------------- 10 ok
    def test_10_clean_archive_verifies(self):
        w = make_world(total=4, cap=3)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "a1", b"m1")
            governed_sign(o, w, "a2", b"m2")
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="a3", amount=1)
            o.sign_reserved("a3", [b"m3"])
            o.settle_signing("a3")
            # an unsigned reservation left HELD (within lease) is fine now
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="held", amount=1)
            o.save()
        res = verify_budgets(self._bundle(w))
        self.assertTrue(res["ok"], res["findings"])

    def test_10b_exempt_archive_verifies(self):
        w = make_world(total=1, cap=1)
        with w["store"].locked():
            o = orch(w)
            seed, pub = crypto.gen_signing_keypair()
            o.dir.register_version("free-x", seed, pub, [1], [], "cf")
            o.sign("free-x", b"ok")
            o.save()
        res = verify_budgets(self._bundle(w))
        self.assertTrue(res["ok"], res["findings"])

    # ------------------------------------------------------- tamper cases
    def test_tamper_forged_budget(self):
        from kc.budget_verify import FORGED_BUDGET
        w = make_world(total=2, cap=2)
        bundle = self._bundle(w)
        for e in bundle["audit"]:
            if e["event"] == "budget_issued":
                e["payload"]["total"] = 99
                e["payload"]["officer_sig"] = e["payload"]["officer_sig"][:-2] \
                    + "AA"
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == FORGED_BUDGET
                            for f in res["findings"]))

    def test_tamper_double_consumption(self):
        from kc.budget_verify import DUPLICATE_CONSUMPTION
        w = make_world(total=2, cap=2)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "d1", b"m")
            o.save()
        bundle = self._bundle(w)
        # duplicate the consumed event for the same request (insider with
        # write access appends a chain-consistent duplicate settlement)
        consumed = [e for e in bundle["audit"]
                    if e["event"] == "budget_reservation_consumed"][0]
        dup = copy.deepcopy(consumed)
        idx = bundle["audit"].index(consumed) + 1
        bundle["audit"].insert(idx, dup)
        # keep the chain self-consistent after the insertion
        _relink_from(bundle, idx)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == DUPLICATE_CONSUMPTION
                            for f in res["findings"]))

    def test_tamper_over_quota(self):
        from kc.budget_verify import OVER_QUOTA_SIGNATURE
        w = make_world(total=1, cap=1)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "q1", b"m")
            o.save()
        bundle = self._bundle(w)
        # append a second reserve that blows past total
        reserved = [e for e in bundle["audit"]
                    if e["event"] == "budget_reserved"][0]
        extra = copy.deepcopy(reserved)
        extra["payload"]["request_id"] = "q-fake"
        bundle["audit"].append(extra)
        _relink_from(bundle, len(bundle["audit"]) - 1)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == OVER_QUOTA_SIGNATURE
                            for f in res["findings"]))

    def test_tamper_cross_subject(self):
        from kc.budget_verify import CROSS_SUBJECT
        w = make_world(total=2, cap=2)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "cs1", b"m")
            o.save()
        bundle = self._bundle(w)
        for i, e in enumerate(bundle["audit"]):
            if e["event"] == "budget_reserved":
                e["payload"]["subject"] = "someone-else"
                _relink_from(bundle, i)
                break
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == CROSS_SUBJECT
                            for f in res["findings"]))

    def test_tamper_reserved_after_window(self):
        from kc.budget_verify import RESERVED_AFTER_WINDOW
        w = make_world(total=2, cap=2, window=100)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "w1", b"m")
            o.save()
        bundle = self._bundle(w)
        for i, e in enumerate(bundle["audit"]):
            if e["event"] == "budget_reserved":
                e["payload"]["reserved_at"] = w["clock"]() + 5000
                _relink_from(bundle, i)
                break
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == RESERVED_AFTER_WINDOW
                            for f in res["findings"]))

    def test_tamper_revision_regression(self):
        from kc.budget_verify import REVISION_REGRESSION
        w = make_world(total=5, cap=3)
        with w["store"].locked():
            o = orch(w)
            b = o.budgets._find_budget(w["budget_id"])
            fields = {"budget_id": b["id"], "base_revision": 1,
                      "revision": 2, "total": 4, "per_batch_cap": 3,
                      "effective_at": b["effective_at"],
                      "deadline": b["deadline"], "lease_seconds": b["lease_seconds"],
                      "reason": "x"}
            sig = B.sign_officer_body(
                w["officer_seed"],
                B.officer_body("budget-revise-v1", fields))
            o.budgets.revise_budget(
                b["id"], base_revision=1, total=4, per_batch_cap=3,
                effective_at=b["effective_at"], deadline=b["deadline"],
                lease_seconds=b["lease_seconds"],
                officer_id="sec", officer_sig=sig, reason="x")
            o.save()
        bundle = self._bundle(w)
        for i, e in enumerate(bundle["audit"]):
            if e["event"] == "budget_revised":
                e["payload"]["revision"] = 1  # regression
                _relink_from(bundle, i)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == REVISION_REGRESSION
                            for f in res["findings"]))

    def test_tamper_release_with_signature(self):
        from kc.budget_verify import RELEASED_SIGNED
        w = make_world(total=2, cap=2, lease=10)
        with w["store"].locked():
            o = orch(w)
            o.reserve_signing(purpose=w["purpose"], subject=w["subject"],
                              request_id="rs", amount=1)
            o.sign_reserved("rs", [b"m"])
            o.save()
        bundle = self._bundle(w)
        # fabricate a release event despite the signature audit
        sig_ev = [e for e in bundle["audit"]
                  if e["event"] == "budget_signature_recorded"][0]
        release = {
            "event": "budget_reservation_released",
            "payload": {"budget_id": w["budget_id"],
                        "request_id": "rs", "reservation_id":
                        sig_ev["payload"]["reservation_id"],
                        "released_amount": 1, "consumed_amount": 0,
                        "kind": "manual-release", "actor": "evil",
                        "manual": True, "reason": "fabricated"}}
        bundle["audit"].append(release)
        _relink_from(bundle, len(bundle["audit"]) - 1)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == RELEASED_SIGNED
                            for f in res["findings"]))

    def test_tamper_consumption_without_signature(self):
        from kc.budget_verify import CONSUMPTION_NO_SIG
        w = make_world(total=2, cap=2)
        bundle = self._bundle(w)
        reserved = {
            "event": "budget_reserved",
            "payload": {"budget_id": w["budget_id"], "request_id": "ghost",
                        "reservation_id": "rsv_ghost", "purpose": w["purpose"],
                        "key_version_id": w["key"]["id"],
                        "subject": w["subject"], "amount": 1,
                        "reserved_at": w["clock"](),
                        "lease_expires_at": w["clock"]() + 30,
                        "budget_revision": 1}}
        consumed = {
            "event": "budget_reservation_consumed",
            "payload": {"budget_id": w["budget_id"], "request_id": "ghost",
                        "reservation_id": "rsv_ghost", "amount": 1,
                        "consumed_amount": 1, "released_amount": 0,
                        "kind": "settled", "actor": "x",
                        "n_signatures": 0}}
        bundle["audit"].extend([reserved, consumed])
        _relink_from(bundle, len(bundle["audit"]) - 2)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == CONSUMPTION_NO_SIG
                            for f in res["findings"]))

    def test_tamper_signature_without_settlement(self):
        from kc.budget_verify import SIG_NO_SETTLE
        w = make_world(total=2, cap=2, lease=10)
        bundle = self._bundle(w)
        # reserve + signature but no consume, and declare lease expired
        now = w["clock"]()
        reserved = {
            "event": "budget_reserved",
            "payload": {"budget_id": w["budget_id"], "request_id": "orphan",
                        "reservation_id": "rsv_o", "purpose": w["purpose"],
                        "key_version_id": w["key"]["id"],
                        "subject": w["subject"], "amount": 1,
                        "reserved_at": now - 100,
                        "lease_expires_at": now - 50,
                        "budget_revision": 1}}
        signed = {
            "event": "budget_signature_recorded",
            "payload": {"budget_id": w["budget_id"], "request_id": "orphan",
                        "reservation_id": "rsv_o",
                        "key_version_id": w["key"]["id"], "count": 1,
                        "produced": [], "subject": w["subject"]}}
        bundle["audit"].extend([reserved, signed])
        _relink_from(bundle, len(bundle["audit"]) - 2)
        res = verify_budgets(bundle, now=now)
        self.assertTrue(any(f["code"] == SIG_NO_SETTLE
                            for f in res["findings"]))

    def test_tamper_exempt_under_governed_purpose(self):
        from kc.budget_verify import EXEMPT_GOVERNED
        w = make_world(total=2, cap=2)
        bundle = self._bundle(w)
        bundle["audit"].append({
            "event": "budget_exempt_signature",
            "payload": {"purpose": w["purpose"],
                        "key_version_id": w["key"]["id"],
                        "governance": "exempt",
                        "message_digest": "x", "sig_digest": "y",
                        "ts": w["clock"]()}})
        _relink_from(bundle, len(bundle["audit"]) - 1)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == EXEMPT_GOVERNED
                            for f in res["findings"]))

    def test_tamper_floor_breach(self):
        from kc.budget_verify import FLOOR_BREACHED
        w = make_world(total=3, cap=2)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "f1", b"m")
            o.save()
        bundle = self._bundle(w)
        rev = [e for e in bundle["audit"]
               if e["event"] == "budget_issued"][0]
        fake = {
            "event": "budget_revised",
            "payload": {"budget_id": w["budget_id"], "base_revision": 1,
                        "revision": 2, "old_total": 3, "total": 0,
                        "per_batch_cap": 2,
                        "effective_at": rev["payload"]["effective_at"],
                        "deadline": rev["payload"]["deadline"],
                        "lease_seconds": 30, "old_lease": 30,
                        "consumed_at_revise": 1, "reserved_at_revise": 0,
                        "officer_id": "sec", "officer_sig": "A" * 86,
                        "reason": "shrink below floor"}}
        bundle["audit"].append(fake)
        _relink_from(bundle, len(bundle["audit"]) - 1)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == FLOOR_BREACHED
                            for f in res["findings"]))

    def test_tamper_floor_breach_valid_sig_still_flagged(self):
        """A genuine officer-signed below-floor revision is rejected by the
        manager itself; in the archive it can only appear via tampering."""
        from kc.budget_verify import FLOOR_BREACHED
        w = make_world(total=3, cap=2)
        with w["store"].locked():
            o = orch(w)
            governed_sign(o, w, "g1", b"m")
            o.save()
        bundle = self._bundle(w)
        rev = [e for e in bundle["audit"]
               if e["event"] == "budget_issued"][0]
        # proper base64 placeholder signature (invalid -> FORGED_BUDGET too),
        # but the FLOOR check must fire regardless of signature validity
        fake_sig = crypto.b64e(b"\x00" * 64)
        fake = {
            "event": "budget_revised",
            "payload": {"budget_id": w["budget_id"], "base_revision": 1,
                        "revision": 2, "old_total": 3, "total": 0,
                        "per_batch_cap": 2,
                        "effective_at": rev["payload"]["effective_at"],
                        "deadline": rev["payload"]["deadline"],
                        "lease_seconds": 30, "old_lease": 30,
                        "consumed_at_revise": 1, "reserved_at_revise": 0,
                        "officer_id": "sec", "officer_sig": fake_sig,
                        "reason": "shrink below floor"}}
        bundle["audit"].append(fake)
        _relink_from(bundle, len(bundle["audit"]) - 1)
        res = verify_budgets(bundle)
        self.assertTrue(any(f["code"] == FLOOR_BREACHED
                            for f in res["findings"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
