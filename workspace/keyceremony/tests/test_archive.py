"""Scenarios for the offline audit archive: incremental witnessing,
isolation on equivocation, crash recovery, concurrent convergence,
single-shot CAS publication and offline tamper detection.

Run:  python3 -m unittest tests.test_archive -v
"""

import json
import multiprocessing
import os
import random
import shutil
import tempfile
import threading
import time
import unittest
import urllib.request

from kc.archive import (
    Archive, ArchiveError, ZERO64, generate_source_keypair, segment_digest,
    sign_segment, witness_root,
)
from kc import crypto
from kc.archive_verify import verify_bundle


def make_chain(seed, sid, n, *, start=1, prev=ZERO64, fork_digest_at=None,
               payloads=None, omit=()):
    """Produce a signed chain of n segments."""
    segs = []
    for i in range(n):
        seq = start + i
        payload = (payloads or {}).get(seq) or crypto.digest_hex(
            {"source": sid, "seq": seq, "body": f"event-{seq}"})
        seg = sign_segment(seed, sid, seq, prev, payload)
        if seq not in omit:
            segs.append(seg)
        prev = segment_digest(seg)
    return segs


def tamper(seg, **fields):
    s = dict(seg)
    s.update(fields)
    return s


class ArchiveTestBase(unittest.TestCase):
    THRESHOLD = 2

    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="kcarc-")
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.arc = Archive(self.root, self.THRESHOLD)
        self.keys = {}
        for sid in ("region-a", "region-b", "region-c"):
            pub, seed = generate_source_keypair()
            self.keys[sid] = {"pub": pub, "seed": seed,
                              "seed_raw": crypto.b64d(seed)}
            self.arc.register_source(sid, pub)

    def segs(self, sid, n, **kw):
        return make_chain(self.keys[sid]["seed_raw"], sid, n, **kw)


class TestOutOfOrderAndIdempotency(ArchiveTestBase):
    def test_unordered_gap_fill_and_continuous_confirmation(self):
        a_segs = self.segs("region-a", 5)
        shuffled = a_segs[2:] + a_segs[:2]   # seq 3,4,5,1,2
        res = self.arc.ingest_many(shuffled)
        # nothing confirms beyond seq gap until predecessors arrive
        statuses = {r["seq"]: r["status"] for r in res["results"]}
        self.assertEqual(statuses[3], "accepted")
        v = self.arc.view()["sources"]["region-a"]
        self.assertEqual(v["last_confirmed_seq"], 5)
        self.assertEqual(v["gaps"], [])
        # digest chain
        self.assertEqual(v["last_confirmed_digest"], segment_digest(a_segs[4]))

    def test_duplicate_upload_is_idempotent(self):
        segs = self.segs("region-a", 3)
        self.arc.ingest_many(segs)
        before = self.arc.view()["sources"]["region-a"]
        for seg in segs:  # repeat everything, twice
            r = self.arc.ingest(seg)
            self.assertEqual(r["status"], "duplicate")
        after = self.arc.view()["sources"]["region-a"]
        self.assertEqual(before["confirmed_count"], after["confirmed_count"])
        self.assertEqual(after["last_confirmed_seq"], 3)

    def test_partial_upload_reports_gap(self):
        self.arc.ingest_many([s for s in self.segs("region-a", 5)
                              if s["seq"] in (1, 2, 4)])
        v = self.arc.view()["sources"]["region-a"]
        self.assertEqual(v["last_confirmed_seq"], 2)
        self.assertEqual([g["seq"] for g in v["gaps"]], [3])

    def test_missing_predecessor_is_never_jumped(self):
        segs = self.segs("region-a", 4)
        self.arc.ingest(segs[3])  # only seq 4
        v = self.arc.view()["sources"]["region-a"]
        self.assertEqual(v["last_confirmed_seq"], 0)
        self.assertEqual([g["seq"] for g in v["gaps"]], [1, 2, 3])

    def test_forged_signature_is_rejected_and_kept_as_evidence(self):
        other_seed = os.urandom(32)
        forged = sign_segment(other_seed, "region-a", 1, ZERO64,
                              crypto.digest_hex("x"))
        with self.assertRaises(ArchiveError):
            self.arc.ingest(forged)
        inv = self.arc.view()["invalid_segments"]
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["reason"], "BAD_SIGNATURE")
        # good segment still processes
        self.arc.ingest(self.segs("region-a", 1)[0])
        self.assertEqual(
            self.arc.view()["sources"]["region-a"]["last_confirmed_seq"], 1)


class TestEquivocation(ArchiveTestBase):
    def test_same_seq_conflict_isolates_and_preserves_evidence(self):
        segs = self.segs("region-a", 4)
        self.arc.ingest_many(segs)
        # an alternative seq 3, signed by the *same* source key, with
        # different payload -> continuation from a different seq-3 digest,
        # re-signing prev so the signature itself is valid
        seed = self.keys["region-a"]["seed_raw"]
        alt3 = sign_segment(seed, "region-a", 3, segs[2]["prev"],
                            crypto.digest_hex("totally-different-payload"))
        r = self.arc.ingest(alt3)
        self.assertEqual(r["status"], "conflict")
        cid = r["conflict_id"]
        v = self.arc.view()
        self.assertTrue(v["sources"]["region-a"]["isolated"])
        self.assertIn(cid, v["open_conflicts"])
        # confirmed state not polluted: tip stays at 4 on the original branch
        self.assertEqual(v["sources"]["region-a"]["last_confirmed_seq"], 4)
        self.assertEqual(v["sources"]["region-a"]["last_confirmed_digest"],
                         segment_digest(segs[3]))
        # evidence carries both fully signed versions
        cfx = v["conflicts"][cid]
        digests = {x["digest"] for x in cfx["versions"]}
        self.assertEqual(digests, {segment_digest(segs[2]),
                                   segment_digest(alt3)})

    def test_other_sources_keep_aggregating_under_isolation(self):
        self.arc.ingest_many(self.segs("region-a", 2))
        self.arc.ingest_many(self.segs("region-b", 2))
        seed = self.keys["region-a"]["seed_raw"]
        alt1 = sign_segment(seed, "region-a", 1, ZERO64,
                            crypto.digest_hex("fork"))
        self.arc.ingest(alt1)
        # region-b still accepts more segments
        self.arc.ingest_many(self.segs("region-b", 4))
        b = self.arc.view()["sources"]["region-b"]
        self.assertEqual(b["last_confirmed_seq"], 4)
        self.assertFalse(b["isolated"])

    def test_resolve_requires_reason_and_valid_version(self):
        segs = self.segs("region-a", 2)
        self.arc.ingest_many(segs)
        seed = self.keys["region-a"]["seed_raw"]
        alt1 = sign_segment(seed, "region-a", 1, ZERO64,
                            crypto.digest_hex("fork"))
        cid = self.arc.ingest(alt1)["conflict_id"]
        with self.assertRaises(ArchiveError):
            self.arc.resolve_conflict(cid, segment_digest(alt1), "", "ops")
        with self.assertRaises(ArchiveError):
            self.arc.resolve_conflict(cid, "0" * 64, "reason", "ops")

    def test_resolve_revalidates_forward_chain(self):
        segs = self.segs("region-a", 4)
        self.arc.ingest_many(segs)
        seed = self.keys["region-a"]["seed_raw"]
        alt3 = sign_segment(seed, "region-a", 3, segs[2]["prev"],
                            crypto.digest_hex("alt-payload"))
        cid = self.arc.ingest(alt3)["conflict_id"]
        r = self.arc.resolve_conflict(cid, segment_digest(alt3),
                                      "payload was mis-exported", "alice")
        # seq 3,4 built on rejected version -> rolled back; alt3 confirms but
        # old seq4 does not link to it -> chain stops, new gap at 4
        self.assertEqual(r["rolled_back"], [3, 4])
        self.assertEqual(r["revalidated"], [3])
        v = self.arc.view()["sources"]["region-a"]
        self.assertFalse(v["isolated"])
        self.assertEqual(v["last_confirmed_seq"], 3)
        self.assertEqual(v["last_confirmed_digest"], segment_digest(alt3))
        self.assertEqual([g["seq"] for g in v["gaps"]], [4])

        # exporter re-sends a corrected seq4 chained onto alt3, then seq5
        fixed4 = sign_segment(seed, "region-a", 4, segment_digest(alt3),
                              crypto.digest_hex("fixed-4"))
        fixed5 = sign_segment(seed, "region-a", 5, segment_digest(fixed4),
                              crypto.digest_hex("fixed-5"))
        self.arc.ingest_many([fixed4, fixed5])
        v = self.arc.view()["sources"]["region-a"]
        self.assertEqual(v["last_confirmed_seq"], 5)
        # rejected versions remain in the conflict evidence forever
        cfx = self.arc.view()["conflicts"][cid]
        self.assertEqual(cfx["status"], "RESOLVED")
        self.assertEqual(len(cfx["versions"]), 2)
        self.assertEqual(cfx["decision"]["reason"],
                         "payload was mis-exported")

    def test_rejected_version_reupload_stays_rejected(self):
        s1 = self.segs("region-a", 2)[0]
        s2 = self.segs("region-a", 2)[1]
        self.arc.ingest_many([s1, s2])
        self.arc.ingest_many(self.segs("region-b", 1))
        seed = self.keys["region-a"]["seed_raw"]
        fork = sign_segment(seed, "region-a", 1, ZERO64,
                            crypto.digest_hex("FORK"))
        cid = self.arc.ingest(fork)["conflict_id"]
        self.arc.resolve_conflict(cid, segment_digest(s1),
                                  "verified out of band", "ops")
        # repeated rejected-fork uploads never re-isolate or pollute
        for _ in range(3):
            r = self.arc.ingest(fork)
            self.assertEqual(r["status"], "duplicate")
            self.assertTrue(r["rejected"])
        v = self.arc.view()
        self.assertFalse(v["sources"]["region-a"]["isolated"])
        self.assertEqual(v["sources"]["region-a"]["last_confirmed_digest"],
                         segment_digest(s2))
        # a brand-new third version is a fresh equivocation and isolates
        third = sign_segment(seed, "region-a", 1, ZERO64,
                             crypto.digest_hex("third-fork"))
        r = self.arc.ingest(third)
        self.assertEqual(r["status"], "conflict")
        self.assertTrue(self.arc.view()["sources"]["region-a"]["isolated"])

    def test_candidate_conflict_before_confirmation(self):
        # unordered: seq1 arrives, then two seq2 versions before advancing
        s1 = self.segs("region-a", 1)[0]
        seed = self.keys["region-a"]["seed_raw"]
        v2a = sign_segment(seed, "region-a", 2, segment_digest(s1),
                           crypto.digest_hex("a"))
        v2b = sign_segment(seed, "region-a", 2, segment_digest(s1),
                           crypto.digest_hex("b"))
        # ingest seq2 forks before seq1 -> first one can't confirm; then
        # conflict registered
        self.arc.ingest(v2a)
        r = self.arc.ingest(v2b)
        self.assertEqual(r["status"], "conflict")
        v = self.arc.view()
        self.assertTrue(v["sources"]["region-a"]["isolated"])
        self.assertEqual(v["sources"]["region-a"]["last_confirmed_seq"], 0)
        # resolve accepting v2a; now seq1 + seq2 confirm
        self.arc.resolve_conflict(r["conflict_id"], segment_digest(v2a),
                                  "a wins", "ops")
        self.arc.ingest(s1)
        v = self.arc.view()["sources"]["region-a"]
        self.assertEqual(v["last_confirmed_seq"], 2)
        self.assertEqual(v["last_confirmed_digest"], segment_digest(v2a))


class TestRecovery(ArchiveTestBase):
    def test_resume_after_interruption(self):
        self.arc.ingest_many([s for s in self.segs("region-a", 5)
                              if s["seq"] != 3])
        self.arc.ingest_many(self.segs("region-b", 3))
        last_a = self.arc.view()["sources"]["region-a"]["last_confirmed_seq"]
        self.assertEqual(last_a, 2)

        # simulate process restart: brand-new object over same directory
        arc2 = Archive(self.root)
        r = arc2.recover()
        self.assertEqual(r["sources"]["region-a"]["last_seq"], 2)
        self.assertEqual(r["sources"]["region-b"]["last_seq"], 3)

        # fill the gap after restart; no double counting
        self.arc.ingest(self.segs("region-a", 5)[2])  # seq3
        r = self.arc.recover()
        self.assertEqual(r["sources"]["region-a"]["advanced_on_recovery"], 0)
        v = arc2.view()["sources"]["region-a"]
        self.assertEqual(v["last_confirmed_seq"], 5)
        self.assertEqual(len(v["candidate_versions"]), 0)

    def test_isolation_survives_restart(self):
        segs = self.segs("region-a", 2)
        self.arc.ingest_many(segs)
        seed = self.keys["region-a"]["seed_raw"]
        alt = sign_segment(seed, "region-a", 1, ZERO64,
                           crypto.digest_hex("fork"))
        cid = self.arc.ingest(alt)["conflict_id"]
        Archive(self.root).recover()
        v = Archive(self.root).view()
        self.assertTrue(v["sources"]["region-a"]["isolated"])
        self.assertIn(cid, v["open_conflicts"])


def _worker_ingest(args):
    root, seg = args
    Archive(root).ingest(seg)
    return True


class TestConvergence(ArchiveTestBaseBase := ArchiveTestBase):
    def test_threads_converge_to_one_tip(self):
        segs = {sid: self.segs(sid, 6) for sid in self.keys}
        pool = [s for sid in segs for s in segs[sid]]
        random.Random(42).shuffle(pool)

        def worker(chunk):
            for s in chunk:
                Archive(self.root).ingest(s)

        chunks = [pool[i::4] for i in range(4)]
        threads = [threading.Thread(target=worker, args=(c,)) for c in chunks]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        v = self.arc.view()
        for sid in self.keys:
            self.assertEqual(v["sources"][sid]["last_confirmed_seq"], 6, sid)
            self.assertFalse(v["sources"][sid]["isolated"], sid)

    def test_separate_processes_converge(self):
        segs = {sid: self.segs(sid, 4) for sid in self.keys}
        pool = [(self.root, s) for sid in segs for s in segs[sid]]
        random.Random(7).shuffle(pool)
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(4) as p:
            results = p.map(_worker_ingest, pool)
        self.assertTrue(all(results))
        v = self.arc.view()
        for sid in self.keys:
            self.assertEqual(v["sources"][sid]["last_confirmed_seq"], 4)
            self.assertFalse(v["sources"][sid]["isolated"])
            self.assertEqual(v["sources"][sid]["gaps"], [])


class TestPublication(ArchiveTestBase):
    def test_threshold_blocks_then_publishes(self):
        self.arc.ingest_many(self.segs("region-a", 3))
        with self.assertRaises(ArchiveError) as cm:
            self.arc.publish()
        self.assertEqual(cm.exception.code, "THRESHOLD_NOT_MET")
        self.assertEqual(cm.exception.details["problems"][0]["have"], 1)

        self.arc.ingest_many(self.segs("region-b", 2))
        m = self.arc.publish()["manifest"]
        self.assertEqual(m["round"], 1)
        self.assertEqual(m["threshold"], 2)
        self.assertEqual(len(m["heads"]), 2)
        self.assertEqual(self.arc.view()["current_round"], 2)

    def test_open_conflict_blocks_publication(self):
        self.arc.ingest_many(self.segs("region-a", 1))
        self.arc.ingest_many(self.segs("region-b", 1))
        seed = self.keys["region-a"]["seed_raw"]
        self.arc.ingest(sign_segment(seed, "region-a", 1, ZERO64,
                                     crypto.digest_hex("fork")))
        with self.assertRaises(ArchiveError) as cm:
            self.arc.publish()
        self.assertEqual(cm.exception.code, "OPEN_CONFLICTS")

    def test_concurrent_publish_single_winner(self):
        for sid in self.keys:
            self.arc.ingest_many(self.segs(sid, 2))
        outcomes = []

        def publisher():
            outcomes.append(Archive(self.root).publish())

        ts = [threading.Thread(target=publisher) for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        roots = {o["manifest"]["root"] for o in outcomes}
        self.assertEqual(len(roots), 1)
        self.assertEqual(sum(not o["race_lost"] for o in outcomes), 1)
        self.assertTrue(all(o["published"] for o in outcomes))

    def test_concurrent_publish_single_winner_multiprocess(self):
        for sid in self.keys:
            self.arc.ingest_many(self.segs(sid, 2))
        ctx = multiprocessing.get_context("fork")
        with ctx.Pool(6) as p:
            outs = p.map(_worker_publish, [self.root] * 6)
        roots = {o["manifest"]["root"] for o in outs}
        self.assertEqual(len(roots), 1)
        self.assertEqual(sum(not o["race_lost"] for o in outs), 1)

    def test_late_segments_go_to_next_round_history_immutable(self):
        self.arc.ingest_many(self.segs("region-a", 2))
        self.arc.ingest_many(self.segs("region-b", 2))
        first = self.arc.publish()["manifest"]

        late_a = self.segs("region-a", 1)[0]
        # already inside first round; build genuinely new confirmations
        more_a = self.segs("region-a", 4)
        self.arc.ingest(more_a[3])  # seq4 needs seq3
        self.arc.ingest(more_a[2])  # seq3
        second = self.arc.publish()["manifest"]
        self.assertEqual(second["round"], 2)
        self.assertEqual(second["prev_root"], first["root"])
        # late re-upload of an old confirmed segment must not rewrite history
        self.arc.ingest(late_a)
        stored_first = self.arc.publication(1)
        self.assertEqual(stored_first, first)
        # re-publish attempt in the same round returns the existing root
        again = self.arc.publish()
        self.assertTrue(again["race_lost"])
        self.assertEqual(again["manifest"]["root"], second["root"])

    def test_witness_root_independently_recomputable(self):
        self.arc.ingest_many(self.segs("region-a", 2))
        self.arc.ingest_many(self.segs("region-b", 1))
        m = self.arc.publish()["manifest"]
        recomputed = witness_root(1, 2, m["heads"], ZERO64)
        self.assertEqual(recomputed, m["root"])


def _worker_publish(root):
    return Archive(root).publish()


class TestOfflineVerifier(ArchiveTestBase):
    def _clean_bundle(self):
        self.arc.ingest_many(self.segs("region-a", 4))
        self.arc.ingest_many(self.segs("region-b", 3))
        self.arc.publish()
        self.arc.ingest_many(self.segs("region-c", 2))
        self.arc.publish()
        return self.arc.export_bundle()

    def test_clean_bundle_passes(self):
        report = verify_bundle(self._clean_bundle(), strict=False)
        self.assertTrue(report["ok"], json.dumps(report, indent=2))

    def test_deleted_segment_detected(self):
        b = self._clean_bundle()
        # drop seq 2 of region-a from the confirmed set AND keep later seqs
        segs = b["segments"]
        keep = [s for s in segs
                if not (s["source"] == "region-a" and s["seq"] == 2
                        and s["status"] == "confirmed")]
        b["segments"] = keep
        report = verify_bundle(b, strict=False)
        codes = {f["code"] for f in report["findings"]}
        self.assertIn("GAP_CROSSED", codes)

    def test_swapped_segment_detected(self):
        b = self._clean_bundle()
        # change payload of one confirmed segment but keep its old signature
        target = next(s for s in b["segments"]
                      if s["source"] == "region-a" and s["seq"] == 2)
        target["payload_digest"] = crypto.digest_hex("swapped")
        # envelope digest no longer matches content; verifier recomputes
        report = verify_bundle(b, strict=False)
        self.assertFalse(report["ok"])
        self.assertTrue(any(f["code"] in
                            ("MALFORMED_SEGMENT", "FORGED_SIGNATURE",
                             "SEGMENT_SWAPPED")
                            for f in report["findings"]))

    def test_forged_signature_detected(self):
        b = self._clean_bundle()
        target = next(s for s in b["segments"]
                      if s["source"] == "region-b" and s["seq"] == 1)
        target["sig"] = crypto.b64e(b"\x00" * 64)
        report = verify_bundle(b, strict=False)
        self.assertIn("FORGED_SIGNATURE",
                      {f["code"] for f in report["findings"]})

    def test_chain_break_detected(self):
        b = self._clean_bundle()
        target = next(s for s in b["segments"]
                      if s["source"] == "region-b" and s["seq"] == 2)
        target["prev"] = "f" * 64
        # recompute envelope digest so it passes the shape check, but sig
        # fails and chain breaks
        target.pop("digest", None)
        report = verify_bundle(b, strict=False)
        codes = {f["code"] for f in report["findings"]}
        self.assertTrue({"FORGED_SIGNATURE", "CHAIN_BROKEN"} & codes)

    def test_double_count_detected(self):
        b = self._clean_bundle()
        dup = dict(next(s for s in b["segments"]
                        if s["source"] == "region-a" and s["seq"] == 1))
        # alter digest to simulate two different confirmed versions
        dup["payload_digest"] = crypto.digest_hex("dup-other")
        dup["digest"] = crypto.digest_hex({"source": dup["source"],
                                           "seq": dup["seq"],
                                           "prev": dup["prev"],
                                           "payload_digest":
                                               dup["payload_digest"]})
        b["segments"].append(dup)
        report = verify_bundle(b, strict=False)
        self.assertIn("DOUBLE_COUNTED",
                      {f["code"] for f in report["findings"]})

    def test_gap_crossed_in_checkpoint_detected(self):
        b = self._clean_bundle()
        # falsify checkpoint: claim seq 4 while deleting evidence of seq 3
        keep = [s for s in b["segments"]
                if not (s["source"] == "region-a" and s["seq"] == 3
                        and s["status"] == "confirmed")]
        b["segments"] = keep
        report = verify_bundle(b, strict=False)
        self.assertTrue({"GAP_CROSSED", "CHECKPOINT_MISMATCH"}
                        & {f["code"] for f in report["findings"]})

    def test_publish_with_open_conflict_detected(self):
        self.arc.ingest_many(self.segs("region-a", 2))
        self.arc.ingest_many(self.segs("region-b", 2))
        seed = self.keys["region-a"]["seed_raw"]
        self.arc.ingest(sign_segment(seed, "region-a", 1, ZERO64,
                                     crypto.digest_hex("fork")))
        # operator bypasses guard with force (simulating a tampered export)
        self.arc.publish(force=True)
        b = self.arc.export_bundle()
        report = verify_bundle(b, strict=False)
        self.assertIn("UNRESOLVED_PUBLISH",
                      {f["code"] for f in report["findings"]})

    def test_tampered_root_detected(self):
        b = self._clean_bundle()
        b["publications"][0]["root"] = "9" * 64
        report = verify_bundle(b, strict=False)
        self.assertIn("ROOT_TAMPERED",
                      {f["code"] for f in report["findings"]})

    def test_prev_root_rewrite_detected(self):
        b = self._clean_bundle()
        b["publications"][1]["prev_root"] = "a" * 64
        b["publications"][1]["root"] = witness_root(
            2, 2, b["publications"][1]["heads"], "a" * 64)
        report = verify_bundle(b, strict=False)
        self.assertIn("PREVIOUS_ROOT_REWRITTEN",
                      {f["code"] for f in report["findings"]})

    def test_threshold_falsification_detected(self):
        b = self._clean_bundle()
        # strip one head from the first manifest but keep the old root
        m = b["publications"][0]
        m["heads"] = [h for h in m["heads"] if h["source"] != "region-b"]
        m["segments"] = [s for s in m["segments"]
                         if s["source"] != "region-b"]
        report = verify_bundle(b, strict=False)
        self.assertTrue({"THRESHOLD_FALSIFIED", "ROOT_TAMPERED"}
                        & {f["code"] for f in report["findings"]})

    def test_resolved_conflict_bundle_passes(self):
        segs = self.segs("region-a", 3)
        self.arc.ingest_many(segs)
        self.arc.ingest_many(self.segs("region-b", 2))
        seed = self.keys["region-a"]["seed_raw"]
        alt1 = sign_segment(seed, "region-a", 1, ZERO64,
                            crypto.digest_hex("fork"))
        cid = self.arc.ingest(alt1)["conflict_id"]
        self.arc.resolve_conflict(cid, segment_digest(segs[0]),
                                  "original verified out of band", "alice")
        self.arc.publish()
        report = verify_bundle(self.arc.export_bundle(), strict=False)
        self.assertTrue(report["ok"], json.dumps(report, indent=2))

    def test_equivocation_without_conflict_record_detected(self):
        b = self._clean_bundle()
        # inject a second signed candidate but delete the conflict record
        sid = "region-b"
        seed = self.keys[sid]["seed_raw"]
        seg1 = next(s for s in b["segments"]
                    if s["source"] == sid and s["seq"] == 1)
        alt = sign_segment(seed, sid, 1, ZERO64,
                           crypto.digest_hex("hidden-fork"))
        b["segments"].append({"source": sid, "seq": 1, "status": "candidate",
                              "prev": alt["prev"],
                              "digest": segment_digest(alt),
                              "payload_digest": alt["payload_digest"],
                              "sig": alt["sig"]})
        report = verify_bundle(b, strict=False)
        self.assertIn("CONFLICT_NOT_ISOLATED",
                      {f["code"] for f in report["findings"]})


class TestHTTPEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from kc.archive_server import Handler, ThreadingHTTPServer
        cls.root = tempfile.mkdtemp(prefix="kcarc-http-")
        Handler.app = type("A", (), {"archive": Archive(cls.root, 2)})()
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.thr = threading.Thread(target=cls.httpd.serve_forever,
                                   daemon=True)
        cls.thr.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        shutil.rmtree(cls.root, ignore_errors=True)

    def _req(self, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if body is not None else "GET")
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def test_full_http_flow_with_concurrent_publish(self):
        code, reg = self._req("/api/archive/sources",
                              {"source": "r-a"})
        self.assertEqual(code, 200)
        self.assertIn("seed", reg)

        # r-b needs a key we know; register with a real pair
        pub_b, seed_b = generate_source_keypair()
        code, _ = self._req("/api/archive/sources",
                            {"source": "r-b", "pubkey": pub_b})
        self.assertEqual(code, 200)

        seed_a = crypto.b64d(reg["seed"])
        for s in make_chain(seed_a, "r-a", 3):
            self.assertEqual(self._req("/api/archive/segments", s)[0], 200)
        for s in make_chain(crypto.b64d(seed_b), "r-b", 3):
            self._req("/api/archive/segments", s)

        # threshold initially met via r-a + r-b2 (different registrations);
        # concurrent publish
        outs = []

        def pub():
            outs.append(self._req("/api/archive/publish", {}))

        ts = [threading.Thread(target=pub) for _ in range(5)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        roots = {o[1]["manifest"]["root"] for o in outs}
        self.assertEqual(len(roots), 1)
        wins = [o for o in outs if not o[1].get("race_lost")]
        self.assertEqual(len(wins), 1)

        code, st = self._req("/api/archive/status")
        self.assertEqual(code, 200)
        self.assertEqual(st["current_round"], 2)

        # restart recovery endpoint + bundle verifier
        self.assertEqual(self._req("/api/archive/recover", {})[0], 200)
        _, bundle = self._req("/api/archive/bundle")
        report = verify_bundle(bundle, strict=False)
        self.assertTrue(report["ok"], json.dumps(report, indent=2))


if __name__ == "__main__":
    unittest.main()
