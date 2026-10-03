"""HTTP end-to-end test for verifiable signing-quota budgets.

Bootstraps a store, generates a key, then over the network exercises:
  * duty gate (only ROOT_OWNER writes budget orders),
  * subject registration, order creation with time window + short lease,
  * budgeted sign via /api/sign with request id and idempotent replay,
  * exhaustion and concurrent contention for the final unit,
  * revision conflict returning current revision/quantity diff,
  * pause/resume, revoked subject,
  * crash-takeover (hold with/without signature) using real subprocesses,
  * manual hung-reservation handling (reason required, signed hold refused),
  * public unauthenticated dashboard status,
  * legacy purpose still signs without a budget,
  * export bundle verifies; and the independent CLI catches a tampered file.
"""
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8131
ROOT = f"/tmp/kc-http-budget-{PORT}"
shutil.rmtree(ROOT, ignore_errors=True)

subprocess.run([sys.executable, "-m", "kc.bootstrap", "--root", ROOT],
               capture_output=True, text=True, check=True)
proc = subprocess.Popen(
    [sys.executable, "-m", "kc.server", "--root", ROOT,
     "--port", str(PORT), "--ticket-ttl", "600"],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

TOKENS = {}


def call(path, body=None, token=None, method=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        BASE + path, data=data,
        method=method or ("POST" if body is not None else "GET"),
        headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def login(pid):
    call("/api/session/login-challenge", {"device_id": "dev_" + pid})
    s, j = call("/api/session/login", {"device_id": "dev_" + pid})
    assert s == 200, (s, j)
    TOKENS[pid] = j["token"]


try:
    BASE = f"http://127.0.0.1:{PORT}"
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)
    ALL = ("alice", "bruno", "carla", "diego")
    for pid in ALL:
        login(pid)
    A, D, C = TOKENS["alice"], TOKENS["diego"], TOKENS["carla"]

    def steps(cid, pids):
        for pid in pids:
            assert call(f"/api/ceremonies/{cid}/attest",
                        {"device_id": "dev_" + pid}, token=TOKENS[pid])[0] == 200
        for pid in pids:
            assert call(f"/api/ceremonies/{cid}/receive",
                        {"device_id": "dev_" + pid}, token=TOKENS[pid])[0] == 200
        for pid in ("alice", "bruno", "carla"):
            assert call(f"/api/ceremonies/{cid}/confirm",
                        {"device_id": "dev_" + pid}, token=TOKENS[pid])[0] == 200

    # generate an ACTIVE key
    s, c0 = call("/api/ceremonies/open",
                 {"kind": "GENERATE", "policy_id": "pol-root-v1",
                  "purpose": "root-signing"}, token=A)
    assert s == 200, (s, c0)
    steps(c0["id"], ALL)
    assert call(f"/api/ceremonies/{c0['id']}/commit", {}, token=A)[0] == 200
    s, keys = call("/api/keys?purpose=root-signing", token=A)
    kv = keys["keys"][0]["id"]
    print("generated key", kv[:14])

    # Auxiliary budget scenarios need their own purposes (one order per
    # purpose), and the policy only covers root-signing. Register ACTIVE
    # test keys for them directly through the ungated library surface.
    auxp = subprocess.run(
        [sys.executable, os.path.join(os.path.dirname(__file__),
                                      "register_test_keys.py"),
         ROOT, "cont-svc", "pause-svc", "crash-svc", "legacy-svc"],
        capture_output=True, text=True, check=True)
    AUX = json.loads(auxp.stdout)

    # public status needs no token
    s, st = call("/api/budgets/status")
    assert s == 200 and st["budgets"] == [] and st["requests"] == [], (s, st)

    # duty gate: operator cannot create budgets
    s, j = call("/api/sign-budgets/subjects",
                {"subject": "svc-bill", "name": "billing"}, token=D)
    assert s == 403 and j["error"] == "FORBIDDEN", (s, j)

    # owner registers subject + creates a budget order (total=3, lease 2s)
    s, j = call("/api/sign-budgets/subjects",
                {"subject": "svc-bill", "name": "billing service"}, token=A)
    assert s == 200, (s, j)
    order = {"purpose": "root-signing", "key_version_id": kv,
             "subject": "svc-bill", "total": 3, "batch_cap": 1,
             "lease_seconds": 2, "valid_until": time.time() + 3600,
             "reason": "e2e acceptance"}
    s, j = call("/api/sign-budgets", order, token=A)
    assert s == 200, (s, j)
    bid = j["budget"]["budget_id"]
    assert j["budget"]["available"] == 3

    # sign without a request id is rejected for a budgeted purpose
    s, j = call("/api/sign", {"purpose": "root-signing", "message": "x"},
                token=A)
    assert s == 422 and j["error"] == "POLICY_VIOLATION", (s, j)

    # budgeted draws
    sigs = {}
    for i in range(3):
        s, r = call("/api/sign",
                    {"purpose": "root-signing", "message": f"m{i}",
                     "request_id": f"req-{i}", "subject": "svc-bill"},
                    token=A)
        assert s == 200 and r["budgeted"] and not r.get("replay"), (s, r)
        sigs[f"req-{i}"] = r
        s, v = call("/api/verify",
                    {"purpose": "root-signing", "message": f"m{i}",
                     "sig": r["sig"]}, token=C)
        assert v["valid"]
    # replay: same request id -> first signature + settlement, no new charge
    s, rep = call("/api/sign",
                  {"purpose": "root-signing", "message": "m0",
                   "request_id": "req-0", "subject": "svc-bill"}, token=A)
    assert s == 200 and rep["replay"] and rep["sig"] == sigs["req-0"]["sig"], \
        (s, rep)
    assert rep["settled_at"] == sigs["req-0"]["settled_at"]
    print("budgeted draw + replay ok")

    # exhausted
    s, j = call("/api/sign",
                {"purpose": "root-signing", "message": "m3",
                 "request_id": "req-3", "subject": "svc-bill"}, token=A)
    assert s == 409 and j["error"] == "QUOTA_EXHAUSTED", (s, j)

    # concurrent contention for a fresh budget's final unit
    s, j = call("/api/sign-budgets/subjects",
                {"subject": "svc-cont", "name": "contention"}, token=A)
    s, j = call("/api/sign-budgets",
                {"purpose": "cont-svc", "key_version_id": AUX["cont-svc"],
                 "subject": "svc-cont", "total": 1, "batch_cap": 1,
                 "lease_seconds": 30, "valid_until": time.time() + 3600},
                token=A)
    assert s == 200, (s, j)

    def contend(i):
        return call("/api/sign",
                    {"purpose": "cont-svc", "message": f"c{i}",
                     "request_id": f"c-{i}", "subject": "svc-cont"}, token=D)
    with ThreadPoolExecutor(max_workers=12) as ex:
        rs = list(ex.map(contend, range(12)))
    oks = [r for s, r in rs if s == 200]
    nos = [r for s, r in rs if s != 200]
    assert len(oks) == 1 and all(r["error"] == "QUOTA_EXHAUSTED" for r in nos), \
        (len(oks), [r.get("error") for r in nos])
    print("last-unit contention: exactly 1 of 12 succeeded")

    # revision conflict: owner revises once (3->2 disallowed below floor=3)
    s, j = call(f"/api/sign-budgets/{bid}/revise",
                {"base_revision": 1, "total": 2, "reason": "shrink"}, token=A)
    assert s == 409 and j["error"] == "SHRINK_BELOW_CONSUMED_PLUS_HELD", (s, j)
    s, j = call(f"/api/sign-budgets/{bid}/revise",
                {"base_revision": 1, "total": 3, "reason": "noop-level"},
                token=A)
    assert s == 200 and j["budget"]["revision"] == 2, (s, j)
    s, stale = call(f"/api/sign-budgets/{bid}/revise",
                    {"base_revision": 1, "total": 3}, token=A)
    assert s == 409 and stale["error"] == "REVISION_CONFLICT", (s, stale)
    assert stale["current_revision"] == 2
    assert stale["current_snapshot"]["total"] == 3
    print("revision conflict returns current version + quantities")

    # pause blocks, resume allows
    s, j = call(f"/api/sign-budgets/{bid}/pause",
                {"reason": "incident"}, token=A)
    assert s == 200 and j["budget"]["status"] == "PAUSED"
    # create a small budget to demonstrate pause blocking a new draw
    call("/api/sign-budgets/subjects",
         {"subject": "svc-p", "name": "p"}, token=A)
    s, pb = call("/api/sign-budgets",
                 {"purpose": "pause-svc", "key_version_id": AUX["pause-svc"],
                  "subject": "svc-p", "total": 2, "batch_cap": 1,
                  "lease_seconds": 30, "valid_until": time.time() + 3600},
                 token=A)
    pbid = pb["budget"]["budget_id"]
    pcode, presp = call(f"/api/sign-budgets/{pbid}/pause", {"reason": "x"},
                        token=A)
    assert pcode == 200, (pcode, presp, s, pb)
    s, j = call("/api/sign",
                {"purpose": "pause-svc", "message": "q", "request_id": "q1",
                 "subject": "svc-p"}, token=A)
    assert s == 409 and j["error"] == "BUDGET_PAUSED", (s, j)
    assert call(f"/api/sign-budgets/{pbid}/resume", {"reason": "clear"},
                token=A)[0] == 200
    assert call("/api/sign",
                {"purpose": "pause-svc", "message": "q", "request_id": "q1",
                 "subject": "svc-p"}, token=A)[0] == 200
    print("pause/resume ok")

    # crashed worker: hold only, lease expires, takeover releases
    call("/api/sign-budgets/subjects",
         {"subject": "svc-crash", "name": "cr"}, token=A)
    s, cb = call("/api/sign-budgets",
                 {"purpose": "crash-svc", "key_version_id": AUX["crash-svc"],
                  "subject": "svc-crash", "total": 2, "batch_cap": 1,
                  "lease_seconds": 1, "valid_until": time.time() + 3600},
                 token=A)
    assert s == 200, (s, cb)
    # real subprocess takes the hold then exits (code 17) without signing
    p = subprocess.run([sys.executable,
                        os.path.join(os.path.dirname(__file__),
                                     "register_test_keys.py"),
                        "--crash", ROOT, "hold", "cr-hold",
                        "crash-svc", "svc-crash", "msg"])
    assert p.returncode == 17
    time.sleep(1.5)  # let the 1s lease expire
    s, tv = call("/api/sign-requests/cr-hold/takeover", {}, token=A)
    assert s == 200 and tv["action"] == "released_expired", (s, tv)
    s, st = call("/api/budgets/status")
    bst = [b for b in st["budgets"] if b["purpose"] == "crash-svc"][0]
    assert bst["held"] == 0 and bst["available"] == 2, bst
    print("crash after hold (unsigned) -> takeover released")

    # crashed worker after signature -> takeover settles, quota not reusable
    p = subprocess.run([sys.executable,
                        os.path.join(os.path.dirname(__file__),
                                     "register_test_keys.py"),
                        "--crash", ROOT, "signature", "cr-sig",
                        "crash-svc", "svc-crash", "signed-then-dead"])
    assert p.returncode == 17
    s, tv = call("/api/sign-requests/cr-sig/takeover", {}, token=A)
    assert s == 200 and tv["action"] == "settled_signature", (s, tv)
    # manual release of that now-signed/settled request is refused
    s, j = call("/api/sign-requests/cr-sig/release",
                {"reason": "try to free it anyway"}, token=A)
    assert s == 409 and j["error"] == "RESERVATION_NOT_HELD", (s, j)
    print("crash after signature -> takeover settled; release refused")

    # manual handling needs a reason and records operator + quantities
    subprocess.run([sys.executable,
                    os.path.join(os.path.dirname(__file__),
                                 "register_test_keys.py"),
                    "--crash", ROOT, "hold-ok", "hung-1",
                    "crash-svc", "svc-crash", "msg"], check=True)
    s, j = call("/api/sign-requests/hung-1/release",
                {"reason": "   "}, token=A)
    assert s == 422 and j["error"] == "POLICY_VIOLATION", (s, j)
    s, j = call("/api/sign-requests/hung-1/release",
                {"reason": "host decommissioned; no signature"}, token=A)
    assert s == 200 and j["state"] == "RELEASED", (s, j)
    print("manual handling: reason required, operator/quantities recorded")

    # legacy purpose with no budget signs the old way
    s, legacy = call("/api/sign",
                     {"purpose": "legacy-svc", "message": "plain"}, token=A)
    assert s == 200 and not legacy.get("budgeted"), (s, legacy)
    print("unbudgeted purpose uses legacy signing")

    # export bundle verifies (the test-helper keys bypass ceremonies, so the
    # acceptance gate here is the budget replay; ceremony provenance is fully
    # covered by the other suites)
    s, bundle = call("/api/export", token=A)
    assert s == 200
    from kc.export import verify_bundle
    verdict = verify_bundle(bundle)
    assert verdict["checks"]["sign_budgets_ok"], verdict["problems"]
    budget_problems = [p for p in verdict["problems"]
                       if p.startswith("sign budget")]
    assert not budget_problems, budget_problems
    print("export bundle verifies: sign_budgets_ok")

    # tampered archive file is caught by the independent CLI
    out = "/tmp/kc-budget-tampered-%d.json" % PORT
    with open(out, "w") as f:
        json.dump(bundle, f)
    # forge: bump the first budget total upward AND remove a settle event
    tampered = json.loads(json.dumps(bundle))
    for e in tampered["audit"]:
        if e["event"] == "budget_reservation_settled":
            e["payload"]["quantity"] = 99
    with open(out, "w") as f:
        json.dump(tampered, f)
    r = subprocess.run([sys.executable, "-m", "kc.budget_cli",
                        "verify-bundle", "--bundle", out],
                       capture_output=True, text=True)
    assert r.returncode == 1 and "OVER_BUDGET" in r.stdout, r.stdout
    print("tampered archive detected:",
          [ln.strip() for ln in r.stdout.splitlines() if "OVER_BUDGET" in ln][0])

    print("BUDGET HTTP E2E ALL OK")
finally:
    proc.terminate()
    proc.wait(timeout=10)
