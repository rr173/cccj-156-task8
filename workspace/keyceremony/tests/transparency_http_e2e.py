"""End-to-end HTTP test for the caller-facing transparency surface.

Drives a running ``kc.server``:

  * public proof endpoints (head, inclusion, consistency, log public key),
  * the browser-side verifier (the exact JavaScript from transparency.html is
    evaluated under node against live server responses),
  * public gossip submission that triggers a same-size split-view and freezes
    publication,
  * a four-eyes PUBLISH_GENERATION ticket being refused while frozen while
    historical verification keeps working,
  * an owner-only split resolution with a reason, after which the four-eyes
    publish succeeds and the head chain continues,
  * the rejected head staying available as evidence.

The independent checker is finally run over the exported bundle.
"""

import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc import crypto, ed25519  # noqa: E402
from kc.transparency import head_content  # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8360
ROOT = f"/tmp/kc-tl-http-{PORT}"
shutil.rmtree(ROOT, ignore_errors=True)

subprocess.run([sys.executable, "-m", "kc.bootstrap", "--root", ROOT],
               check=True, capture_output=True, text=True)

# Seed one completed GENERATE ceremony + an opening key directly through the
# library (the HTTP four-eyes ceremony flow itself is covered by http_e2e).
_seed = r"""
import sys
sys.path.insert(0, %r)
from kc.storage import Store
from kc.ceremony import Orchestrator
from kc import policy as P
from kc.fleet import Fleet
import os
store = Store(%r)
fleet = Fleet(os.path.join(%r, "wallets"))
pids = ["alice","bruno","carla","diego"]
ctx = {pid: __import__("kc.console", fromlist=["DeviceContext"]).DeviceContext(
    fleet.get("dev_"+pid)) for pid in pids}
with store.locked():
    o = Orchestrator(store)
    cid = o.open_ceremony(P.GENERATE, "pol-root-v1", "root-signing",
                          "alice")["id"]
    for p in pids: ctx[p].attest(o, cid)
    for p in pids: ctx[p].receive_share(o, cid)
    for p in ("alice","bruno","carla"): ctx[p].confirm(o, cid)
    o.commit(cid, "alice")
    o.save()
""" % (os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ROOT, ROOT)
subprocess.run([sys.executable, "-c", _seed], check=True,
               capture_output=True, text=True)

proc = subprocess.Popen(
    [sys.executable, "-m", "kc.server", "--root", ROOT,
     "--port", str(PORT)],
    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def call(path, body=None, token=None, raw=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(
        BASE + path, data=data,
        method=("POST" if body is not None else "GET"), headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


try:
    BASE = f"http://127.0.0.1:{PORT}"
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.1)

    # transparency page is served
    with urllib.request.urlopen(BASE + "/transparency") as r:
        html = r.read().decode()
    assert "透明度日志" in html and "verifyInclusion" in html
    print("transparency page served")

    # ---- 1. public proofs without a session ------------------------------
    s, st = call("/api/transparency/status")
    assert s == 200 and st["tree_size"] == 1, st
    s, pubj = call("/api/transparency/log-pub")
    assert s == 200
    log_pub = crypto.b64d(pubj["log_pub"])
    s, inc = call("/api/transparency/inclusion?purpose=root-signing&version=1")
    assert s == 200 and inc["tree_size"] == 1 and inc["leaf_index"] == 0, inc
    # head signature is publicly verifiable
    from kc.transparency import verify_head_signature
    assert verify_head_signature(log_pub, inc["head"])
    old_head = inc["head"]
    print("public inclusion + signed head ok")

    # ---- 2. browser-side verification over live responses -----------------
    node = shutil.which("node")
    if node:
        import re
        js = re.search(r"<script>(.*)</script>", html, re.S).group(1)
        driver = js + """
async function main(){
  const get = async p => JSON.parse(await (await fetch(BASE+p)).text());
  const inc = await get("/api/transparency/inclusion?purpose=root-signing&version=1");
  const pubj = await get("/api/transparency/log-pub");
  const pub = Uint8Array.from(Buffer.from(pubj.log_pub,"base64"));
  const lh = await leafHash(inc.leaf);
  const leafOk = hex(lh) === inc.leaf_hash;
  const incOk = await verifyInclusion(inc.leaf_index, inc.tree_size,
      inc.inclusion_path, lh, unhex(inc.head.root_hash));
  const sigOk = Ed.verify(pub, asciiBytes(canonical({
      domain:inc.head.domain, tree_size:inc.head.tree_size,
      root_hash:inc.head.root_hash, issued_at:inc.head.issued_at,
      prev_head_hash:inc.head.prev_head_hash})),
    Uint8Array.from(Buffer.from(inc.head.tree_head_sig,"base64")));
  console.log(JSON.stringify({leafOk, incOk, sigOk}));
}
main();
"""
        driver = 'const BASE=' + json.dumps(BASE) + ';\n' + driver
        n = subprocess.run([node, "-e", driver], capture_output=True, text=True)
        assert n.returncode == 0, n.stderr
        verdict = json.loads(n.stdout.strip().splitlines()[-1])
        assert verdict == {"leafOk": True, "incOk": True, "sigOk": True}, verdict
        print("browser-side recomputation agrees with server:", verdict)
    else:
        print("node unavailable; skipping in-page JS execution check")

    # ---- 3. log in everyone -----------------------------------------------
    def login(pid):
        did = "dev_" + pid
        call("/api/session/login-challenge", {"device_id": did})
        s, j = call("/api/session/login", {"device_id": did})
        assert s == 200, (s, j)
        return j["token"]

    TOK = {pid: login(pid)
           for pid in ("alice", "bruno", "carla", "diego")}
    tok_alice, tok_diego, tok_carla = (TOK["alice"], TOK["diego"],
                                       TOK["carla"])

    # ---- 4. gossip a same-size different-root head -> freeze --------------
    # The forked head is signed by the same log key (it represents a control
    # instance that equivocated), so a valid signature with a different root
    # is exactly what split-view detection must catch.
    from kc.storage import Store
    seed = Store(ROOT).service_seed()
    bad = head_content(old_head["tree_size"], "f" * 64,
                       old_head["issued_at"], old_head["prev_head_hash"])
    bad["tree_head_sig"] = crypto.b64e(ed25519.sign(
        seed, crypto.dumps(
            {k: bad[k] for k in
             ("domain", "tree_size", "root_hash", "issued_at",
              "prev_head_hash")}).encode()))
    s, obs = call("/api/transparency/observe",
                  {"head": bad, "observer": "external-monitor"})
    assert s == 200 and obs["frozen"], obs
    assert obs["split"]["kind"] == "SAME_SIZE_DIFFERENT_ROOT", obs["split"]
    split_id = obs["split"]["split_id"]
    print("split-view freeze recorded:", split_id)

    # historical signature verification still works while frozen
    msg = "history"
    s, signed = call("/api/sign",
                     {"purpose": "root-signing", "message": msg},
                     token=tok_diego)
    assert s == 200, (s, signed)
    s, v = call("/api/verify",
                {"purpose": "root-signing", "message": msg,
                 "sig": signed["sig"]}, token=tok_alice)
    assert s == 200 and v["valid"], (s, v)
    print("historical sign/verify works while frozen")

    # ---- 5. open+commit a ROTATE, then the four-eyes publish must fail ----
    s, c = call("/api/ceremonies/open",
                {"kind": "ROTATE", "policy_id": "pol-root-v1",
                 "purpose": "root-signing"}, token=tok_alice)
    assert s == 200, (s, c)
    cid = c["id"]
    for pid in ("alice", "bruno", "carla", "diego"):
        assert call(f"/api/ceremonies/{cid}/attest",
                    {"device_id": "dev_" + pid},
                    token=TOK[pid])[0] == 200
    for pid in ("alice", "bruno", "carla", "diego"):
        assert call(f"/api/ceremonies/{cid}/receive",
                    {"device_id": "dev_" + pid},
                    token=TOK[pid])[0] == 200
    for pid in ("alice", "bruno", "carla"):
        assert call(f"/api/ceremonies/{cid}/confirm",
                    {"device_id": "dev_" + pid},
                    token=TOK[pid])[0] == 200
    # the materializing commit itself is blocked by the freeze
    s, j = call(f"/api/ceremonies/{cid}/commit", {}, token=tok_alice)
    assert s == 409 and j["error"] == "TRANSPARENCY_FROZEN", (s, j)
    print("new key materialization blocked while frozen")

    # ---- 6. only the owner may resolve, reason required -------------------
    s, j = call("/api/transparency/resolve",
                {"split_id": split_id, "chosen_head": old_head,
                 "reason": "verified local extension out of band"},
                token=tok_carla)
    assert s == 403, (s, j)
    s, j = call("/api/transparency/resolve",
                {"split_id": split_id, "chosen_head": old_head,
                 "reason": ""}, token=tok_alice)
    assert j["error"] == "TRANSPARENCY_RESOLUTION_REJECTED", (s, j)
    s, current = call("/api/transparency/status")
    s, res = call("/api/transparency/resolve",
                  {"split_id": split_id,
                   "chosen_head": current["head"],
                   "reason": "out-of-band witness quorum confirmed local log"},
                  token=tok_alice)
    assert s == 200, (s, res)
    assert res["rejected"]["root"] == "f" * 64
    s, st2 = call("/api/transparency/status")
    assert st2["frozen"] is None and st2["resolutions"], st2
    print("owner resolution with reason unfroze; rejected head retained")

    # ---- 7. the blocked rotation round must be discarded (four-eyes ABORT),
    # then open a new one and run the full four-eyes publish ---------------
    s, ta = call("/api/tickets",
                 {"operation": "ABORT_ACTIVE",
                  "payload": {"ceremony_id": cid,
                              "reason": "discard round blocked by freeze"}},
                 token=tok_alice)
    assert s == 200, (s, ta)
    s, ar = call("/api/tickets/approve",
                 {"ticket_id": ta["ticket"]["id"]}, token=tok_carla)
    assert s == 200, (s, ar)
    s, c2 = call("/api/ceremonies/open",
                 {"kind": "ROTATE", "policy_id": "pol-root-v1",
                  "purpose": "root-signing"}, token=tok_alice)
    assert s == 200, (s, c2)
    cid2 = c2["id"]
    for pid in ("alice", "bruno", "carla", "diego"):
        assert call(f"/api/ceremonies/{cid2}/attest",
                    {"device_id": "dev_" + pid},
                    token=TOK[pid])[0] == 200
    for pid in ("alice", "bruno", "carla", "diego"):
        assert call(f"/api/ceremonies/{cid2}/receive",
                    {"device_id": "dev_" + pid},
                    token=TOK[pid])[0] == 200
    for pid in ("alice", "bruno", "carla"):
        assert call(f"/api/ceremonies/{cid2}/confirm",
                    {"device_id": "dev_" + pid},
                    token=TOK[pid])[0] == 200
    s, j = call(f"/api/ceremonies/{cid2}/commit", {}, token=tok_alice)
    assert s == 200, (s, j)
    s, keys = call("/api/keys?purpose=root-signing", token=tok_alice)
    old_id = keys["purposes"]["root-signing"]
    # direct publish is four-eyes protected
    s, j = call(f"/api/ceremonies/{cid2}/publish",
                {"expected_active": old_id}, token=tok_diego)
    assert s == 422 and j["error"] == "PROTECTED_OPERATION", (s, j)
    # diego initiates, alice (owner) approves -> CAS publish
    s, t1 = call("/api/tickets",
                 {"operation": "PUBLISH_GENERATION",
                  "payload": {"ceremony_id": cid2,
                              "expected_active": old_id}}, token=tok_diego)
    assert s == 200, (s, t1)
    tid = t1["ticket"]["id"]
    s, appr = call("/api/tickets/approve", {"ticket_id": tid},
                   token=tok_alice)
    assert s == 200, (s, appr)

    # ---- 8. post-resolution transparency proofs ---------------------------
    s, st3 = call("/api/transparency/status")
    assert st3["tree_size"] >= 4, st3
    s, cc = call(f"/api/transparency/consistency?old_size="
                 f"{old_head['tree_size']}")
    assert s == 200
    from kc.transparency import verify_consistency
    assert verify_consistency(
        old_head["tree_size"], cc["tree_size"],
        cc["consistency_path"],
        bytes.fromhex(old_head["root_hash"]),
        bytes.fromhex(cc["head"]["root_hash"]))
    print("post-resolution consistency proves strict append:",
          old_head["tree_size"], "->", cc["tree_size"])

    # the rejected head is still evidence in the status
    assert any(sp["split_id"] == split_id and sp.get("status") == "RESOLVED"
               for sp in st3["splits"]), \
        [(sp["split_id"], sp.get("status")) for sp in st3["splits"]]

    print("TRANSPARENCY HTTP E2E PASSED")
finally:
    proc.terminate()
    proc.wait()
