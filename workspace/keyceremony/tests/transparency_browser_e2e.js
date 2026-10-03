#!/usr/bin/env node
/*
 * Browser-side test driver for kc/transparency.html.
 *
 * Loads the EXACT <script> shipped in the page (no reimplementation), stubs
 * just enough DOM/localStorage/crypto to run it under node against the live
 * fixture server (tests/transparency_browser_server.py), and exercises every
 * acceptance scenario:
 *
 *   1. >= 2 version updates: latest head badge trusted; the member path for
 *      any version rebuilds in the browser;
 *   2. mixed purposes / a larger tree / many historical heads: repeated
 *      switching and reloads keep identical verdicts;
 *   3. tampered summary content or attestation field -> untrusted, still
 *      untrusted after a fresh re-evaluation ("reload");
 *   4. old-head vs new-head: legal extension passes; truncation / reorder /
 *      early-entry rewrite / foreign-tree splice all fail;
 *   5. forged attestation or same-height divergent head: conflict saved,
 *      publication frozen, historical verification unaffected;
 *   6. recover from the provable branch with a reason: publishing resumes and
 *      the recovered branch still verifies trusted on reopen.
 *
 * Usage: node transparency_browser_e2e.js PORT
 */
"use strict";
const fs = require("fs");
const path = require("path");
const http = require("http");

const PORT = parseInt(process.argv[2] || "8361", 10);
const BASE = `http://127.0.0.1:${PORT}`;

function request(method, p, body, token) {
  return new Promise((resolve, reject) => {
    const data = body !== undefined ? JSON.stringify(body) : null;
    const headers = {};
    if (data) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = Buffer.byteLength(data);  // node won't set it
    }                                                        // on manual write
    if (token) headers["Authorization"] = "Bearer " + token;
    const rq = http.request(BASE + p, {method, headers}, (res) => {
      let buf = "";
      res.on("data", c => buf += c);
      res.on("end", () => {
        let j = null; try { j = JSON.parse(buf); } catch (e) {}
        resolve({status: res.statusCode, json: j, text: buf});
      });
    });
    rq.on("error", reject);
    if (data) rq.write(data);
    rq.end();
  });
}
const get = p => request("GET", p);
const post = (p, b, t) => request("POST", p, b, t);

// node 20 exposes globalThis.crypto.subtle already; make sure it exists.
if (!globalThis.crypto || !globalThis.crypto.subtle) {
  globalThis.crypto = require("crypto").webcrypto;
}

// ---- minimal DOM / storage stub ------------------------------------------------
const storage = {};
const elements = {};
function makeEl(id) {
  return {id, value: "", textContent: "", innerHTML: "", style: {}};
}
const IDS = ["headview","pinned","pininfo","splitview","latest","branches",
  "observer","obshead","obsresult","inc-purpose","inc-version","inc-vid",
  "incresult","cons-oldsize","cons-oldroot","cons-oldhead","consresult",
  "token","resolve-split","resolve-reason","resolve-result",
  "hist-size","histresult","histlist","hist-progress"];
for (const id of IDS) elements[id] = makeEl(id);

globalThis.window = globalThis;
globalThis.localStorage = {
  getItem: k => (k in storage ? storage[k] : null),
  setItem: (k, v) => { storage[k] = String(v); },
  removeItem: k => { delete storage[k]; },
};
globalThis.document = {
  getElementById: id => {
    if (!elements[id]) elements[id] = makeEl(id);
    return elements[id];
  },
};
// node 20 ships fetch but cannot resolve RELATIVE urls without a document;
// wrap it so the page's "/api/..." calls reach the live fixture, and headers
// map the same way the browser fetch API accepts them.
const nodeFetch = globalThis.fetch;
globalThis.fetch = async (p, opts) => {
  const url = String(p).startsWith("http") ? String(p) : BASE + String(p);
  return nodeFetch(url, opts);
};

// ---- load the exact page script ------------------------------------------------
const html = fs.readFileSync(
  path.join(__dirname, "..", "kc", "transparency.html"), "utf8");
const pageJs = html.match(/<script>([\s\S]*)<\/script>/)[1];
(0, eval)(pageJs);  // installs globalThis.KC; refresh() is gated on window/document
const KC = globalThis.KC;

let failures = 0;
function check(cond, msg) {
  if (cond) console.log("  ok   " + msg);
  else { failures++; console.log("  FAIL " + msg); }
}
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function waitEval() {
  const ev = await KC.evaluateLog();
  if (ev.error) throw new Error("evaluation failed: " + ev.error);
  return ev;
}
// full page refresh: exactly what the onload handler does in a real browser -
// populates the shared EVAL and renders every panel
async function pageRefresh() {
  await KC.refresh();
  // refresh() evaluates asynchronously after rendering the cheap panels;
  // wait for its evaluation to land in the shared EVAL the UI reads.
  for (let i = 0; i < 200 && !KC.getEval(); i++) await sleep(10);
  if (!KC.getEval()) throw new Error("page refresh did not produce an EVAL");
  return KC.getEval();
}
async function login(pid) {
  await post("/api/session/login-challenge", {device_id: "dev_" + pid});
  const r = await post("/api/session/login", {device_id: "dev_" + pid});
  if (r.status !== 200) throw new Error("login failed " + pid + ": " + r.text);
  return r.json.token;
}
// flip one character in the MIDDLE of a base64 signature (never the padding
// tail, where some bits are unused and a change may leave the signature valid)
function corruptB64(s) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const idx = Math.max(2, Math.floor(s.length / 2));
  let ch = alphabet[(alphabet.indexOf(s[idx]) + 7) % alphabet.length];
  return s.slice(0, idx) + ch + s.slice(idx + 1);
}

async function main() {
  for (let i = 0; i < 60; i++) {
    try { await get("/health"); break; } catch (e) { await sleep(100); }
  }

  // ================= 1. latest trusted, member paths rebuild =================
  let ev = await pageRefresh();
  const N = ev.status.tree_size;
  check(N >= 5, "seeded a mixed-purpose, multi-version tree (size=" + N + ")");
  check(ev.ok, "full shared evaluation is trusted");
  check(ev.current && ev.current.trusted,
    "freshly signed latest head renders the TRUSTED badge");
  check(ev.current.checks.sig && ev.current.checks.root &&
        ev.current.checks.prevLink && ev.current.checks.headHash,
    "trusted = valid signature + recomputed root + head-hash link");
  check(elements.headview.innerHTML.includes("可信"),
    "current head panel shows the Chinese trusted badge");

  // member inclusion path for EVERY purpose, rebuilt in the browser and bound
  // to the verified chain head
  const purposes = Object.keys(ev.status.latest_by_purpose);
  let allMembers = true;
  for (const purpose of purposes) {
    const ver = ev.status.latest_by_purpose[purpose].version;
    const inc = (await get(`/api/transparency/inclusion?purpose=` +
      encodeURIComponent(purpose) + `&version=${ver}`)).json;
    const lh = await KC.leafHash(inc.leaf);
    const pathOk = await KC.verifyInclusion(inc.leaf_index, inc.tree_size,
      inc.inclusion_path, lh, KC.unhex(inc.head.root_hash));
    const rec = ev.heads.get(inc.tree_size);
    if (!pathOk || !rec || !KC.sameHead(inc.head, rec.head)) allMembers = false;
  }
  check(allMembers, "member path rebuilds in-browser for all " +
    purposes.length + " purposes and anchors to the same verified head");

  // inclusion UI happy path (purpose+version are both required by the API)
  elements["inc-purpose"].value = "root-signing";
  elements["inc-version"].value =
    String(ev.status.latest_by_purpose["root-signing"].version);
  elements["inc-vid"].value = "";
  await KC.checkInclusion();
  check(elements.incresult.innerHTML.includes("可信") &&
        !elements.incresult.innerHTML.includes("不可信"),
    "inclusion UI reports the member path trusted");

  // ================= 2. switching + reload reproducibility ==================
  const snapshot = ev => JSON.stringify([...ev.heads.entries()]
    .map(([sz, r]) => [sz, r.trusted, r.head.root_hash, r.head.tree_head_sig]));
  const snap0 = snapshot(ev);
  let histAll = true;
  for (let sz = 1; sz <= N; sz++) {
    await KC.checkHistoryHead(sz);
    if (!elements.histresult.innerHTML.includes("可信")) histAll = false;
    const r = ev.heads.get(sz);
    if (!r.trusted) histAll = false;
  }
  check(histAll, "every historical summary 1.." + N +
    " shows the same trusted verdict as the current view");
  ev = await pageRefresh();
  check(ev.current.trusted, "browsing back to the latest head stays trusted");
  const evReload = await pageRefresh();
  check(snapshot(evReload) === snap0 && evReload.ok,
    "a fresh reload reproduces identical verdicts (deterministic)");
  ev = evReload;

  // ================= 3. tampered content / attestation ======================
  const cur = ev.current.head;
  const tContent = JSON.parse(JSON.stringify(cur));
  tContent.root_hash = "a".repeat(64);   // summary content replaced
  check(!(await KC.verifyHeadSig(ev.pubBytes, tContent)),
    "content-replaced summary: signature fails");
  check(tContent.root_hash !== KC.hex(ev.prefixRoots[N]),
    "content-replaced summary: root cannot match the browser prefix root");

  const tSig = JSON.parse(JSON.stringify(cur));
  tSig.tree_head_sig = corruptB64(tSig.tree_head_sig); // attestation only
  check(!(await KC.verifyHeadSig(ev.pubBytes, tSig)),
    "attestation-field-only tamper: signature fails");

  const tIssued = JSON.parse(JSON.stringify(cur));
  tIssued.issued_at = "2026-01-01T00:00:00Z";
  check(!(await KC.verifyHeadSig(ev.pubBytes, tIssued)),
    "signed-field (issued_at) rewrite detected");

  check(KC.wellFormedHead(cur) &&
        KC.wellFormedHead(JSON.parse(JSON.stringify(cur))),
    "well-formed genuine head passes structural validation");
  const malformed = JSON.parse(JSON.stringify(cur));
  delete malformed.tree_head_sig;
  check(!KC.wellFormedHead(malformed),
    "head missing the attestation field is structurally rejected");

  // "reload": same tampered inputs re-fed after a fresh evaluation stay bad
  const evAgain = await pageRefresh();
  check(evAgain.ok && evAgain.current.trusted,
    "live server state (untampered) trusted again after probes");
  check(!(await KC.verifyHeadSig(evAgain.pubBytes, tContent)) &&
        !(await KC.verifyHeadSig(evAgain.pubBytes, tSig)),
    "tampered inputs remain untrusted after reload (reproducible)");

  // ================= 4. extension vs truncation/reorder/splice ==============
  const OLD = 2;
  const oldHead = ev.heads.get(OLD).head;
  const cc = (await get(`/api/transparency/consistency?old_size=${OLD}`)).json;
  check(await KC.verifyConsistency(OLD, cc.tree_size, cc.consistency_path,
      KC.unhex(oldHead.root_hash), KC.unhex(cc.head.root_hash)),
    `genuine extension ${OLD} -> ${cc.tree_size} verifies`);

  // 4a truncation (drop tail)
  check(!(await KC.verifyConsistency(OLD, N, cc.consistency_path,
      KC.unhex(oldHead.root_hash), KC.unhex(KC.hex(ev.prefixRoots[N - 1])))),
    "truncated new root (tail removed) fails");

  // 4b proof reorder
  if (cc.consistency_path.length >= 2) {
    const swapped = [cc.consistency_path[1], cc.consistency_path[0]]
      .concat(cc.consistency_path.slice(2));
    check(!(await KC.verifyConsistency(OLD, cc.tree_size, swapped,
        KC.unhex(oldHead.root_hash), KC.unhex(cc.head.root_hash))),
      "reordered consistency proof fails");
  } else {
    check(true, "(short proof; reorder case n/a)");
  }

  // 4c early-entry rewrite: anchor root altered -> old-region mismatch
  const early = KC.unhex(oldHead.root_hash); early[0] ^= 1;
  check(!(await KC.verifyConsistency(OLD, cc.tree_size, cc.consistency_path,
      early, KC.unhex(cc.head.root_hash))),
    "early-entry rewrite (pinned anchor mismatch) fails");

  // 4d foreign-tree splice: same size, signed head from a different root
  const foreignOld = JSON.parse(JSON.stringify(oldHead));
  foreignOld.root_hash = "c".repeat(64);
  check(!(await KC.verifyConsistency(OLD, cc.tree_size, cc.consistency_path,
      KC.unhex(foreignOld.root_hash), KC.unhex(cc.head.root_hash))),
    "cross-tree spliced anchor fails the proof");
  check(!KC.sameHead(foreignOld, ev.heads.get(OLD).head),
    "foreign anchor is not this log's stored head at that height");

  // UI: genuine pasted old head accepted
  elements["cons-oldsize"].value = "";
  elements["cons-oldroot"].value = "";
  elements["cons-oldhead"].value = JSON.stringify(oldHead);
  await KC.checkConsistency();
  check(elements.consresult.innerHTML.includes("合法延长确认") &&
        !elements.consresult.innerHTML.includes("拒绝"),
    "consistency UI accepts the real extension");
  // UI: spliced anchor rejected
  elements["cons-oldhead"].value = JSON.stringify(foreignOld);
  await KC.checkConsistency();
  check(elements.consresult.innerHTML.includes("拒绝") ||
        elements.consresult.innerHTML.includes("不可信") ||
        elements.consresult.innerHTML.includes("不一致"),
    "consistency UI rejects the cross-tree anchor");
  // UI: pinned genuine head (localStorage path) accepted
  elements["cons-oldhead"].value = "";
  globalThis.localStorage.setItem("kc-transparency-pinned-head-v1",
    JSON.stringify(oldHead));
  elements["cons-oldsize"].value = String(OLD);
  elements["cons-oldroot"].value = "";
  await KC.checkConsistency();
  check(elements.consresult.innerHTML.includes("合法延长确认"),
    "consistency UI accepts a genuinely pinned historical head");

  // ================= 5. forged attestation + same-height fork ===============
  const tok = {};
  for (const pid of ["alice", "bruno", "carla", "diego"])
    tok[pid] = await login(pid);
  const preFreezeSize = (await get("/api/transparency/status")).json.tree_size;

  async function expectFrozen(kind, label) {
    const st = (await get("/api/transparency/status")).json;
    check(!!st.frozen &&
      st.splits.some(sp => sp.kind === kind && sp.status === "OPEN"),
      label + ": conflict saved as OPEN split-view evidence (" + kind + ")");
    const evFr = await pageRefresh();
    check(evFr.ok && evFr.current.trusted,
      label + ": old summaries remain verifiably trusted while frozen");
    const blocked = await post("/test-helper/grow", {});
    check(blocked.status === 409 && blocked.json.error === "TRANSPARENCY_FROZEN",
      label + ": new publication paused with TRANSPARENCY_FROZEN");
    return st;
  }
  async function assertResolveGuards(st) {
    elements.token.value = tok.alice;
    elements["resolve-split"].value = st.frozen.split_id;
    elements["resolve-reason"].value = "";
    await KC.resolveSplit();
    check(elements["resolve-result"].innerHTML.includes("原因必填"),
      "resolution without a reason is refused in the UI");
    elements.token.value = tok.diego;
    elements["resolve-reason"].value = "attempt without owner rights";
    await KC.resolveSplit();
    const rr = elements["resolve-result"].innerHTML +
               elements["resolve-result"].textContent;
    check(rr.includes("FORBIDDEN") || rr.includes("403") || rr.includes("权限"),
      "non-owner resolution is refused by the server");
  }
  async function recoverFrom(st, reason) {
    elements.token.value = tok.alice;
    elements["resolve-split"].value = st.frozen.split_id;
    elements["resolve-reason"].value = reason;
    await KC.resolveSplit();
    check(elements["resolve-result"].innerHTML.includes("已选择本地可验证分支"),
      "owner recovers with a reason from the provable branch");
    const stRes = (await get("/api/transparency/status")).json;
    check(stRes.frozen === null &&
      stRes.splits.some(sp => sp.split_id === st.frozen.split_id &&
        sp.status === "RESOLVED" && sp.resolution && sp.resolution.reason),
      "split resolved with recorded reason; rejected head retained");
  }

  // 5a forged attestation: structurally a head but a bogus signature. Per the
  // acceptance criteria this saves a conflict AND pauses publication.
  const forged = JSON.parse(JSON.stringify(cur));
  forged.tree_head_sig = "A".repeat(88);
  elements.observer.value = "browser-driver";
  elements.obshead.value = JSON.stringify(forged);
  await KC.submitObserved();
  const forgedHtml = elements.obsresult.innerHTML +
                     elements.obsresult.textContent;
  check(forgedHtml.includes("伪造") || forgedHtml.includes("BAD_HEAD") ||
        forgedHtml.includes("无效"),
    "forged attestation is flagged as untrusted (server answers BAD_HEAD)");
  const stForged = await expectFrozen("INVALID_HEAD_SIGNATURE",
    "forged attestation");
  await assertResolveGuards(stForged);
  await recoverFrom(stForged,
    "forged attestation rejected as evidence; local log verified in-browser " +
    "and out of band");
  let grown = await post("/test-helper/grow", {});
  check(grown.status === 200,
    "publication resumes after forged-attestation recovery");

  // 5b same-height different-root head, genuinely signed (equivocation)
  const fork = (await get("/test-helper/fork-head")).json;
  check(await KC.verifyHeadSig(ev.pubBytes, fork),
    "fixture fork carries a VALID log signature (real equivocation case)");
  elements.obshead.value = JSON.stringify(fork);
  await KC.submitObserved();
  check(elements.obsresult.innerHTML.includes("冻结"),
    "same-height divergent head freezes publication");
  const stFrozen = await expectFrozen("SAME_SIZE_DIFFERENT_ROOT",
    "same-height fork");
  await assertResolveGuards(stFrozen);

  // ================= 6. recover from the provable branch ====================
  await recoverFrom(stFrozen,
    "browser recomputation confirmed the local branch; divergent head kept " +
    "as rejected evidence");

  // publishing resumes and extends the chain past the pre-freeze anchor
  grown = await post("/test-helper/grow", {});
  check(grown.status === 200 && grown.json.tree_size > preFreezeSize,
    "publication resumes after fork recovery (" + preFreezeSize + " -> " +
    grown.json.tree_size + ")");

  // reopen: recovered branch still trusted and strictly extends pre-freeze
  const evFinal = await pageRefresh();
  check(evFinal.ok && evFinal.current.trusted,
    "reopened page still shows the recovered branch as trusted");
  const ccFinal = (await get(
    `/api/transparency/consistency?old_size=${preFreezeSize}`)).json;
  check(await KC.verifyConsistency(preFreezeSize, ccFinal.tree_size,
      ccFinal.consistency_path,
      KC.unhex(ev.heads.get(preFreezeSize).head.root_hash),
      KC.unhex(ccFinal.head.root_hash)),
    "post-recovery heads strictly extend the pre-freeze trusted anchor");

  console.log(failures === 0
    ? "\nTRANSPARENCY BROWSER E2E PASSED"
    : `\n${failures} CHECK(S) FAILED`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch(e => { console.error(e); process.exit(2); });
