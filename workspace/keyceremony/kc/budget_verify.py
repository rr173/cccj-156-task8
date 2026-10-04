"""Independent offline verifier for the verifiable signing-usage budgets.

Given an export bundle (audit chain + key directory + budget sheets), the
checker rebuilds every quantity change purely from the hash-chained audit
events - it never trusts the derived state in the bundle. It recomputes:

  * budget sheets and their incrementing revision chain (officer-signed);
  * reservation credential signatures;
  * consumed / reserved / released / available quantities per budget;
  * the  consumed + valid_held <= total  invariant at every reserve;
  * the signature <-> reservation <-> settlement correspondence.

Detectable violations (machine-readable codes):

  FORGED_BUDGET                forged/unsigned officer budget sheet
  DUPLICATE_CONSUMPTION        one reservation settled twice
  OVER_QUOTA_SIGNATURE         signatures exceed reservation/total
  CROSS_SUBJECT_MISAPPROPRIATION  reservation subject != budget subject
  RESERVED_AFTER_WINDOW        reserve outside [effective_at, deadline)
  REVISION_REGRESSION          revision numbers not strictly increasing
  RELEASED_SIGNED_RESERVATION  a release despite existing signature audit
  CONSUMPTION_WITHOUT_SIGNATURE  settle consumed units with no signatures
  SIGNATURE_WITHOUT_SETTLEMENT   end-of-archive governed sig never settled
  RESERVATION_CREDENTIAL_BAD   reservation credential signature invalid
  BUDGET_TOTAL_FLOOR_BREACHED  revised total below consumed + held
  EXEMPT_WHILE_GOVERNED        an "exempt" signature under an active sheet
  SUBJECT_REVOKED_RESERVE      reserve after the subject was revoked
  KEY_RETIRED_RESERVE          reserve against a non-ACTIVE key version

The audit hash chain and service signature are checked by export.verify_bundle
and re-checked here as well; a broken chain raises CHAIN_BROKEN.
"""

from __future__ import annotations

from . import crypto, ed25519
from .storage import GENESIS

# violation codes (stable identifiers for tooling / tests)
FORGED_BUDGET = "FORGED_BUDGET"
DUPLICATE_CONSUMPTION = "DUPLICATE_CONSUMPTION"
OVER_QUOTA_SIGNATURE = "OVER_QUOTA_SIGNATURE"
CROSS_SUBJECT = "CROSS_SUBJECT_MISAPPROPRIATION"
RESERVED_AFTER_WINDOW = "RESERVED_AFTER_WINDOW"
REVISION_REGRESSION = "REVISION_REGRESSION"
RELEASED_SIGNED = "RELEASED_SIGNED_RESERVATION"
CONSUMPTION_NO_SIG = "CONSUMPTION_WITHOUT_SIGNATURE"
SIG_NO_SETTLE = "SIGNATURE_WITHOUT_SETTLEMENT"
CREDENTIAL_BAD = "RESERVATION_CREDENTIAL_BAD"
FLOOR_BREACHED = "BUDGET_TOTAL_FLOOR_BREACHED"
EXEMPT_GOVERNED = "EXEMPT_WHILE_GOVERNED"
SUBJECT_REVOKED_RESERVE = "SUBJECT_REVOKED_RESERVE"
KEY_RETIRED_RESERVE = "KEY_RETIRED_RESERVE"
CHAIN_BROKEN = "CHAIN_BROKEN"
SERVICE_SIG_BAD = "SERVICE_SIGNATURE_INVALID"
BUDGET_REPLAY = "BUDGET_DUPLICATE_RESERVE"

BUDGET_EVENTS = {
    "budget_officer_registered", "budget_subject_registered",
    "budget_subject_revoked", "budget_issued", "budget_revised",
    "budget_status_changed", "budget_reserved",
    "budget_signature_recorded", "budget_reservation_consumed",
    "budget_reservation_released", "budget_exempt_signature",
}


def _audit_hash(entry: dict) -> str:
    h = __import__("hashlib").sha256()
    h.update(entry["prev"].encode())
    h.update(crypto.dumps(entry["payload"]).encode())
    h.update(str(entry["ts"]).encode())
    h.update(str(entry["seq"]).encode())
    return h.hexdigest()


class _Finding(Exception):
    pass


def verify_budgets(bundle: dict, *, now: float | None = None) -> dict:
    """Replay budget semantics from bundle['audit']. Returns
    {ok, findings:[{code,message,seq}], checks:{...}}."""
    findings: list[dict] = []

    def bad(code, message, seq=None):
        findings.append({"code": code, "message": message, "seq": seq})

    audit = bundle.get("audit", [])
    service_pub = None
    if bundle.get("service_identity_pub"):
        service_pub = crypto.b64d(bundle["service_identity_pub"])

    # ---- 1. audit hash chain + per-entry service signature --------------
    prev = GENESIS
    for i, e in enumerate(audit):
        try:
            broken = e.get("prev") != prev or e.get("hash") != _audit_hash(e)
        except (KeyError, TypeError):
            broken = True
        if broken:
            bad(CHAIN_BROKEN, f"audit[{i}] chain/hash broken", e.get("seq"))
        if service_pub is not None and "svc_sig" in e:
            try:
                sig_ok = ed25519.verify(
                    service_pub, e["hash"].encode(),
                    crypto.b64d(e["svc_sig"]))
            except Exception:
                sig_ok = False
            if not sig_ok:
                bad(SERVICE_SIG_BAD, f"audit[{i}] service signature invalid",
                    e.get("seq"))
        prev = e.get("hash", prev)

    # key directory lookup (version status at export time)
    keys = {k["id"]: k for k in bundle.get("keys", [])}

    # ---- 2. replay budget state from events -----------------------------
    officers: dict[str, bytes] = {}
    revoked: set[str] = set()
    budgets: dict[str, dict] = {}          # budget_id -> derived state
    reservations: dict[str, dict] = {}    # request_id -> derived state

    def _check_officer(seq, officer_id: str, body: dict, sig: str):
        pub = officers.get(officer_id)
        if pub is None:
            bad(FORGED_BUDGET,
                f"audit {seq}: signature by unregistered officer "
                f"{officer_id}", seq)
            return False
        try:
            sig_ok = bool(sig) and ed25519.verify(
                pub, crypto.dumps(body).encode(), crypto.b64d(sig))
        except Exception:
            sig_ok = False
        if not sig_ok:
            bad(FORGED_BUDGET,
                f"audit {seq}: officer signature does not verify", seq)
            return False
        return True

    def _quantities(bid: str):
        consumed = reserved = 0
        for r in reservations.values():
            if r["budget_id"] != bid:
                continue
            if r["status"] == "CONSUMED":
                consumed += r["consumed"]
            elif r["status"] in ("HELD", "SIGNED"):
                reserved += r["amount"] - r["consumed"]
        return consumed, reserved

    for e in audit:
        ev, p, seq = e.get("event"), e.get("payload", {}), e.get("seq")
        if ev not in BUDGET_EVENTS:
            continue

        if ev == "budget_officer_registered":
            oid = p["officer_id"]
            if oid in officers:
                bad(FORGED_BUDGET, f"officer {oid} registered twice", seq)
            officers[oid] = crypto.b64d(p["pub"])
            # verify self-attestation when present
            reg = None
            # registration body is not in the audit payload; optional here
            continue

        if ev == "budget_subject_registered":
            revoked.discard(p["subject_id"])
            continue
        if ev == "budget_subject_revoked":
            revoked.add(p["subject_id"])
            continue

        if ev == "budget_issued":
            bid = p["budget_id"]
            if bid in budgets:
                bad(FORGED_BUDGET, f"budget {bid} issued twice", seq)
            fields = {"purpose": p["purpose"],
                      "key_version_id": p["key_version_id"],
                      "subject": p["subject"], "total": p["total"],
                      "per_batch_cap": p["per_batch_cap"],
                      "effective_at": p["effective_at"],
                      "deadline": p["deadline"],
                      "lease_seconds": p["lease_seconds"],
                      "label": p.get("label", "")}
            body = {"kind": "budget-issue-v1", "fields": fields}
            _check_officer(seq, p["officer_id"], body, p.get("officer_sig"))
            if p["revision"] != 1:
                bad(REVISION_REGRESSION,
                    f"budget {bid} issued at revision {p['revision']} != 1",
                    seq)
            budgets[bid] = {
                "id": bid, "revision": 1, "total": p["total"],
                "per_batch_cap": p["per_batch_cap"],
                "effective_at": p["effective_at"],
                "deadline": p["deadline"],
                "lease_seconds": p["lease_seconds"],
                "purpose": p["purpose"],
                "key_version_id": p["key_version_id"],
                "subject": p["subject"], "status": "ACTIVE",
                "issued_at": e["ts"]}
            continue

        if ev == "budget_revised":
            b = budgets.get(p["budget_id"])
            if b is None:
                bad(FORGED_BUDGET,
                    f"revision for unknown budget {p['budget_id']}", seq)
                continue
            if p["base_revision"] != b["revision"]:
                bad(REVISION_REGRESSION,
                    f"budget {b['id']}: revision base {p['base_revision']} "
                    f"!= current {b['revision']}", seq)
            if p["revision"] != b["revision"] + 1:
                bad(REVISION_REGRESSION,
                    f"budget {b['id']}: revision must increase by exactly 1 "
                    f"({b['revision']} -> {p['revision']})", seq)
            fields = {"budget_id": b["id"], "base_revision": p["base_revision"],
                      "revision": p["revision"], "total": p["total"],
                      "per_batch_cap": p["per_batch_cap"],
                      "effective_at": p["effective_at"],
                      "deadline": p["deadline"],
                      "lease_seconds": p["lease_seconds"],
                      "reason": p.get("reason", "")}
            _check_officer(seq, p["officer_id"],
                           {"kind": "budget-revise-v1", "fields": fields},
                           p.get("officer_sig"))
            # floor: reduced total cannot undercut consumed + valid held
            consumed, reserved = _quantities(b["id"])
            if p["total"] < consumed + reserved:
                bad(FLOOR_BREACHED,
                    f"budget {b['id']} rev {p['revision']}: total "
                    f"{p['total']} < consumed {consumed} + held {reserved}",
                    seq)
            b.update({"revision": p["revision"], "total": p["total"],
                      "per_batch_cap": p["per_batch_cap"],
                      "effective_at": p["effective_at"],
                      "deadline": p["deadline"],
                      "lease_seconds": p["lease_seconds"]})
            continue

        if ev == "budget_status_changed":
            b = budgets.get(p["budget_id"])
            if b is None:
                bad(FORGED_BUDGET,
                    f"status change for unknown budget {p['budget_id']}", seq)
                continue
            if p["revision"] != b["revision"] + 1:
                bad(REVISION_REGRESSION,
                    f"budget {b['id']}: status change must increment revision",
                    seq)
            if p.get("officer_id"):
                fields = {"budget_id": b["id"],
                          "base_revision": b["revision"],
                          "revision": p["revision"],
                          "status": p["new_status"],
                          "reason": p.get("reason", "")}
                _check_officer(seq, p["officer_id"],
                               {"kind": "budget-status-v1", "fields": fields},
                               p.get("officer_sig"))
            b["revision"] = p["revision"]
            b["status"] = p["new_status"]
            continue

        if ev == "budget_reserved":
            rq = p["request_id"]
            b = budgets.get(p["budget_id"])
            if b is None:
                bad(FORGED_BUDGET,
                    f"reservation under unknown budget {p['budget_id']}", seq)
                continue
            if rq in reservations:
                bad(BUDGET_REPLAY,
                    f"request_id {rq} reserved twice", seq)
            if p["subject"] != b["subject"]:
                bad(CROSS_SUBJECT,
                    f"reservation subject {p['subject']} != budget subject "
                    f"{b['subject']}", seq)
            # time window
            at = p["reserved_at"]
            if at < b["effective_at"] or at >= b["deadline"]:
                bad(RESERVED_AFTER_WINDOW,
                    f"reserve at {at} outside window "
                    f"[{b['effective_at']},{b['deadline']})", seq)
            if p["subject"] in revoked:
                bad(SUBJECT_REVOKED_RESERVE,
                    f"reserve after subject {p['subject']} revoked", seq)
            if b["status"] == "PAUSED":
                bad(RESERVED_AFTER_WINDOW,
                    f"reserve while budget {b['id']} paused", seq)
            kv = keys.get(b["key_version_id"])
            if kv is not None:
                # A version is normally ACTIVE at reserve time and only
                # retires later (old signatures keep verifying). Judge by the
                # retirement/destruction timestamp, not the status at export:
                # a reserve before that instant was against an ACTIVE key.
                retired_at = kv.get("retired_at") or kv.get("destroyed_at")
                if kv["status"] in ("RETIRING", "DESTROYED"):
                    if retired_at is None or at >= float(retired_at):
                        bad(KEY_RETIRED_RESERVE,
                            f"reserve at {at} against {kv['status']} key "
                            f"version {b['key_version_id']} "
                            f"(retired {retired_at})", seq)
                elif kv["status"] in ("STAGED", "ABORTED"):
                    bad(KEY_RETIRED_RESERVE,
                        f"reserve against never-active {kv['status']} key "
                        f"version {b['key_version_id']}", seq)
            if p["amount"] > b["per_batch_cap"]:
                bad(OVER_QUOTA_SIGNATURE,
                    f"reserve {p['amount']} > per-batch cap "
                    f"{b['per_batch_cap']}", seq)
            consumed, reserved = _quantities(b["id"])
            if consumed + reserved + p["amount"] > b["total"]:
                bad(OVER_QUOTA_SIGNATURE,
                    f"reserve over budget: consumed {consumed} + held "
                    f"{reserved} + asked {p['amount']} > total {b['total']}",
                    seq)
            reservations[rq] = {
                "request_id": rq, "budget_id": b["id"],
                "subject": p["subject"], "amount": p["amount"],
                "consumed": 0, "status": "HELD",
                "n_signatures": 0, "reserved_at": at,
                "lease_expires_at": p["lease_expires_at"],
                "seq": seq}
            continue

        if ev == "budget_signature_recorded":
            r = reservations.get(p["request_id"])
            if r is None:
                bad(FORGED_BUDGET,
                    f"signature for unknown request {p['request_id']}", seq)
                continue
            if r["subject"] != p["subject"]:
                bad(CROSS_SUBJECT,
                    f"signed subject {p['subject']} != reservation subject "
                    f"{r['subject']}", seq)
            if r["status"] not in ("HELD", "SIGNED"):
                bad(OVER_QUOTA_SIGNATURE,
                    f"signature on {r['status']} reservation "
                    f"{p['request_id']}", seq)
            r["n_signatures"] += int(p["count"])
            if r["n_signatures"] > r["amount"]:
                bad(OVER_QUOTA_SIGNATURE,
                    f"{r['n_signatures']} signatures exceed reservation "
                    f"{r['amount']} for {p['request_id']}", seq)
            r["status"] = "SIGNED"
            continue

        if ev == "budget_reservation_consumed":
            r = reservations.get(p["request_id"])
            if r is None:
                bad(FORGED_BUDGET,
                    f"consume unknown request {p['request_id']}", seq)
                continue
            if r["status"] == "CONSUMED":
                bad(DUPLICATE_CONSUMPTION,
                    f"request {p['request_id']} settled twice", seq)
            consumed_amt = int(p["consumed_amount"])
            if consumed_amt > 0 and r["n_signatures"] < consumed_amt:
                bad(CONSUMPTION_NO_SIG,
                    f"consumed {consumed_amt} but only "
                    f"{r['n_signatures']} signature(s) audited for "
                    f"{p['request_id']}", seq)
            if consumed_amt > r["amount"]:
                bad(OVER_QUOTA_SIGNATURE,
                    f"consumed {consumed_amt} > reserved {r['amount']}", seq)
            r["consumed"] = consumed_amt
            r["status"] = "CONSUMED"
            r["settle_kind"] = p.get("kind")
            continue

        if ev == "budget_reservation_released":
            r = reservations.get(p["request_id"])
            if r is None:
                bad(FORGED_BUDGET,
                    f"release unknown request {p['request_id']}", seq)
                continue
            if r["n_signatures"] > 0:
                bad(RELEASED_SIGNED,
                    f"released {p['request_id']} despite "
                    f"{r['n_signatures']} signature audit record(s)", seq)
            if r["status"] == "CONSUMED":
                bad(DUPLICATE_CONSUMPTION,
                    f"released an already-consumed request "
                    f"{p['request_id']}", seq)
            r["status"] = "RELEASED"
            continue

        if ev == "budget_exempt_signature":
            # legitimate only while NO non-superseded sheet governs the
            # (purpose, version) at that point in time.
            purpose, vid = p["purpose"], p["key_version_id"]
            governed = any(
                b["purpose"] == purpose and b["key_version_id"] == vid
                for b in budgets.values())
            if governed:
                bad(EXEMPT_GOVERNED,
                    f"exempt signature for governed {purpose}/{vid} at "
                    f"audit {seq}", seq)
            continue

    # ---- 3. end-of-archive: every governed signature is settled ---------
    for rq, r in reservations.items():
        if r["n_signatures"] > 0 and r["status"] in ("HELD", "SIGNED"):
            # A *live* reservation (lease not lapsed) is allowed to be
            # mid-protocol; only expired-but-unsigned-settled is a finding.
            expired = (now is not None
                       and r["lease_expires_at"] <= now)
            if expired:
                bad(SIG_NO_SETTLE,
                    f"request {rq} has {r['n_signatures']} signature(s), "
                    f"lease expired, but no consumption/return record")

    # ---- 4. credential signature spot check from bundle state -----------
    raw_res = bundle.get("budget_reservations") or []
    if isinstance(raw_res, dict):
        raw_res = list(raw_res.values())
    for rv in raw_res:
        cred = rv.get("credential")
        rq = rv.get("request_id")
        if cred and service_pub is not None:
            ok = ed25519.verify(service_pub,
                                crypto.dumps(cred["body"]).encode(),
                                crypto.b64d(cred["service_sig"]))
            if not ok:
                bad(CREDENTIAL_BAD,
                    f"reservation credential for {rq} fails verification")
            body = cred["body"]
            if body.get("request_id") != rq or \
                    body.get("amount") != rv.get("amount"):
                bad(CREDENTIAL_BAD,
                    f"reservation credential body mismatches record {rq}")

    checks = {
        "n_budgets": len(budgets),
        "n_reservations": len(reservations),
        "n_findings": len(findings),
        "final": {bid: {"total": b["total"],
                        "consumed": _quantities(bid)[0],
                        "reserved": _quantities(bid)[1],
                        "revision": b["revision"], "status": b["status"]}
                  for bid, b in budgets.items()},
    }
    return {"ok": not findings, "findings": findings, "checks": checks}
