"""Command line for verifiable signing-usage budgets.

Examples
--------
# generate a security-officer identity (seed printed once, kept out of band)
python3 -m kc.budget_cli gen-officer

# register the officer public key and a calling subject
python3 -m kc.budget_cli register-officer --root ./kc-data \
    --officer sec --pub-file sec.pub
python3 -m kc.budget_cli register-subject --root ./kc-data \
    --subject svc-a --label "caller service A"

# issue a signed budget sheet (the officer signs with its local seed)
python3 -m kc.budget_cli issue --root ./kc-data \
    --purpose root-signing --key-version kv_xxx --subject svc-a \
    --total 1000 --per-batch 50 --lease-seconds 30 \
    --effective-at $(date +%s) --deadline $(date -d '+30 days' +%s) \
    --officer sec --seed-file sec.seed

# revise / pause / resume (concurrent edits return BUDGET_REVISION_CONFLICT)
python3 -m kc.budget_cli revise --root ./kc-data --budget bdg_xxx \
    --base-revision 2 --total 800 --per-batch 50 --officer sec \
    --seed-file sec.seed --reason "monthly reduction"
python3 -m kc.budget_cli pause  --root ./kc-data --budget bdg_xxx --reason incident
python3 -m kc.budget_cli resume --root ./kc-data --budget bdg_xxx --reason cleared

# console views
python3 -m kc.budget_cli status  --root ./kc-data
python3 -m kc.budget_cli requests --root ./kc-data [--budget bdg_xxx]

# manual handling of a long-hung reservation (refuses signed requests)
python3 -m kc.budget_cli release --root ./kc-data --request req_xxx \
    --operator alice --reason "worker lost; no signature audit"
python3 -m kc.budget_cli settle-hung --root ./kc-data --request req_xxx \
    --operator alice --reason "worker died after signing"

# verifiable archive: export and independently re-check every quantity
python3 -m kc.budget_cli verify --root ./kc-data
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import budgets as B
from . import crypto
from .ceremony import Orchestrator
from .errors import CeremonyError
from .storage import Store


def _load(root: str):
    store = Store(root)
    return store, Orchestrator(store)


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


def _ts(s) -> float:
    return time.time() if s is None else float(s)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kc.budget_cli")
    ap.add_argument("--root", default="./kc-data")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("gen-officer")

    p = sub.add_parser("register-officer")
    p.add_argument("--officer", required=True)
    p.add_argument("--pub-file", required=True)
    p.add_argument("--label", default="")

    p = sub.add_parser("register-subject")
    p.add_argument("--subject", required=True)
    p.add_argument("--label", default="")

    p = sub.add_parser("revoke-subject")
    p.add_argument("--subject", required=True)
    p.add_argument("--reason", default="")

    p = sub.add_parser("issue")
    p.add_argument("--purpose", required=True)
    p.add_argument("--key-version", required=True)
    p.add_argument("--subject", required=True)
    p.add_argument("--total", type=int, required=True)
    p.add_argument("--per-batch", type=int, required=True)
    p.add_argument("--lease-seconds", type=int, default=30)
    p.add_argument("--effective-at", type=float, default=None)
    p.add_argument("--deadline", type=float, required=True)
    p.add_argument("--officer", required=True)
    p.add_argument("--seed-file", required=True)
    p.add_argument("--label", default="")

    p = sub.add_parser("revise")
    p.add_argument("--budget", required=True)
    p.add_argument("--base-revision", type=int, required=True)
    p.add_argument("--total", type=int, required=True)
    p.add_argument("--per-batch", type=int, required=True)
    p.add_argument("--lease-seconds", type=int, default=None)
    p.add_argument("--effective-at", type=float, default=None)
    p.add_argument("--deadline", type=float, default=None)
    p.add_argument("--officer", required=True)
    p.add_argument("--seed-file", required=True)
    p.add_argument("--reason", default="")

    for name in ("pause", "resume"):
        p = sub.add_parser(name)
        p.add_argument("--budget", required=True)
        p.add_argument("--reason", default="")
        p.add_argument("--officer", default=None)
        p.add_argument("--seed-file", default=None)

    sub.add_parser("status")
    p = sub.add_parser("requests")
    p.add_argument("--budget", default=None)

    p = sub.add_parser("release")
    p.add_argument("--request", dest="request_id", required=True)
    p.add_argument("--operator", required=True)
    p.add_argument("--reason", required=True)

    p = sub.add_parser("settle-hung")
    p.add_argument("--request", dest="request_id", required=True)
    p.add_argument("--operator", required=True)
    p.add_argument("--reason", required=True)

    p = sub.add_parser("verify")
    p.add_argument("--json", action="store_true")

    a = ap.parse_args(argv)

    if a.cmd == "gen-officer":
        seed, pub = B.new_officer_keypair()
        print("# officer seed (KEEP SECRET, shown once):")
        print(crypto.b64e(seed))
        print("# officer public key:")
        print(crypto.b64e(pub))
        return 0

    store, o = _load(a.root)
    try:
        with store.locked():
            bm = o.budgets
            if a.cmd == "register-officer":
                pub_b64 = _read(a.pub_file)
                rec = bm.register_officer(a.officer, crypto.b64d(pub_b64),
                                          a.label)
                print(json.dumps({"registered": rec["officer_id"]},
                                 ensure_ascii=False))
            elif a.cmd == "register-subject":
                rec = bm.register_subject(a.subject, a.label)
                print(json.dumps({"registered": rec["subject_id"]},
                                 ensure_ascii=False))
            elif a.cmd == "revoke-subject":
                bm.revoke_subject(a.subject, a.reason, "cli")
                print(json.dumps({"revoked": a.subject}, ensure_ascii=False))
            elif a.cmd == "issue":
                seed = crypto.b64d(_read(a.seed_file))
                eff = time.time() - 1 if a.effective_at is None \
                    else a.effective_at
                fields = dict(purpose=a.purpose, key_version_id=a.key_version,
                              subject=a.subject, total=a.total,
                              per_batch_cap=a.per_batch,
                              effective_at=eff, deadline=a.deadline,
                              lease_seconds=a.lease_seconds, label=a.label)
                sig = B.sign_officer_body(
                    seed, B.officer_body("budget-issue-v1", fields))
                b = bm.create_budget(officer_id=a.officer, officer_sig=sig,
                                     **fields)
                print(json.dumps({"budget_id": b["id"],
                                  "revision": b["revision"]},
                                 ensure_ascii=False))
            elif a.cmd == "revise":
                seed = crypto.b64d(_read(a.seed_file))
                b = bm._find_budget(a.budget)
                fields = {"budget_id": b["id"],
                          "base_revision": a.base_revision,
                          "revision": a.base_revision + 1,
                          "total": a.total,
                          "per_batch_cap": a.per_batch,
                          "effective_at": b["effective_at"]
                              if a.effective_at is None else a.effective_at,
                          "deadline": b["deadline"]
                              if a.deadline is None else a.deadline,
                          "lease_seconds": b["lease_seconds"]
                              if a.lease_seconds is None else a.lease_seconds,
                          "reason": a.reason}
                sig = B.sign_officer_body(
                    seed, B.officer_body("budget-revise-v1", fields))
                nb = bm.revise_budget(
                    a.budget, base_revision=a.base_revision,
                    total=a.total, per_batch_cap=a.per_batch,
                    effective_at=None if a.effective_at is None
                    else a.effective_at,
                    deadline=None if a.deadline is None else a.deadline,
                    lease_seconds=a.lease_seconds,
                    officer_id=a.officer, officer_sig=sig,
                    reason=a.reason)
                print(json.dumps({"budget_id": nb["id"],
                                  "revision": nb["revision"],
                                  "total": nb["total"]}, ensure_ascii=False))
            elif a.cmd in ("pause", "resume"):
                sig = None
                if a.officer and a.seed_file:
                    seed = crypto.b64d(_read(a.seed_file))
                    b0 = bm._find_budget(a.budget)
                    new_status = "PAUSED" if a.cmd == "pause" else "ACTIVE"
                    body = B.officer_body("budget-status-v1", {
                        "budget_id": a.budget,
                        "base_revision": b0["revision"],
                        "revision": b0["revision"] + 1,
                        "status": new_status, "reason": a.reason})
                    sig = B.sign_officer_body(seed, body)
                fn = bm.pause_budget if a.cmd == "pause" else bm.resume_budget
                nb = fn(a.budget, a.officer or "cli", a.reason,
                        a.officer, sig)
                print(json.dumps({"budget_id": nb["id"],
                                  "status": nb["status"],
                                  "revision": nb["revision"]},
                                 ensure_ascii=False))
            elif a.cmd == "status":
                _print_status(bm)
            elif a.cmd == "requests":
                for r in bm.list_reservations(a.budget):
                    print(json.dumps({
                        "request_id": r["request_id"],
                        "budget_id": r["budget_id"],
                        "subject": r["subject"], "status": r["status"],
                        "amount": r["amount"],
                        "consumed": r["consumed_amount"],
                        "signatures": r["n_signatures"],
                        "lease_expires_at": r["lease_expires_at"],
                        "settlement": r["settlement"]}, ensure_ascii=False))
            elif a.cmd == "release":
                r = bm.manual_release(a.request_id, a.operator, a.reason)
                print(json.dumps({"request_id": r["request_id"],
                                  "status": r["status"],
                                  "manual_handling": r["manual_handling"]},
                                 ensure_ascii=False))
            elif a.cmd == "settle-hung":
                r = bm.manual_settle(a.request_id, a.operator, a.reason)
                print(json.dumps({"request_id": r["request_id"],
                                  "status": r["status"],
                                  "consumed": r["consumed_amount"]},
                                 ensure_ascii=False))
            elif a.cmd == "verify":
                from .export import build_bundle
                from .budget_verify import verify_budgets
                res = verify_budgets(build_bundle(o))
                if a.json:
                    print(json.dumps(res, indent=2, ensure_ascii=False))
                else:
                    for b in res["checks"]["final"].items():
                        print(f"budget {b[0]}: {b[1]}")
                    if res["ok"]:
                        print(f"[PASS] budgets_ok ({res['checks']['n_budgets']} "
                              f"sheets, {res['checks']['n_reservations']} "
                              f"requests)")
                    else:
                        for f in res["findings"]:
                            print(f"[FAIL] {f['code']}: {f['message']} "
                                  f"(seq {f['seq']})")
            o.save()
    except CeremonyError as e:
        err = {"error": e.code, "message": str(e)}
        for attr in ("base_revision", "current_revision",
                     "base_snapshot", "current_snapshot"):
            v = getattr(e, attr, None)
            if v is not None:
                err[attr] = v
        print(json.dumps(err, ensure_ascii=False), file=sys.stderr)
        return 2
    return 0


def _print_status(bm):
    st = bm.status()
    for b in st["budgets"]:
        print(f"budget {b['budget_id']} rev={b['revision']} "
              f"{b['status']} purpose={b['purpose']} "
              f"key={b['key_version_id'][:16]} subject={b['subject']}")
        print(f"   total={b['total']} available={b['available']} "
              f"reserved={b['reserved']} consumed={b['consumed']} "
              f"per_batch={b['per_batch_cap']} lease={b['lease_seconds']}s "
              f"window=[{b['effective_at']:.0f},{b['deadline']:.0f})")
    print(f"subjects: {', '.join(st['subjects']) or '-'}")
    print(f"officers: {', '.join(st['officers']) or '-'}")


if __name__ == "__main__":
    raise SystemExit(main())
