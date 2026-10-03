"""Command line for signing-quota budgets and offline archive verification.

Examples:
  python -m kc.budget_cli subject --root ./kc-data --id svc-billing --name "Billing"
  python -m kc.budget_cli create  --root ./kc-data --purpose billing-certs \\
      --key kv_xxx --subject svc-billing --total 1000 --batch-cap 25 \\
      --valid-until 2026-12-31T00:00:00Z --lease-seconds 30 --actor alice
  python -m kc.budget_cli status  --root ./kc-data
  python -m kc.budget_cli revise  --root ./kc-data --budget bg_xxx \\
      --base-revision 1 --total 800 --actor alice
  python -m kc.budget_cli pause   --root ./kc-data --budget bg_xxx --actor alice
  python -m kc.budget_cli resume  --root ./kc-data --budget bg_xxx --actor alice
  python -m kc.budget_cli takeover --root ./kc-data --request req-1
  python -m kc.budget_cli release  --root ./kc-data --request req-1 \\
      --operator alice --reason "worker host decommissioned"
  python -m kc.budget_cli verify  --root ./kc-data
  python -m kc.budget_cli verify-bundle export.json
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys

from .ceremony import Orchestrator
from .budget_verify import verify_budget_audit
from .storage import Store


def _parse_when(s: str | None) -> float | None:
    if s is None:
        return None
    s = s.strip()
    try:
        return float(s)  # epoch seconds (integer or fractional)
    except ValueError:
        pass
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(s).timestamp()


def _open(root: str):
    store = Store(root)
    lock_cm = store.locked()
    lock_cm.__enter__()
    orch = Orchestrator(store)
    return store, orch, lock_cm


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kc.budget_cli")
    ap.add_argument("cmd", choices=(
        "subject", "revoke-subject", "create", "revise", "pause", "resume",
        "status", "requests", "takeover", "sweep", "release",
        "verify", "verify-bundle"))
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--id", "--subject", dest="subject")
    ap.add_argument("--name", default="")
    ap.add_argument("--purpose")
    ap.add_argument("--key", dest="key_version_id")
    ap.add_argument("--total", type=int)
    ap.add_argument("--batch-cap", type=int)
    ap.add_argument("--lease-seconds", type=int)
    ap.add_argument("--valid-from")
    ap.add_argument("--valid-until")
    ap.add_argument("--actor", "--operator", dest="actor", default="cli-admin")
    ap.add_argument("--reason", default="")
    ap.add_argument("--budget")
    ap.add_argument("--base-revision", type=int)
    ap.add_argument("--request", dest="request_id")
    ap.add_argument("--bundle")
    a = ap.parse_args(argv)

    if a.cmd == "verify-bundle":
        path = a.bundle or (argv[-1] if argv and argv[-1].endswith(".json")
                            else None)
        with open(path or "export.json", encoding="utf-8") as f:
            bundle = json.load(f)
        leads = frozenset(
            pid for pid, pr in bundle.get("participants", {}).items()
            if pr.get("role") == "ROOT_OWNER")
        v = verify_budget_audit(bundle["audit"], security_leads=leads)
        _print_verdict(v)
        return 0 if v["ok"] else 1

    store, orch, lock_cm = _open(a.root)
    try:
        bm = orch.budgets
        if a.cmd == "subject":
            print(json.dumps(bm.register_subject(a.subject, a.name, a.actor),
                             indent=2, sort_keys=True))
        elif a.cmd == "revoke-subject":
            print(json.dumps(bm.revoke_subject(a.subject, a.actor, a.reason),
                             indent=2, sort_keys=True))
        elif a.cmd == "create":
            b = bm.create_budget(
                purpose=a.purpose, key_version_id=a.key_version_id,
                subject=a.subject, total=a.total,
                batch_cap=a.batch_cap or 1,
                valid_from=_parse_when(a.valid_from),
                valid_until=_parse_when(a.valid_until),
                actor=a.actor, reason=a.reason,
                lease_seconds=a.lease_seconds or 30)
            print(json.dumps(b, indent=2, sort_keys=True))
        elif a.cmd == "revise":
            b = bm.revise_budget(
                a.budget, base_revision=a.base_revision, actor=a.actor,
                total=a.total, batch_cap=a.batch_cap,
                valid_from=_parse_when(a.valid_from),
                valid_until=_parse_when(a.valid_until),
                lease_seconds=a.lease_seconds, reason=a.reason)
            print(json.dumps(b, indent=2, sort_keys=True))
        elif a.cmd == "pause":
            print(json.dumps(bm.pause(a.budget, a.actor, a.reason),
                             indent=2, sort_keys=True))
        elif a.cmd == "resume":
            print(json.dumps(bm.resume(a.budget, a.actor, a.reason),
                             indent=2, sort_keys=True))
        elif a.cmd == "status":
            print(json.dumps({"subjects": orch.state["sign_subjects"],
                              "budgets": bm.list_budgets()},
                             indent=2, sort_keys=True))
        elif a.cmd == "requests":
            print(json.dumps({"requests": bm.list_requests()},
                             indent=2, sort_keys=True))
        elif a.cmd == "takeover":
            print(json.dumps(bm.take_over(request_id=a.request_id,
                                          actor=a.actor),
                             indent=2, sort_keys=True))
        elif a.cmd == "sweep":
            print(json.dumps({"verdicts": bm.sweep_expired(actor=a.actor)},
                             indent=2, sort_keys=True))
        elif a.cmd == "release":
            print(json.dumps(bm.manual_release(
                request_id=a.request_id, operator=a.actor, reason=a.reason),
                indent=2, sort_keys=True))
        elif a.cmd == "verify":
            v = verify_budget_audit(orch.audit.entries)
            _print_verdict(v)
            return 0 if v["ok"] else 1
        orch.save()
        return 0
    finally:
        lock_cm.__exit__(None, None, None)


def _print_verdict(v: dict):
    if v["ok"]:
        print("[PASS] sign_budgets_ok")
    else:
        print("[FAIL] sign_budgets_ok")
    for f in v["findings"]:
        print(f"  - {f['code']} seq={f['seq']}: {f['message']}")
    for bid, c in v["budgets"].items():
        print(f"  budget {bid}: total={c['total']} consumed={c['consumed']} "
              f"held={c['held']} released={c['released']} "
              f"available={c['available']} rev={c['revision']} "
              f"status={c['status']}")
    print(f"  reservations replayed: {len(v['reservations'])}")


if __name__ == "__main__":
    sys.exit(main())
