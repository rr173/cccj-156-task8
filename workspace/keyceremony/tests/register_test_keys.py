"""Test-only helper: provision ACTIVE key versions for the given purposes in
a store without running ceremonies. The library surface is intentionally
ungated, so this is the supported way for tests to seed keys for purposes
the bootstrapped policy does not cover.

Usage: register_test_keys.py <root> <purpose> [<purpose>...]
Prints JSON {purpose: key_version_id} on stdout.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from kc.storage import Store
from kc.ceremony import Orchestrator
from kc import crypto


def main():
    root = sys.argv[1]
    purposes = sys.argv[2:]
    store = Store(root)
    with store.locked():
        o = Orchestrator(store)
        out = {}
        for pur in purposes:
            seed, pub = crypto.gen_signing_keypair()
            k = o.dir.register_version(pur, seed, pub, [], [],
                                       "test-helper")
            out[pur] = k["id"]
        o.save()
    sys.stdout.write(json.dumps(out))


def crash_worker():
    """Minimal crash reproducer used by the budget HTTP e2e.

    argv: root mode request_id purpose subject [message]
    mode = hold        take a reservation then crash (exit 17), never sign;
           hold-ok    take a reservation and exit cleanly (exit 0);
           signature   hold, sign, then crash before settle.
    Every durable step is fsynced by the BudgetManager before the crash.
    """
    root, mode, request_id, purpose, subject = sys.argv[2:7]
    message = (sys.argv[7] if len(sys.argv) > 7 else "msg").encode()
    store = Store(root)
    with store.locked():
        o = Orchestrator(store)
        if mode in ("hold", "hold-ok"):
            o.budgets.hold(request_id=request_id, purpose=purpose,
                           subject=subject, quantity=1)
            o.save()
        elif mode == "signature":
            o.budgeted_sign(purpose=purpose, message=message,
                            request_id=request_id, subject=subject,
                            crash_after="signature")
        else:
            raise SystemExit(2)
    os._exit(0 if mode == "hold-ok" else 17)


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--crash":
        crash_worker()
    else:
        main()
