"""Test-only fixture server for the transparency browser driver.

Boots a real ``kc.server`` against a scratch root, seeds a multi-purpose,
multi-version transparency tree (so the browser exercises a *larger* log with
mixed purposes and several historical heads), then exposes two TEST-ONLY
helper routes the browser cannot construct itself:

  * GET  /test-helper/fork-head
        a structurally valid head at the current size, signed by the real log
        key, but binding a different root_hash (monitor equivocation);
  * POST /test-helper/grow
        append one more public-only lifecycle leaf through the log, proving
        that publication resumes after split recovery.

The helper routes are registered by subclassing Handler in this fixture
file only; production code (kc.server) is unchanged.

Usage: python3 tests/transparency_browser_server.py PORT
The server prints "FIXTURE READY" on stdout once it is accepting requests.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http.server import ThreadingHTTPServer  # noqa: E402

from kc import crypto, ed25519  # noqa: E402
from kc.attestation import provision_device  # noqa: E402
from kc.ceremony import Orchestrator  # noqa: E402
from kc.console import DeviceContext  # noqa: E402
from kc import policy as P  # noqa: E402
from kc.fleet import Fleet  # noqa: E402
from kc import server as srv  # noqa: E402
from kc.storage import Store  # noqa: E402
from kc.transparency import (  # noqa: E402
    CREATED, STAGED, make_leaf, sign_head, head_content,
)

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8361
ROOT = tempfile.mkdtemp(prefix=f"kc-tl-browser-{PORT}-")

PURPOSES = ["root-signing", "svc-a", "svc-b", "svc-c", "svc-d"]
ROLES = [("alice", P.ROOT_OWNER), ("bruno", P.KEY_STEWARD),
         ("carla", P.WITNESS_SHAREHOLDER), ("diego", P.ENCLAVE_OPERATOR)]
PIDS = [p for p, _ in ROLES]
CONFIRMERS = ("alice", "bruno", "carla")


def seed_world():
    from kc.bootstrap import bootstrap
    bootstrap(ROOT, policy_id="pol-root-v1", purposes=tuple(PURPOSES))
    store = Store(ROOT)
    fleet = Fleet(os.path.join(ROOT, "wallets"))
    ctx = {pid: DeviceContext(fleet.get("dev_" + pid)) for pid in PIDS}
    with store.locked():
        o = Orchestrator(store)
        # ensure all four test devices are bound under the pol slots
        for purpose in PURPOSES:
            cid = o.open_ceremony(P.GENERATE, "pol-root-v1", purpose,
                                  "alice")["id"]
            for p in PIDS:
                ctx[p].attest(o, cid)
            for p in PIDS:
                ctx[p].receive_share(o, cid)
            for p in CONFIRMERS:
                ctx[p].confirm(o, cid)
            o.commit(cid, "alice")
        o.save()


def grow_one(o):
    """Append one more public-only leaf directly through the embedded log.
    Uses a fresh synthetic purpose so no lifecycle/key preconditions apply."""
    n = o.tlog.size
    leaf = make_leaf(
        f"grown-{n}", 1, f"v-grown-{n}", f"fp-grown-{n}", f"PUB-grown-{n}",
        CREATED, "NONE", "test-fixture", f"test-grow-{n}")
    r = o.tlog.record(leaf)
    return r["head"]


class FixtureHandler(srv.Handler):
    def do_GET(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        if path == "/test-helper/fork-head":
            return self._fork_head()
        return super().do_GET()

    def do_POST(self):
        from urllib.parse import urlparse
        path = urlparse(self.path).path
        if path == "/test-helper/grow":
            return self._grow()
        return super().do_POST()

    def _fork_head(self):
        with self.app.store.locked():
            o = Orchestrator(self.app.store)
            size = o.tlog.size
            local = o.tlog.current_head()
            fork = head_content(size, "f" * 64, local["issued_at"],
                                local["prev_head_hash"])
            fork["tree_head_sig"] = sign_head(o.seed, fork)
            fork["head_hash"] = "f" * 64
            o.save()
        self._send(200, fork)

    def _grow(self):
        from kc.transparency import PublicationFrozen
        try:
            with self.app.store.locked():
                o = Orchestrator(self.app.store)
                head = grow_one(o)
                o.save()
        except PublicationFrozen as e:
            self._error(e)
            return
        self._send(200, {"tree_size": head["tree_size"], "head": head})


def main():
    seed_world()
    app = srv.App(ROOT)
    httpd = ThreadingHTTPServer(("127.0.0.1", PORT), FixtureHandler)
    FixtureHandler.app = app
    print("FIXTURE READY", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        shutil.rmtree(ROOT, ignore_errors=True)


if __name__ == "__main__":
    main()
