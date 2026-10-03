#!/usr/bin/env python3
"""Launch the transparency browser fixture, run the node browser driver,
and tear the fixture down regardless of the outcome.

Usage: python3 tests/transparency_browser_e2e.py [PORT]
"""

import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8364


def main() -> int:
    srv = subprocess.Popen(
        [sys.executable, os.path.join(HERE, "transparency_browser_server.py"),
         str(PORT)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    ready = False
    try:
        deadline = time.time() + 30
        while time.time() < deadline:
            line = srv.stdout.readline()
            if not line:
                if srv.poll() is not None:
                    print("fixture server exited early", file=sys.stderr)
                    return 2
                time.sleep(0.05)
                continue
            if "FIXTURE READY" in line:
                ready = True
                break
        if not ready:
            print("fixture server did not become ready", file=sys.stderr)
            return 2
        node = subprocess.run(
            ["node", os.path.join(HERE, "transparency_browser_e2e.js"),
             str(PORT)])
        return node.returncode
    finally:
        if srv.poll() is None:
            srv.send_signal(signal.SIGINT)
            try:
                srv.wait(timeout=5)
            except subprocess.TimeoutExpired:
                srv.kill()
                srv.wait()


if __name__ == "__main__":
    raise SystemExit(main())
