"""HTTP surface + web console for the offline audit archive.

Run:  python3 -m kc.archive_server --root ./kc-data --port 8090

Unlike the ceremony console, the archive ingress is machine-to-machine:
exporters from regions/nodes POST signed segments, operators watch the
dashboard and make conflict decisions. It is intended to be bound to a
restricted/air-gapped network, hence no session layer — deploy behind the
same terminal-attestation proxy as the rest of the control plane if exposed.

Endpoints:
  GET  /                         dashboard (gaps, conflicts, round, roots)
  GET  /api/archive/status       full state view
  POST /api/archive/sources      {source, pubkey?} (key generated if omitted)
  POST /api/archive/threshold    {threshold}
  POST /api/archive/segments     one segment or {"segments":[...]}
  POST /api/archive/recover      resume from checkpoint after restart
  POST /api/archive/conflicts/resolve
                                 {conflict_id, accepted_digest, reason, by}
  POST /api/archive/publish      CAS publish for the current round
  GET  /api/archive/publications list published manifests
  GET  /api/archive/bundle       export bundle for the offline verifier
"""

from __future__ import annotations

import argparse
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from .archive import Archive
from .errors import CeremonyError

ARCHIVE_HTML = os.path.join(os.path.dirname(__file__), "archive.html")

PUBLIC_GET = {"/", "/index.html", "/health",
              "/api/archive/status", "/api/archive/publications",
              "/api/archive/bundle"}


class App:
    def __init__(self, root: str, threshold: int | None = None):
        self.archive = Archive(root, threshold)


class Handler(BaseHTTPRequestHandler):
    app: App = None

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, obj):
        body = json.dumps(obj, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        if not n:
            return {}
        raw = self.rfile.read(n).decode()
        if not raw.strip():
            return {}
        return json.loads(raw)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            try:
                with open(ARCHIVE_HTML, "rb") as f:
                    html = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(html)))
                self.end_headers()
                self.wfile.write(html)
            except FileNotFoundError:
                self._send(404, {"error": "console unavailable"})
            return
        if path == "/health":
            return self._send(200, {"ok": True})
        try:
            arc = self.app.archive
            if path == "/api/archive/status":
                return self._send(200, arc.view())
            if path == "/api/archive/publications":
                return self._send(200, {"publications": arc.publications()})
            if path == "/api/archive/bundle":
                return self._send(200, arc.export_bundle())
            self._send(404, {"error": "NOT_FOUND", "path": path})
        except CeremonyError as e:
            self._send(e.http_status, {"error": e.code, "message": str(e),
                                       "problems": getattr(e, "details", None)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": "INTERNAL", "message": str(e)})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except Exception:
            return self._send(400, {"error": "BAD_JSON"})
        arc = self.app.archive
        try:
            if path == "/api/archive/sources":
                pubkey = body.get("pubkey")
                shown_seed = None
                if not pubkey:
                    from .archive import generate_source_keypair
                    pubkey, shown_seed = generate_source_keypair()
                res = arc.register_source(body["source"], pubkey)
                if shown_seed and not res.get("duplicate"):
                    res["seed"] = shown_seed
                    res["warning"] = ("source signing seed, shown ONCE; "
                                      "exporters sign segments with it")
                return self._send(200, res)
            if path == "/api/archive/threshold":
                arc.set_threshold(int(body["threshold"]))
                return self._send(200, {"threshold": arc.threshold})
            if path == "/api/archive/segments":
                segs = body.get("segments", [body] if body else [])
                return self._send(200, arc.ingest_many(segs))
            if path == "/api/archive/recover":
                return self._send(200, arc.recover())
            if path == "/api/archive/conflicts/resolve":
                return self._send(200, arc.resolve_conflict(
                    body["conflict_id"], body["accepted_digest"],
                    body["reason"], body["by"]))
            if path == "/api/archive/publish":
                return self._send(200, arc.publish(
                    force=bool(body.get("force", False))))
            self._send(404, {"error": "NOT_FOUND", "path": path})
        except CeremonyError as e:
            self._send(e.http_status,
                       {"error": e.code, "message": str(e),
                        "problems": getattr(e, "details", {}).get(
                            "problems") if hasattr(e, "details") else None})
        except KeyError as e:
            self._send(400, {"error": "MISSING_FIELD", "field": str(e)})
        except Exception as e:  # noqa: BLE001
            self._send(500, {"error": "INTERNAL", "message": str(e)})


def serve(root: str, port: int, threshold: int | None = None):
    Handler.app = App(root, threshold)
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"archive console on http://127.0.0.1:{port}/  (data: {root})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="kc.archive_server")
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--threshold", type=int, default=None)
    args = ap.parse_args(argv)
    serve(args.root, args.port, args.threshold)


if __name__ == "__main__":
    main()
