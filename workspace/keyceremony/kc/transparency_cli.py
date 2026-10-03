"""Command-line independent checker for the transparency log.

Usage:
    python -m kc.transparency_cli verify export.json
    python -m kc.transparency_cli verify transparency_section.json

Accepts either a full ceremony export bundle (as produced by
``kc.verify_export --from-store`` / ``GET /api/export``) or a standalone
transparency section. It recomputes every Merkle root from the leaves,
re-derives proof positions from (size, index), replays the signed head chain,
enforces the per-(purpose, version) lifecycle state machine, checks
split-view handling and flags any materialized ACTIVE/STAGED key that has no
transparency leaf. No state directory or secret material is needed.

Exit code 0 = clean; 2 = findings (each printed with a distinct code).
"""

from __future__ import annotations

import argparse
import json
import sys

from .transparency_verify import verify_transparency


def _load(path: str):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    if isinstance(doc, dict) and "transparency" in doc:
        section = doc["transparency"]
        return section, doc.get("keys"), doc.get("audit")
    return doc, None, None


def verify_file(path: str) -> dict:
    section, keys, audit = _load(path)
    if keys is None and audit is None:
        return verify_transparency(section)
    return verify_transparency(section, keys=keys, audit=audit)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["verify"])
    ap.add_argument("path", help="export bundle or transparency section JSON")
    a = ap.parse_args(argv)
    result = verify_file(a.path)
    print(f"leaves={result['n_leaves']} heads={result['n_heads']}")
    if result["ok"]:
        print("TRANSPARENCY VERIFIED OK")
        return 0
    print("FINDINGS:")
    for f in result["findings"]:
        print(f"  - {f['code']}: {f['message']}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
