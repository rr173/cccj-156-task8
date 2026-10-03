"""Command-line interface for the offline audit archive.

    python3 -m kc.archive_cli init        --root ./kc-data --threshold 2
    python3 -m kc.archive_cli register    --root ./kc-data --source region-a
    python3 -m kc.archive_cli keygen
    python3 -m kc.archive_cli ingest      --root ./kc-data segments.json
    python3 -m kc.archive_cli status      --root ./kc-data
    python3 -m kc.archive_cli recover     --root ./kc-data
    python3 -m kc.archive_cli resolve     --root ./kc-data --conflict cfx-1 \
        --accept <digest> --reason "..." --by operator
    python3 -m kc.archive_cli publish     --root ./kc-data
    python3 -m kc.archive_cli export      --root ./kc-data --out bundle.json
    python3 -m kc.archive_cli verify      bundle.json
    python3 -m kc.archive_cli worker      --root ./kc-data segments.json
    python3 -m kc.archive_cli mksample    --out segs.json --source region-a \
        --seed <b64> --count 4
"""

from __future__ import annotations

import argparse
import json
import sys

from . import crypto
from .archive import (
    Archive, BadSignature, generate_source_keypair, segment_digest,
    sign_segment,
)
from .archive_verify import verify_bundle
from .errors import CeremonyError


def _load_segments(path: str):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "segments" in data:
        data = data["segments"]
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise SystemExit("input must be a JSON segment object or array")
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="kc.archive_cli")
    ap.add_argument("command",
                    choices=["init", "register", "keygen", "ingest", "status",
                             "recover", "resolve", "publish", "export",
                             "verify", "worker", "mksample"])
    ap.add_argument("--root", default="./kc-data")
    ap.add_argument("--threshold", type=int)
    ap.add_argument("--source")
    ap.add_argument("--pubkey")
    ap.add_argument("--conflict")
    ap.add_argument("--accept")
    ap.add_argument("--reason")
    ap.add_argument("--by")
    ap.add_argument("--seed")
    ap.add_argument("--count", type=int)
    ap.add_argument("--start", type=int, default=1)
    ap.add_argument("--prev", default="0" * 64)
    ap.add_argument("--out")
    ap.add_argument("--force", action="store_true")
    ap.add_argument("paths", nargs="*")
    args = ap.parse_intermixed_args(argv)

    if args.command == "keygen":
        pub, seed = generate_source_keypair()
        print(json.dumps({"pubkey": pub, "seed": seed}, indent=2))
        return 0

    if args.command == "verify":
        if not args.paths:
            ap.error("verify needs a bundle path")
        with open(args.paths[0], encoding="utf-8") as f:
            bundle = json.load(f)
        report = verify_bundle(bundle, strict=False)
        print(json.dumps(report, indent=2, sort_keys=True))
        if report["ok"]:
            print(f"[PASS] archive bundle verified: {report['checks']}")
            return 0
        print(f"[FAIL] {len(report['findings'])} finding(s):",
              file=sys.stderr)
        for f in report["findings"]:
            print(f"  - {f['code']}: {f['message']}", file=sys.stderr)
        return 1

    if args.command == "init":
        t = args.threshold if args.threshold is not None else 1
        arc = Archive(args.root, t)
        print(json.dumps({"initialized": True, "root": args.root,
                          "threshold": arc.threshold}, indent=2))
        return 0

    if args.command == "register":
        if not args.source:
            ap.error("--source required")
        if args.pubkey:
            pubkey = args.pubkey
            shown_seed = None
        else:
            pubkey, seed = generate_source_keypair()
            shown_seed = seed
        arc = Archive(args.root)
        res = arc.register_source(args.source, pubkey)
        if shown_seed:
            res["seed"] = shown_seed
            res["warning"] = ("the seed is shown ONCE; the exporter signs "
                              "segments with it")
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    arc = Archive(args.root, args.threshold)

    if args.command == "ingest" or args.command == "worker":
        segs = _load_segments(args.paths[0])
        # A worker process is simply a separate process sharing the directory;
        # the store lock guarantees convergence.
        res = arc.ingest_many(segs)
        res["view"] = arc.view()
        print(json.dumps(res, indent=2, sort_keys=True))
        return 0

    if args.command == "status":
        print(json.dumps(arc.view(), indent=2, sort_keys=True))
        return 0

    if args.command == "recover":
        print(json.dumps(arc.recover(), indent=2, sort_keys=True))
        return 0

    if args.command == "resolve":
        if not (args.conflict and args.accept and args.reason and args.by):
            ap.error("--conflict --accept --reason --by are required")
        print(json.dumps(arc.resolve_conflict(
            args.conflict, args.accept, args.reason, args.by), indent=2,
            sort_keys=True))
        return 0

    if args.command == "publish":
        try:
            print(json.dumps(arc.publish(force=args.force), indent=2,
                             sort_keys=True))
        except CeremonyError as e:
            print(json.dumps({"published": False, "code": e.code,
                              "error": str(e),
                              "problems": getattr(e, "details", {})},
                             indent=2), file=sys.stderr)
            return 2
        return 0

    if args.command == "export":
        bundle = arc.export_bundle()
        text = json.dumps(bundle, indent=2, sort_keys=True)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"exported bundle -> {args.out}")
        else:
            print(text)
        return 0

    if args.command == "mksample":
        # mksample --out segs.json --source id --seed b64 --count n
        if not (args.out and args.source and args.seed and args.count):
            ap.error("mksample needs --out --source --seed --count")
        src, seed_b64, count = args.source, args.seed, args.count
        start = args.start
        prev = args.prev
        seed = crypto.b64d(seed_b64)
        segs = []
        for i in range(count):
            seq = start + i
            payload = crypto.digest_hex(
                {"source": src, "seq": seq, "body": f"event-{seq}"})
            seg = sign_segment(seed, src, seq, prev, payload)
            segs.append(seg)
            prev = segment_digest(seg)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(segs, f, indent=2)
        print(f"wrote {count} segments -> {args.out}")
        return 0

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BadSignature as e:
        print(json.dumps({"error": str(e), "code": e.code}), file=sys.stderr)
        sys.exit(3)
    except CeremonyError as e:
        print(json.dumps({"error": str(e), "code": e.code}), file=sys.stderr)
        sys.exit(2)
