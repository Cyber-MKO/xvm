"""Command line: xvm-golden verify DIR | import-manager DIR --archives F --alerts F."""

from __future__ import annotations

import argparse
import sys
from datetime import timedelta
from pathlib import Path

from . import baseline


def _verify(args: argparse.Namespace) -> int:
    problems = baseline.verify(args.dir)
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print(f"ok: {args.dir}")
    return 0


def _import(args: argparse.Namespace) -> int:
    counts = baseline.import_manager(
        args.dir, args.archives, args.alerts, timedelta(seconds=args.margin)
    )
    print(f"archives: {counts['archives']} events, alerts: {counts['alerts']}")
    return _verify(args)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="xvm-golden", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="check a captured baseline")
    v.add_argument("dir", type=Path)
    v.set_defaults(func=_verify)
    i = sub.add_parser("import-manager", help="add the scenario window of the manager logs")
    i.add_argument("dir", type=Path)
    i.add_argument("--archives", type=Path, required=True)
    i.add_argument("--alerts", type=Path, required=True)
    i.add_argument("--margin", type=int, default=120, help="seconds added on each side")
    i.set_defaults(func=_import)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
