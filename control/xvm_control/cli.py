"""Command line: xvm-profile validate FILE... | resolve FILE [--bases DIR]..."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

from . import profile

DEFAULT_BASES = Path("control/profiles/bases")


def _validate(args: argparse.Namespace) -> int:
    failed = False
    for path in args.files:
        try:
            doc = profile.load(path)
            if doc["kind"] == "host-profile":
                profile.resolve_file(path, args.bases or [DEFAULT_BASES])
        except profile.ProfileError as exc:
            print(exc, file=sys.stderr)
            failed = True
        else:
            print(f"ok: {path}")
    return 1 if failed else 0


def _resolve(args: argparse.Namespace) -> int:
    try:
        host = profile.resolve_file(args.file, args.bases or [DEFAULT_BASES])
    except profile.ProfileError as exc:
        print(exc, file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(host, indent=2))
    else:
        print(yaml.safe_dump(host, sort_keys=False, allow_unicode=True), end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="xvm-profile", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("validate", help="check base images and host profiles")
    v.add_argument("files", type=Path, nargs="+")
    v.add_argument("--bases", type=Path, action="append", help="base image folder (repeatable)")
    v.set_defaults(func=_validate)
    r = sub.add_parser("resolve", help="print a host profile merged onto its base")
    r.add_argument("file", type=Path)
    r.add_argument("--bases", type=Path, action="append", help="base image folder (repeatable)")
    r.add_argument("--format", choices=["yaml", "json"], default="yaml")
    r.set_defaults(func=_resolve)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
