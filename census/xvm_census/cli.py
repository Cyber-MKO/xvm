"""Command line: xvm-census scan PACKAGE --agent NAME."""

from __future__ import annotations

import argparse
import shutil
import sys
import tempfile
from pathlib import Path

from . import report, scan, unpack


def _cmd_scan(args: argparse.Namespace) -> int:
    src: Path = args.package
    if not src.exists():
        print(f"not found: {src}", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="xvm-census-") as tmp:
        if src.is_dir():
            root, notes = src, []
        else:
            root = Path(tmp) / "root"
            try:
                notes = unpack.unpack(src, root)
            except unpack.UnpackError as exc:
                print(f"unpack failed: {exc}", file=sys.stderr)
                return 1
        digest = None if src.is_dir() else scan.sha256(src)
        census = scan.build_census(
            root, agent=args.agent, source=src.name, notes=notes, source_sha256=digest
        )
        json_path, md_path = report.write(census, args.out, args.name or args.agent)
        if args.keep and not src.is_dir():
            # Keep the unpacked tree by moving it out of the temporary directory.
            keep_to = args.out / f"{args.name or args.agent}.unpacked"
            shutil.move(root, keep_to)
            print(f"unpacked tree kept at {keep_to}", file=sys.stderr)
    print(json_path)
    print(md_path)
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="xvm-census", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="unpack a package and report the APIs it imports")
    s.add_argument("package", type=Path, help="MSI, PKG, DEB, RPM, or an unpacked directory")
    s.add_argument("--agent", required=True, help="agent label, for example wazuh-agent-4.13.1")
    s.add_argument("--name", help="report file name stem (defaults to --agent)")
    s.add_argument("--out", type=Path, default=Path("census/reports"))
    s.add_argument("--keep", action="store_true", help="keep the unpacked tree next to the report")
    s.set_defaults(func=_cmd_scan)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
