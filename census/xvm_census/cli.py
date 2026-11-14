"""Command line: xvm-census scan PACKAGE --agent NAME, and
xvm-census runtime REPORT.json LOG... to record run-time lookups."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import tempfile
from pathlib import Path

from . import report, runtime, scan, unpack


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


def _cmd_runtime(args: argparse.Namespace) -> int:
    path: Path = args.report
    census = json.loads(path.read_text())
    lookups = set()
    for log in args.logs:
        lookups |= runtime.parse_log(log.read_text(errors="replace"))
    added = runtime.merge(census, lookups)
    json_path, md_path = report.write(census, path.parent, path.stem)
    print(f"{added} new run-time lookups in {json_path} and {md_path}")
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
    r = sub.add_parser(
        "runtime", help="record GetProcAddress lookups from personality gap logs in a report"
    )
    r.add_argument("report", type=Path, help="the census report JSON to update")
    r.add_argument("logs", type=Path, nargs="+", help="personality logs with gap lines")
    r.set_defaults(func=_cmd_runtime)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
