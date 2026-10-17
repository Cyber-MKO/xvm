"""Command line: xvm-golden verify | import-manager | diff-manager | delivery."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import timedelta
from pathlib import Path

from . import baseline, fidelity


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


def _report(report: fidelity.Report, out: Path | None) -> int:
    print(report.text())
    if out:
        out.write_text(json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8")
    return 1 if report.errors else 0


def _diff_manager(args: argparse.Namespace) -> int:
    try:
        report = fidelity.diff_manager(
            args.dir, args.archives, args.alerts, args.run_log, args.host, args.agent
        )
    except (ValueError, OSError) as e:
        print(f"xvm-golden: {e}", file=sys.stderr)
        return 2
    return _report(report, args.json)


def _delivery(args: argparse.Namespace) -> int:
    report = fidelity.Report()
    try:
        archives = fidelity.read_ndjson(args.archives, args.agent)
        fidelity.delivery(args.run_log, archives, args.host, report)
    except (ValueError, OSError) as e:
        print(f"xvm-golden: {e}", file=sys.stderr)
        return 2
    return _report(report, args.json)


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
    d = sub.add_parser(
        "diff-manager", help="fidelity test, T6 and T5: an emulated run against the golden run"
    )
    d.add_argument("dir", type=Path, help="golden capture with manager/ imported")
    d.add_argument("--archives", type=Path, required=True, help="emulated run's archives.json")
    d.add_argument("--alerts", type=Path, required=True, help="emulated run's alerts.json")
    d.add_argument("--run-log", type=Path, required=True, help="xvm-scenario run log")
    d.add_argument("--host", help="host in the run log (default: the first)")
    d.add_argument("--agent", help="keep only this agent.name from the emulated files")
    d.add_argument("--json", type=Path, help="also write the report as JSON")
    d.set_defaults(func=_diff_manager)
    t5 = sub.add_parser("delivery", help="T5: every event the run wrote arrives exactly once")
    t5.add_argument("--archives", type=Path, required=True)
    t5.add_argument("--run-log", type=Path, required=True)
    t5.add_argument("--host", help="host in the run log (default: the first)")
    t5.add_argument("--agent", help="keep only this agent.name")
    t5.add_argument("--json", type=Path)
    t5.set_defaults(func=_delivery)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
