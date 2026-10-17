"""xvm-scenario: check scenarios and play them on emulated hosts."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from . import actions, layout, replay
from .clock import HostClock, format_time, parse_duration, parse_time
from .corpus import LOGS, Capture
from .runner import RunLog, Scenario, ScenarioInvalid, load, plan, run


def _validate(args: argparse.Namespace) -> int:
    status = 0
    for path in args.scenarios:
        try:
            sc = load(path)
        except ScenarioInvalid as e:
            for p in e.problems:
                print(f"{path}: {p}", file=sys.stderr)
            status = 1
            continue
        print(f"{path}: ok, {len(sc.steps)} steps")
    return status


def _play(sc: Scenario, args: argparse.Namespace) -> int:
    """Play a scenario as `run` and `replay` describe: a dry run, or on the engine."""
    try:
        start = parse_time(args.start) if args.start else None
        max_skew = parse_duration(args.max_skew)
        jitter = parse_duration(args.jitter)
    except ValueError as e:
        print(f"xvm-scenario: {e}", file=sys.stderr)
        return 2
    if args.dry_run:
        start = start or datetime.now(UTC)
        seed = args.seed or sc.name
        clocks = {h: HostClock(h, start, seed, max_skew, jitter) for h in args.host}
        for p in plan(sc, clocks):
            print(f"{format_time(p.at)}  {p.host}  {p.step.index:>3}  {p.step.name}")
        return 0
    if not args.socket:
        print("xvm-scenario: --socket is required unless --dry-run", file=sys.stderr)
        return 2
    log = RunLog(args.log)
    try:
        run(
            sc,
            args.socket,
            args.host,
            start=start,
            speed=args.speed,
            seed=args.seed,
            max_skew=max_skew,
            jitter=jitter,
            log=log,
            stop_on_error=args.stop_on_error,
        )
    except ScenarioInvalid as e:
        for p in e.problems:
            print(f"xvm-scenario: {p}", file=sys.stderr)
        return 1
    except (OSError, ConnectionError) as e:
        print(f"xvm-scenario: engine: {e}", file=sys.stderr)
        return 1
    finally:
        log.close()
    print(
        f"{sc.name}: {len(sc.steps)} steps on {len(args.host)} hosts, "
        f"{log.errors} failed, {log.gaps} gaps"
    )
    return 1 if log.errors else 0


def _run(args: argparse.Namespace) -> int:
    try:
        sc = load(args.scenario)
    except ScenarioInvalid as e:
        for p in e.problems:
            print(f"{args.scenario}: {p}", file=sys.stderr)
        return 1
    return _play(sc, args)


def _logs(value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in value.split(",") if x.strip())


def _replay(args: argparse.Namespace) -> int:
    capture = Capture.load(args.capture)
    sc, notes = replay.scenario(capture, args.source, _logs(args.logs))
    for n in notes:
        print(f"note: {n}", file=sys.stderr)
    if not sc.steps:
        print("xvm-scenario: no events to replay", file=sys.stderr)
        return 1
    return _play(sc, args)


def _diff_events(args: argparse.Namespace) -> int:
    try:
        report = layout.diff(Capture.load(args.capture), args.run_log, args.host, _logs(args.logs))
    except ValueError as e:
        print(f"xvm-scenario: {e}", file=sys.stderr)
        return 2
    print(report.text())
    if args.json:
        args.json.write_text(json.dumps(report.to_json(), indent=2) + "\n", encoding="utf-8")
    return 1 if report.errors else 0


def _actions(args: argparse.Namespace) -> int:
    for name in sorted(actions.ACTIONS):
        required, optional = actions.PARAMS[name]
        params = [*sorted(required), *(f"[{p}]" for p in sorted(optional))]
        doc = (actions.ACTIONS[name].__doc__ or "").strip().splitlines()
        print(f"{name:<24} {' '.join(params)}")
        if doc:
            print(f"{'':<24} {doc[0]}")
    return 0


def _play_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--socket", help="xvm-engined socket")
    p.add_argument("--host", action="append", required=True, help="host name; repeat for more")
    p.add_argument("--start", help="scenario start, RFC 3339 (default: now)")
    p.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="1 is real time, 10 is ten times faster, 0 runs without waiting",
    )
    p.add_argument("--seed", default="", help="seed for host skew and jitter (default: name)")
    p.add_argument("--max-skew", default="0s", help="largest clock offset per host, e.g. 30s")
    p.add_argument("--jitter", default="0s", help="largest extra delay per step, e.g. 2s")
    p.add_argument("--log", type=Path, help="append the run log (JSON Lines) here")
    p.add_argument("--stop-on-error", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="print the timeline only")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="xvm-scenario", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="check scenario files")
    v.add_argument("scenarios", nargs="+", type=Path)
    v.set_defaults(func=_validate)

    r = sub.add_parser("run", help="play a scenario on hosts served by xvm-engined")
    r.add_argument("scenario", type=Path)
    _play_options(r)
    r.set_defaults(func=_run)

    rp = sub.add_parser("replay", help="replay a golden capture's events on hosts")
    rp.add_argument("capture", type=Path, help="golden capture folder")
    rp.add_argument(
        "--source",
        choices=("scenario", "recent"),
        default="scenario",
        help="the scenario window, or the newest events of each log",
    )
    rp.add_argument("--logs", default=",".join(LOGS), help="logs to replay, comma-separated")
    _play_options(rp)
    rp.set_defaults(func=_replay)

    d = sub.add_parser(
        "diff-events", help="compare a run's events with the golden capture, step by step"
    )
    d.add_argument("capture", type=Path, help="golden capture folder")
    d.add_argument("run_log", type=Path, help="run log of library/golden-windows.yaml")
    d.add_argument("--host", help="host in the run log (default: the first)")
    d.add_argument("--logs", default=",".join(LOGS), help="logs to compare, comma-separated")
    d.add_argument("--json", type=Path, help="also write the report as JSON")
    d.set_defaults(func=_diff_events)

    a = sub.add_parser("actions", help="list the named actions")
    a.set_defaults(func=_actions)

    args = ap.parse_args(argv)
    if getattr(args, "speed", 0) < 0:
        ap.error("--speed must be 0 or more")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
