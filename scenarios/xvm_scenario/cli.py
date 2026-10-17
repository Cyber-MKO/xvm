"""xvm-scenario: check scenarios and play them on emulated hosts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import actions
from .clock import HostClock, format_time, parse_duration, parse_time
from .runner import RunLog, ScenarioInvalid, load, plan, run


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


def _run(args: argparse.Namespace) -> int:
    try:
        sc = load(args.scenario)
        start = parse_time(args.start) if args.start else None
        max_skew = parse_duration(args.max_skew)
        jitter = parse_duration(args.jitter)
    except ScenarioInvalid as e:
        for p in e.problems:
            print(f"{args.scenario}: {p}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"xvm-scenario: {e}", file=sys.stderr)
        return 2
    if args.dry_run:
        from datetime import UTC, datetime

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


def _actions(args: argparse.Namespace) -> int:
    for name in sorted(actions.ACTIONS):
        required, optional = actions.PARAMS[name]
        params = [*sorted(required), *(f"[{p}]" for p in sorted(optional))]
        doc = (actions.ACTIONS[name].__doc__ or "").strip().splitlines()
        print(f"{name:<24} {' '.join(params)}")
        if doc:
            print(f"{'':<24} {doc[0]}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="xvm-scenario", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="check scenario files")
    v.add_argument("scenarios", nargs="+", type=Path)
    v.set_defaults(func=_validate)

    r = sub.add_parser("run", help="play a scenario on hosts served by xvm-engined")
    r.add_argument("scenario", type=Path)
    r.add_argument("--socket", help="xvm-engined socket")
    r.add_argument("--host", action="append", required=True, help="host name; repeat for more")
    r.add_argument("--start", help="scenario start, RFC 3339 (default: now)")
    r.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="1 is real time, 10 is ten times faster, 0 runs without waiting",
    )
    r.add_argument("--seed", default="", help="seed for host skew and jitter (default: name)")
    r.add_argument("--max-skew", default="0s", help="largest clock offset per host, e.g. 30s")
    r.add_argument("--jitter", default="0s", help="largest extra delay per step, e.g. 2s")
    r.add_argument("--log", type=Path, help="append the run log (JSON Lines) here")
    r.add_argument("--stop-on-error", action="store_true")
    r.add_argument("--dry-run", action="store_true", help="print the timeline only")
    r.set_defaults(func=_run)

    a = sub.add_parser("actions", help="list the named actions")
    a.set_defaults(func=_actions)

    args = ap.parse_args(argv)
    if getattr(args, "speed", 0) < 0:
        ap.error("--speed must be 0 or more")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
