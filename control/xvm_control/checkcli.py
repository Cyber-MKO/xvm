"""xvm-check: T2 and T3 against the Wazuh manager's API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from xvm_scenario.clock import parse_duration

from . import checks, profile
from .manager import Manager, ManagerError

DEFAULT_BASES = Path("control/profiles/bases")


def _manager(args: argparse.Namespace) -> Manager:
    password = os.environ.get(args.password_env)
    if password is None:
        raise ManagerError(f"set the API password in ${args.password_env}")
    return Manager(args.manager, args.user, password, ca=args.ca, insecure=args.insecure)


def _finish(result: checks.Result, out: Path | None) -> int:
    print(result.text())
    if out:
        out.write_text(json.dumps(result.to_json(), indent=2) + "\n", encoding="utf-8")
    return 0 if result.passed else 1


def _t2(args: argparse.Namespace) -> int:
    duration = parse_duration(args.duration)
    interval = parse_duration(args.interval)
    enroll = parse_duration(args.enroll_timeout)
    keepalive = parse_duration(args.max_keepalive)
    if args.from_log:
        result = checks.score_t2(
            checks.read_samples(args.from_log), duration, keepalive, interval, enroll
        )
    else:
        if not args.manager:
            raise ManagerError("give --manager, or --from-log to score a recorded run")
        result = checks.watch_t2(
            _manager(args), args.agent, duration, interval, enroll, keepalive, args.log
        )
    return _finish(result, args.json)


def _t3(args: argparse.Namespace) -> int:
    host = profile.resolve_file(args.profile, args.bases or [DEFAULT_BASES])
    agent = _manager(args).agent(args.agent or host["identity"]["hostname"])
    return _finish(checks.check_t3(agent, host), args.json)


def _manager_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("--manager", help="API URL, such as https://manager:55000")
    p.add_argument("--user", default="wazuh", help="API user (default wazuh)")
    p.add_argument(
        "--password-env",
        default="WAZUH_API_PASSWORD",
        help="environment variable holding the API password",
    )
    p.add_argument("--ca", help="CA file for the API certificate")
    p.add_argument(
        "--insecure", action="store_true", help="accept the manager's self-signed certificate"
    )
    p.add_argument("--json", type=Path, help="also write the result as JSON")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="xvm-check", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    t2 = sub.add_parser("t2", help="enrollment and keepalive: active for the whole window")
    _manager_options(t2)
    t2.add_argument("--agent", required=True, help="agent name on the manager")
    t2.add_argument("--duration", default="24h", help="window to stay active (default 24h)")
    t2.add_argument("--interval", default="60s", help="time between samples (default 60s)")
    t2.add_argument(
        "--enroll-timeout", default="10m", help="time allowed to become active (default 10m)"
    )
    t2.add_argument(
        "--max-keepalive",
        default="120s",
        help="oldest keepalive allowed while active (default 120s)",
    )
    t2.add_argument("--log", type=Path, help="append every sample here (JSON Lines)")
    t2.add_argument("--from-log", type=Path, help="score a recorded sample log instead")
    t2.set_defaults(func=_t2)

    t3 = sub.add_parser("t3", help="identity: the manager shows the profile's OS")
    _manager_options(t3)
    t3.add_argument("--profile", type=Path, required=True, help="host profile")
    t3.add_argument("--bases", type=Path, action="append")
    t3.add_argument("--agent", help="agent name (default: the profile's hostname)")
    t3.set_defaults(func=_t3)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except (ManagerError, profile.ProfileError, ValueError) as e:
        print(f"xvm-check: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
