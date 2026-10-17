"""xvm-host: start, stop, reset and watch emulated hosts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .hostctl import HostError, Site

DEFAULT_ROOT = Path("run")


def _site(args: argparse.Namespace) -> Site:
    site = Site.open(args.root, args.bases or None, getattr(args, "hosts", None))
    site.save()
    return site


def _names(site: Site, args: argparse.Namespace) -> list[str]:
    if getattr(args, "all", False):
        return site.hosts()
    if not args.names:
        raise HostError("name a host, or use --all")
    return args.names


def _up(args: argparse.Namespace) -> int:
    site = _site(args)
    for name in args.names:
        print(f"{name}: {site.up(name, args.msi)}")
    return 0


def _down(args: argparse.Namespace) -> int:
    site = _site(args)
    for name in _names(site, args):
        print(f"{name}: {'stopped' if site.down(name) else 'was not up'}")
    return 0


def _reset(args: argparse.Namespace) -> int:
    site = _site(args)
    for name in args.names:
        print(f"{name}: reset; {site.reset(name, args.msi)}")
    return 0


def _status(args: argparse.Namespace) -> int:
    site = _site(args)
    names = args.names or site.hosts()
    rows = {n: site.status(n) for n in names}
    engine = {"pid": site.engine_pid()}
    if (site.root / "engine.json").exists():
        engine.update(json.loads((site.root / "engine.json").read_text()), pid=engine["pid"])
    if args.json:
        print(json.dumps({"engine": engine, "hosts": rows}, indent=2))
        return 0
    print(f"engine: {'up, pid ' + str(engine['pid']) if engine['pid'] else 'down'}")
    print(f"{'host':<20} {'state':<11} {'pid':>7} {'starts':>6} {'restarts':>8}  since")
    for n, st in rows.items():
        pid = st.get("pid") or "-"
        print(
            f"{n:<20} {st['state']:<11} {pid:>7} {st.get('starts', 0):>6} "
            f"{st.get('restarts', 0):>8}  {st.get('since', '-')}"
        )
    return 0


def _engine(args: argparse.Namespace) -> int:
    site = _site(args)
    if args.action == "start":
        print(f"engine: pid {site.start_engine()}")
    elif args.action == "stop":
        print("engine: " + ("stopped" if site.stop_engine(args.force) else "was not running"))
    elif args.action == "restart":
        site.stop_engine(args.force)
        print(f"engine: pid {site.start_engine()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="xvm-host", description=__doc__)
    ap.add_argument(
        "--root", type=Path, default=DEFAULT_ROOT, help=f"run folder (default {DEFAULT_ROOT})"
    )
    ap.add_argument(
        "--bases", type=Path, action="append", help="base image folder; saved in the run folder"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    u = sub.add_parser("up", help="start hosts: engine, install, supervisor")
    u.add_argument("names", nargs="+")
    u.add_argument("--hosts", type=Path, help="host profile folder; saved in the run folder")
    u.add_argument("--msi", type=Path, help="agent MSI to install on first start")
    u.set_defaults(func=_up)

    d = sub.add_parser("down", help="stop hosts")
    d.add_argument("names", nargs="*")
    d.add_argument("--all", action="store_true")
    d.set_defaults(func=_down)

    r = sub.add_parser("reset", help="return stopped hosts to their profile and reinstall")
    r.add_argument("names", nargs="+")
    r.add_argument("--hosts", type=Path)
    r.add_argument("--msi", type=Path)
    r.set_defaults(func=_reset)

    s = sub.add_parser("status", help="show hosts and the engine")
    s.add_argument("names", nargs="*")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=_status)

    e = sub.add_parser("engine", help="start, stop or restart the engine")
    e.add_argument("action", choices=("start", "stop", "restart"))
    e.add_argument("--hosts", type=Path)
    e.add_argument("--force", action="store_true", help="stop even with hosts up")
    e.set_defaults(func=_engine)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except HostError as exc:
        print(f"xvm-host: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
