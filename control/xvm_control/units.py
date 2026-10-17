"""Hosts as transient systemd units: the light way to supervise them.

`systemd-run` starts each host's agent as a transient service: no unit file,
and no supervisor process of ours. systemd restarts it on failure, sends
SIGTERM on stop and SIGKILL after the grace time, and keeps its state.

Unit settings:

- `Restart=on-failure`: a crash restarts; a clean exit (a stopped service) does not.
- `RestartSec=1`, and where systemd has them (version 254 and later)
  `RestartSteps=6` and `RestartMaxDelaySec=60`: backoff from 1 s to 60 s.
- `StartLimitIntervalSec=0`: never give up restarting.
- `KillSignal=SIGTERM`, `TimeoutStopSec=30`: the agent stops through its own
  service handler, and is killed after 30 s.
- `StandardOutput` and `StandardError` append to `host.log`, as with the
  Python supervisor.

Units go to the user's manager (`--user`), or the system manager when run as root.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

STOP_GRACE_S = 30


class UnitError(Exception):
    pass


def available() -> bool:
    """Is systemd running as this machine's init, with its tools on the PATH?"""
    if os.environ.get("XVM_SUPERVISOR_SYSTEMD") == "1":
        return True  # tests and unusual layouts
    return Path("/run/systemd/system").is_dir() and bool(
        shutil.which("systemd-run") and shutil.which("systemctl")
    )


def _scope() -> list[str]:
    return [] if os.geteuid() == 0 else ["--user"]


def unit_name(root: Path, host: str) -> str:
    """One name per run folder and host, so two run folders never collide."""
    site = hashlib.sha256(str(root.resolve()).encode()).hexdigest()[:8]
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", host)
    return f"xvm-{site}-{safe}.service"


def _version() -> int:
    try:
        out = subprocess.run(
            ["systemctl", "--version"], capture_output=True, text=True, check=False
        ).stdout
    except OSError:
        return 0
    m = re.match(r"systemd (\d+)", out)
    return int(m.group(1)) if m else 0


def start(root: Path, host: str, argv: list[str], log: Path) -> str:
    unit = unit_name(root, host)
    props = [
        "Restart=on-failure",
        "RestartSec=1",
        "StartLimitIntervalSec=0",
        "KillSignal=SIGTERM",
        f"TimeoutStopSec={STOP_GRACE_S}",
        f"StandardOutput=append:{log}",
        f"StandardError=append:{log}",
    ]
    if _version() >= 254:
        props += ["RestartSteps=6", "RestartMaxDelaySec=60"]
    # A unit left failed from an earlier run blocks the name.
    subprocess.run(["systemctl", *_scope(), "reset-failed", unit], capture_output=True, check=False)
    cmd = ["systemd-run", *_scope(), f"--unit={unit}", "--quiet"]
    for p in props:
        cmd += ["--property", p]
    r = subprocess.run([*cmd, "--", *argv], capture_output=True, text=True, check=False)
    if r.returncode != 0:
        raise UnitError(f"systemd-run failed: {r.stderr.strip() or r.returncode}")
    return unit


def stop(root: Path, host: str) -> bool:
    unit = unit_name(root, host)
    if show(root, host).get("ActiveState") in (None, "inactive", "failed"):
        return False
    subprocess.run(["systemctl", *_scope(), "stop", unit], capture_output=True, check=False)
    return True


def show(root: Path, host: str) -> dict:
    """The unit's properties; empty when systemd does not know it."""
    unit = unit_name(root, host)
    r = subprocess.run(
        [
            "systemctl",
            *_scope(),
            "show",
            unit,
            "--property",
            "LoadState,ActiveState,SubState,MainPID,NRestarts,ExecMainStatus,"
            "ActiveEnterTimestamp,StateChangeTimestamp",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    props = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    if props.get("LoadState") in (None, "not-found"):
        return {}
    return props


def status(root: Path, host: str) -> dict:
    """The host's state in the same terms as the Python supervisor's status.json."""
    p = show(root, host)
    if not p:
        return {}
    active, sub = p.get("ActiveState"), p.get("SubState")
    if active == "active" and sub == "running":
        state = "running"
    elif sub == "auto-restart" or active == "activating":
        state = "restarting"
    elif active == "failed":
        state = "failed"
    elif active == "deactivating":
        state = "stopping"
    else:
        state = "exited" if p.get("ExecMainStatus") == "0" else "stopped"
    restarts = int(p.get("NRestarts") or 0)
    pid = int(p.get("MainPID") or 0) or None
    return {
        "state": state,
        "pid": pid,
        "starts": restarts + 1,
        "restarts": restarts,
        "since": p.get("StateChangeTimestamp") or p.get("ActiveEnterTimestamp"),
        "last_exit": {"code": int(p["ExecMainStatus"])} if p.get("ExecMainStatus") else None,
        "unit": unit_name(root, host),
    }
