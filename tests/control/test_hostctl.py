"""xvm-host: the engine, installs, supervisors, restarts and resets, with a fake runner."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from xvm_control import hostctl
from xvm_control.hostcli import main

ROOT = Path(__file__).resolve().parents[2]
SCN = ROOT / "tests" / "scenario" / "profiles"

# Stands in for xvm-windows-run. FAKE_MODE: serve (until SIGTERM), fail, fail-once, exit0.
FAKE_RUNNER = """
import json, os, signal, sys, time
from pathlib import Path
out = Path(os.environ["FAKE_OUT"])
runs = out / "runs.jsonl"
n = len(runs.read_text().splitlines()) if runs.exists() else 0
with runs.open("a") as f:
    f.write(json.dumps({"argv": sys.argv[1:], "pid": os.getpid()}) + "\\n")
mode = os.environ.get("FAKE_MODE", "serve")
if mode == "fail" or (mode == "fail-once" and n == 0):
    print("agent crashed", flush=True)
    sys.exit(3)
if mode == "exit0":
    sys.exit(0)
def stop(signum, frame):
    (out / "stopped").write_text("SIGTERM")
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
print("agent started", flush=True)
while True:
    time.sleep(0.05)
"""


@pytest.fixture(scope="module")
def engined() -> Path:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not installed")
    subprocess.run(
        ["cargo", "build", "-q", "-p", "xvm-engine", "--bin", "xvm-engined"], cwd=ROOT, check=True
    )
    return ROOT / "target" / "debug" / "xvm-engined"


@pytest.fixture
def site(engined, tmp_path, monkeypatch):
    runner = tmp_path / "fake-runner"
    runner.write_text(f"#!{sys.executable}\n{FAKE_RUNNER}")
    runner.chmod(0o755)
    out = tmp_path / "out"
    out.mkdir()
    hosts = tmp_path / "hosts"
    shutil.copytree(SCN / "hosts", hosts)
    # scn-a gets the agent launch settings the installer step reads.
    (hosts / "scn-a.yaml").write_text(
        (hosts / "scn-a.yaml").read_text()
        + "agent:\n  product: wazuh\n  version: 4.14.2\n  pid: 4812\n"
        "  environment: {ProgramFiles: 'C:\\Program Files (x86)'}\n"
    )
    monkeypatch.setenv("XVM_ENGINED", str(engined))
    monkeypatch.setenv("XVM_RUNNER", str(runner))
    monkeypatch.setenv("FAKE_OUT", str(out))
    root = tmp_path / "run"
    s = hostctl.Site(root, [SCN / "bases"], hosts)
    s.save()
    yield s, out
    for h in s.hosts():
        s.down(h, timeout=5)
    s.stop_engine(force=True)


def wait_for(fn, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        v = fn()
        if v:
            return v
        time.sleep(0.05)
    raise AssertionError("timed out")


def runs(out: Path) -> list[dict]:
    p = out / "runs.jsonl"
    return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []


def test_up_status_down(site, capsys):
    s, out = site
    assert main(["--root", str(s.root), "up", "scn-a", "scn-b"]) == 0
    assert s.engine_pid() and s.socket.exists()
    wait_for(lambda: len(runs(out)) == 2)
    st = wait_for(lambda: s.status("scn-a") if s.status("scn-a")["state"] == "running" else None)
    assert st["starts"] == 1 and st["pid"]
    argv = next(r["argv"] for r in runs(out) if "scn-a" in r["argv"])
    assert argv == [
        "--engine",
        str(s.socket),
        "--host",
        "scn-a",
        "--drive",
        f"C={s.drive('scn-a')}",
    ]
    # A second up leaves a running host alone.
    assert s.up("scn-a", None) == "already up"
    capsys.readouterr()
    assert main(["--root", str(s.root), "status", "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["engine"]["pid"] == s.engine_pid()
    assert {h: v["state"] for h, v in status["hosts"].items()} == {
        "scn-a": "running",
        "scn-b": "running",
    }
    # The engine refuses to stop under running hosts.
    assert main(["--root", str(s.root), "engine", "stop"]) == 1
    # down passes SIGTERM to the agent, which stops through its own handler.
    assert main(["--root", str(s.root), "down", "--all"]) == 0
    assert (out / "stopped").read_text() == "SIGTERM"
    assert s.status("scn-a")["state"] == "stopped"
    assert s.supervisor_pid("scn-a") is None
    assert "agent started" in (s.host_dir("scn-a") / "host.log").read_text()


def test_failures_restart_with_backoff(site, monkeypatch):
    s, out = site
    monkeypatch.setenv("FAKE_MODE", "fail-once")
    s.up("scn-b", None)
    st = wait_for(lambda: (x := s.status("scn-b"))["starts"] == 2 and x["state"] == "running" and x)
    assert st["restarts"] == 1
    assert st["last_exit"]["code"] == 3
    assert "exited with 3; restarting in 1s" in (s.host_dir("scn-b") / "host.log").read_text()


def test_clean_exit_is_not_restarted(site, monkeypatch):
    s, out = site
    monkeypatch.setenv("FAKE_MODE", "exit0")
    s.up("scn-b", None)
    st = wait_for(lambda: (x := s.status("scn-b"))["state"] == "exited" and x)
    assert st["starts"] == 1 and st["restarts"] == 0
    assert s.supervisor_pid("scn-b") is None


def test_install_once_and_reset(site, monkeypatch, tmp_path):
    s, out = site
    calls = []

    class Result:
        files, gaps = 3, ["CustomAction x"]

    def fake_install(msi, drives, host, program_files):
        calls.append((drives["C"], host["name"], program_files))
        (drives["C"] / "Program Files (x86)").mkdir(parents=True, exist_ok=True)
        return Result()

    monkeypatch.setattr("xvm_msi.install.install", fake_install)
    msi = tmp_path / "agent.msi"
    msi.write_bytes(b"msi")
    assert s.install("scn-a", msi) == "installed 3 files, 1 gaps"
    assert s.install("scn-a", msi) == "already installed"
    assert calls == [(s.drive("scn-a"), "scn-a", "C:\\Program Files (x86)")]
    assert "gap msi CustomAction x" in (s.host_dir("scn-a") / "host.log").read_text()
    with pytest.raises(hostctl.HostError, match="ProgramFiles is not set"):
        s.install("scn-b", msi)

    # reset drops the engine's run-time changes and installs again.
    s.start_engine()
    from xvm_scenario.engine import Engine

    e = Engine(s.socket, "scn-a")
    e.call("list.upsert", name="users", item={"name": "eve"})
    assert any(u["name"] == "eve" for u in e.call("list", name="users"))
    assert s.reset("scn-a", msi) == "installed 3 files, 1 gaps"
    assert not any(u["name"] == "eve" for u in e.call("list", name="users"))
    e.close()
    assert len(calls) == 2
    s.up("scn-a", None)
    with pytest.raises(hostctl.HostError, match="is up"):
        s.reset("scn-a", msi)


def test_unknown_host_and_missing_site(tmp_path, capsys):
    assert main(["--root", str(tmp_path / "nowhere"), "status"]) == 1
    assert "pass --bases and --hosts" in capsys.readouterr().err


def _corpus(root: Path) -> Path:
    from ..scenario.capture import event_xml

    sec = "Microsoft-Windows-Security-Auditing"
    events = [
        event_xml(
            {
                "provider": sec,
                "event_id": 4624,
                "time": "2026-01-01T00:00:00.0000000Z",
                "process_id": 640,
                "data": [{"name": "WorkstationName", "value": "GOLDEN-VM"}],
            },
            "Security",
        ),
        event_xml(
            {
                "provider": sec,
                "event_id": 4634,
                "time": "2026-01-01T00:01:00.0000000Z",
                "data": [{"name": "TargetUserSid", "value": "S-1-5-21-7-8-9-500"}],
            },
            "Security",
        ),
    ]
    (root / "evtx" / "rendered").mkdir(parents=True)
    (root / "evtx" / "rendered" / "Security.xml").write_text(
        "﻿<Events>" + "".join(events) + "</Events>", encoding="utf-8"
    )
    (root / "host").mkdir()
    (root / "manifest.json").write_text(json.dumps({"host": {"name": "GOLDEN-VM"}}))
    (root / "host" / "users.json").write_text(
        json.dumps([{"Name": "Administrator", "SID": "S-1-5-21-7-8-9-500"}])
    )
    (root / "host" / "processes.json").write_text(
        json.dumps([{"ProcessId": 640, "Name": "lsass.exe"}])
    )
    return root


def test_first_start_seeds_the_logs_once(site, tmp_path):
    from datetime import UTC, datetime

    from xvm_scenario.engine import Engine

    s, out = site
    s.corpus = _corpus(tmp_path / "capture")
    s.save()

    def security():
        e = Engine(s.socket, "scn-a")
        try:
            return e.call("evt.query", channel="Security", format="json")["events"]
        finally:
            e.close()

    assert s.up("scn-a", None).endswith("seeded 2 events (0 gaps)")
    events = security()
    assert [e["event_id"] for e in events] == [4624, 4634]
    # Rewritten to name this host, and shifted so the last event is now.
    assert events[0]["data"][0]["value"] == "SCN-A"
    assert events[1]["data"][0]["value"] == "S-1-5-21-1111-2222-3333-500"
    last = datetime.fromisoformat(events[1]["time"].replace("Z", "+00:00"))
    assert abs((datetime.now(UTC) - last).total_seconds()) < 30
    first = datetime.fromisoformat(events[0]["time"].replace("Z", "+00:00"))
    assert round((last - first).total_seconds()) == 60
    # A later start does not seed again; the saved corpus is reused.
    s.down("scn-a")
    again = hostctl.Site.open(s.root)
    assert again.corpus == s.corpus.resolve()
    assert again.up("scn-a", None).endswith("logs already seeded")
    assert len(security()) == 2
    # After a reset the logs are empty, so the next start seeds them again.
    again.down("scn-a")
    again.reset("scn-a", None)
    assert security() == []
    assert again.up("scn-a", None).endswith("seeded 2 events (0 gaps)")


# Stand-ins for systemd-run and systemctl: record each call, run the unit's
# command in the background, and answer `show` from a state file per unit.
FAKE_SYSTEMD_RUN = """
import json, os, subprocess, sys
from pathlib import Path
d = Path(os.environ["FAKE_SYSTEMD"])
args = sys.argv[1:]
with (d / "calls.jsonl").open("a") as f:
    f.write(json.dumps(["systemd-run", *args]) + "\\n")
unit = next(a.split("=", 1)[1] for a in args if a.startswith("--unit="))
cmd = args[args.index("--") + 1:]
p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)
(d / unit).write_text(json.dumps({"pid": p.pid}))
"""
FAKE_SYSTEMCTL = """
import json, os, signal, sys, time
from pathlib import Path
d = Path(os.environ["FAKE_SYSTEMD"])
args = sys.argv[1:]
with (d / "calls.jsonl").open("a") as f:
    f.write(json.dumps(["systemctl", *args]) + "\\n")
words = [a for a in args if not a.startswith("--")]
if args == ["--version"]:
    print("systemd 255 (255.4)")
    sys.exit(0)
verb, unit = words[0], words[1]
state = d / unit
def alive(pid):
    # Not our child, so a finished agent lingers as a zombie until init reaps it.
    try:
        return "zombie" not in Path(f"/proc/{pid}/status").read_text().lower()
    except FileNotFoundError:
        return False
if verb == "show":
    if not state.exists():
        print("LoadState=not-found")
        sys.exit(0)
    pid = json.loads(state.read_text())["pid"]
    if alive(pid):
        print(f"LoadState=loaded\\nActiveState=active\\nSubState=running\\nMainPID={pid}\\n"
              "NRestarts=0\\nExecMainStatus=\\nStateChangeTimestamp=now")
    else:
        state.unlink()  # a transient unit is gone once it ends
        print("LoadState=not-found")
elif verb == "stop" and state.exists():
    pid = json.loads(state.read_text())["pid"]
    os.kill(pid, signal.SIGTERM)
    for _ in range(200):
        if not alive(pid):
            break
        time.sleep(0.02)
    state.unlink()
"""


@pytest.fixture
def systemd(site, tmp_path, monkeypatch):
    s, out = site
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in (("systemd-run", FAKE_SYSTEMD_RUN), ("systemctl", FAKE_SYSTEMCTL)):
        f = bin_dir / name
        f.write_text(f"#!{sys.executable}\n{body}")
        f.chmod(0o755)
    state = tmp_path / "systemd"
    state.mkdir()
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("FAKE_SYSTEMD", str(state))
    monkeypatch.setenv("XVM_SUPERVISOR_SYSTEMD", "1")
    s.supervisor = "systemd"
    s.save()
    yield s, out, state


def _calls(state: Path) -> list[list[str]]:
    return [json.loads(x) for x in (state / "calls.jsonl").read_text().splitlines()]


def test_systemd_units(systemd):
    from xvm_control import units

    s, out, state = systemd
    assert s.backend() == "systemd"
    assert s.up("scn-a", None) == "no msi given; the drive is used as it is"
    unit = units.unit_name(s.root, "scn-a")
    run = next(c for c in _calls(state) if c[0] == "systemd-run")
    scope = [] if os.geteuid() == 0 else ["--user"]
    assert run[1 : 2 + len(scope)] == [*scope, f"--unit={unit}"]
    props = [run[i + 1] for i, a in enumerate(run) if a == "--property"]
    assert {
        "Restart=on-failure",
        "StartLimitIntervalSec=0",
        "KillSignal=SIGTERM",
        "TimeoutStopSec=30",
        "RestartSteps=6",
        "RestartMaxDelaySec=60",
    } <= set(props)
    assert f"StandardOutput=append:{s.host_dir('scn-a') / 'host.log'}" in props
    assert run[run.index("--") + 1 :] == [os.environ["XVM_RUNNER"], *s.runner_args("scn-a")]
    # No supervisor process of ours: systemd owns the agent.
    st = wait_for(lambda: (x := s.status("scn-a"))["state"] == "running" and x)
    assert st["supervisor"] == "systemd" and st["pid"] and st["unit"] == unit
    assert s.supervisor_pid("scn-a") is None
    assert s.up("scn-a", None) == "already up"
    assert s.down("scn-a") is True
    assert (out / "stopped").read_text() == "SIGTERM"
    assert s.status("scn-a")["state"] == "stopped"
    assert s.down("scn-a") is False


def test_systemd_clean_exit_and_fallback(systemd, monkeypatch):
    s, out, state = systemd
    monkeypatch.setenv("FAKE_MODE", "exit0")
    s.up("scn-b", None)
    assert wait_for(lambda: s.status("scn-b")["state"] == "exited")
    # Asked for systemd where it does not run: a clear error, not a silent switch.
    monkeypatch.delenv("XVM_SUPERVISOR_SYSTEMD")
    monkeypatch.setattr("xvm_control.units.available", lambda: False)
    with pytest.raises(hostctl.HostError, match="systemd is not running"):
        s.up("scn-a", None)
    s.supervisor = "auto"
    assert s.backend() == "python"
