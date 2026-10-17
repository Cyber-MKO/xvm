"""xvm-host: the engine, installs, supervisors, restarts and resets, with a fake runner."""

from __future__ import annotations

import json
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
