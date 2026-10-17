"""Host lifecycle: start, stop, reset and watch emulated hosts.

One run folder (`--root`) holds everything a set of hosts needs:

| Path | Holds |
| --- | --- |
| `compiled/` | Profiles compiled for the engine |
| `state/` | The engine's saved run-time state |
| `engine.sock`, `engine.pid`, `engine.log`, `gaps.jsonl` | The engine daemon |
| `hosts/NAME/drive-c/` | The host's C: drive, filled by the MSI installer step |
| `hosts/NAME/installed.json` | Which MSI was installed, so `up` installs once |
| `hosts/NAME/supervisor.pid` | The host's supervisor |
| `hosts/NAME/status.json`, `host.log` | The host's state, and the agent's output |

Each host runs under its own supervisor process. The supervisor starts
`xvm-windows-run`, restarts it when it fails (with backoff), and on SIGTERM
passes the signal on so the agent stops through its own service handler.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from . import profile

ROOT = Path(__file__).resolve().parents[2]
STOP_GRACE_S = 30.0
BACKOFF_MAX_S = 60.0


class HostError(Exception):
    pass


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # A zombie child still answers kill(0); reap it if it is ours.
    try:
        done, _ = os.waitpid(pid, os.WNOHANG)
        return done == 0
    except ChildProcessError:
        return True


def _read_pid(path: Path) -> int | None:
    try:
        pid = int(path.read_text().strip())
    except (OSError, ValueError):
        return None
    return pid if _alive(pid) else None


def _write_json(path: Path, data: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    tmp.replace(path)


def find_binary(name: str, env: str, candidates: list[str]) -> Path:
    """A binary from its environment variable, else the first build that exists."""
    if os.environ.get(env):
        return Path(os.environ[env])
    for c in candidates:
        p = ROOT / c
        if p.is_file():
            return p
    found = shutil.which(name)
    if found:
        return Path(found)
    raise HostError(f"{name} not found: build it, or set {env}")


def engined_binary() -> Path:
    return find_binary(
        "xvm-engined",
        "XVM_ENGINED",
        ["target/release/xvm-engined", "target/debug/xvm-engined"],
    )


def runner_binary() -> Path:
    return find_binary(
        "xvm-windows-run",
        "XVM_RUNNER",
        [
            "target/i686-unknown-linux-gnu/release/xvm-windows-run",
            "target/i686-unknown-linux-gnu/debug/xvm-windows-run",
        ],
    )


@dataclass
class Site:
    """One run folder and the profiles it serves."""

    root: Path
    bases: list[Path]
    hosts_dir: Path
    # A golden capture whose recent events fill each host's logs on first start.
    corpus: Path | None = None

    @property
    def socket(self) -> Path:
        return self.root / "engine.sock"

    def save(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        _write_json(
            self.root / "site.json",
            {
                "bases": [str(b.resolve()) for b in self.bases],
                "hosts": str(self.hosts_dir.resolve()),
                "corpus": str(self.corpus.resolve()) if self.corpus else None,
            },
        )

    @classmethod
    def open(
        cls,
        root: Path,
        bases: list[Path] | None = None,
        hosts_dir: Path | None = None,
        corpus: Path | None = None,
    ) -> Site:
        """The site at root. Profile folders given here win over the saved ones."""
        saved = {}
        if (root / "site.json").exists():
            saved = json.loads((root / "site.json").read_text())
        b = bases or [Path(x) for x in saved.get("bases", [])]
        h = hosts_dir or (Path(saved["hosts"]) if saved.get("hosts") else None)
        if not b or h is None:
            raise HostError(f"{root}: no profile folders yet; pass --bases and --hosts")
        c = corpus or (Path(saved["corpus"]) if saved.get("corpus") else None)
        return cls(root, b, h, c)

    def host_dir(self, name: str) -> Path:
        return self.root / "hosts" / name

    def drive(self, name: str) -> Path:
        return self.host_dir(name) / "drive-c"

    def profile_path(self, name: str) -> Path:
        for ext in (".yaml", ".yml"):
            p = self.hosts_dir / f"{name}{ext}"
            if p.is_file():
                return p
        raise HostError(f"no host profile {name} in {self.hosts_dir}")

    def resolved(self, name: str) -> dict:
        return profile.resolve_file(self.profile_path(name), self.bases)

    # ------------------------------------------------------------ engine

    def engine_pid(self) -> int | None:
        return _read_pid(self.root / "engine.pid")

    def compile(self) -> str:
        """Compile every profile; returns a digest of the result."""
        out = self.root / "compiled"
        if out.exists():
            shutil.rmtree(out)
        profile.compile_tree(self.bases, [self.hosts_dir], out)
        h = hashlib.sha256()
        for p in sorted(out.rglob("*.json")):
            h.update(p.relative_to(out).as_posix().encode() + b"\0" + p.read_bytes())
        return h.hexdigest()

    def start_engine(self, timeout: float = 15.0) -> int:
        """Start the engine on freshly compiled profiles, unless it already runs."""
        pid = self.engine_pid()
        if pid:
            return pid
        self.root.mkdir(parents=True, exist_ok=True)
        digest = self.compile()
        self.socket.unlink(missing_ok=True)
        log = (self.root / "engine.log").open("ab")
        proc = subprocess.Popen(
            [
                str(engined_binary()),
                "--compiled",
                str(self.root / "compiled"),
                "--socket",
                str(self.socket),
                "--state",
                str(self.root / "state"),
                "--gap-log",
                str(self.root / "gaps.jsonl"),
            ],
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
        (self.root / "engine.pid").write_text(f"{proc.pid}\n")
        _write_json(
            self.root / "engine.json", {"pid": proc.pid, "compiled": digest, "started": _now()}
        )
        deadline = time.monotonic() + timeout
        while not self.socket.exists():
            if proc.poll() is not None or time.monotonic() > deadline:
                proc.kill()
                raise HostError(f"xvm-engined did not start; see {self.root / 'engine.log'}")
            time.sleep(0.05)
        return proc.pid

    def stop_engine(self, force: bool = False) -> bool:
        running = [h for h in self.hosts() if self.supervisor_pid(h)]
        if running and not force:
            raise HostError(f"hosts still up: {', '.join(running)}; stop them or use --force")
        pid = self.engine_pid()
        if not pid:
            return False
        _stop(pid, STOP_GRACE_S)
        self.socket.unlink(missing_ok=True)
        return True

    # ------------------------------------------------------------ hosts

    def hosts(self) -> list[str]:
        d = self.root / "hosts"
        return sorted(p.name for p in d.iterdir() if p.is_dir()) if d.is_dir() else []

    def supervisor_pid(self, name: str) -> int | None:
        return _read_pid(self.host_dir(name) / "supervisor.pid")

    def install(self, name: str, msi: Path | None) -> str:
        """Install the agent onto the host's drive once per MSI. Returns what happened."""
        drive = self.drive(name)
        drive.mkdir(parents=True, exist_ok=True)
        if msi is None:
            return "no msi given; the drive is used as it is"
        digest = hashlib.sha256(msi.read_bytes()).hexdigest()
        marker = self.host_dir(name) / "installed.json"
        if marker.exists() and json.loads(marker.read_text()).get("sha256") == digest:
            return "already installed"
        host = self.resolved(name)
        env = (host.get("agent") or {}).get("environment") or {}
        program_files = env.get("ProgramFiles")
        if not program_files:
            raise HostError(f"{name}: agent.environment.ProgramFiles is not set")
        from xvm_msi.install import install  # the installer step lives with the personality

        result = install(msi, {"C": drive}, host, program_files)
        log = self.host_dir(name) / "host.log"
        with log.open("a") as f:
            for gap in result.gaps:
                f.write(f"{_now()} gap msi {gap}\n")
        _write_json(
            marker,
            {
                "msi": str(msi),
                "sha256": digest,
                "installed": _now(),
                "files": result.files,
                "gaps": len(result.gaps),
            },
        )
        return f"installed {result.files} files, {len(result.gaps)} gaps"

    def up(self, name: str, msi: Path | None) -> str:
        if self.supervisor_pid(name):
            return "already up"
        self.profile_path(name)
        self.start_engine()
        note = self.install(name, msi)
        if self.corpus:
            note += "; " + self.seed(name)
        hd = self.host_dir(name)
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "xvm_control.hostctl",
                "supervise",
                name,
                "--root",
                str(self.root),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=(hd / "supervisor.log").open("ab"),
            start_new_session=True,
            # The supervisor imports this package the way this process did.
            env={
                **os.environ,
                "PYTHONPATH": os.pathsep.join(str(Path(p).resolve()) for p in sys.path if p),
            },
        )
        (hd / "supervisor.pid").write_text(f"{proc.pid}\n")
        return note

    def down(self, name: str, timeout: float = STOP_GRACE_S + 5) -> bool:
        pid = self.supervisor_pid(name)
        if not pid:
            return False
        _stop(pid, timeout)
        return True

    def reset(self, name: str, msi: Path | None) -> str:
        """Return a stopped host to its profile: engine state, and a fresh install."""
        if self.supervisor_pid(name):
            raise HostError(f"{name} is up; stop it first")
        if self.engine_pid():
            from xvm_scenario.engine import Engine  # the Python engine client

            e = Engine(self.socket, name)
            try:
                e.call("reset")
            finally:
                e.close()
        shutil.rmtree(self.drive(name), ignore_errors=True)
        (self.host_dir(name) / "installed.json").unlink(missing_ok=True)
        # The engine reset emptied the logs, so the next up fills them again.
        (self.host_dir(name) / "seeded.json").unlink(missing_ok=True)
        return self.install(name, msi)

    def seed(self, name: str) -> str:
        """Fill a new host's event logs with the corpus's recent events, once.

        A real host has a history in its logs when an agent first reads them.
        The capture's newest events (`evtx/rendered/`) are replayed with their
        own spacing, rewritten to name this host, and shifted so the last one
        lands now. The replay log is `hosts/NAME/seed.jsonl`.
        """
        marker = self.host_dir(name) / "seeded.json"
        if marker.exists():
            return "logs already seeded"
        from xvm_scenario import replay
        from xvm_scenario.corpus import Capture
        from xvm_scenario.runner import RunLog, run

        sc, notes = replay.scenario(Capture.load(self.corpus), "recent")
        if not sc.steps:
            return "corpus has no recent events; logs left empty"
        span = sc.steps[-1].offset
        start = datetime.now(UTC) - timedelta(seconds=span)
        log = RunLog(self.host_dir(name) / "seed.jsonl")
        try:
            run(sc, self.socket, [name], start=start, speed=0, seed=name, log=log)
        finally:
            log.close()
        _write_json(
            marker,
            {
                "corpus": str(self.corpus),
                "events": len(sc.steps),
                "failed": log.errors,
                "gaps": log.gaps,
                "notes": notes,
                "seeded": _now(),
            },
        )
        return f"seeded {len(sc.steps) - log.errors} events ({log.gaps} gaps)"

    def status(self, name: str) -> dict:
        st_path = self.host_dir(name) / "status.json"
        st = json.loads(st_path.read_text()) if st_path.exists() else {}
        st["supervisor"] = self.supervisor_pid(name)
        if not st["supervisor"] and st.get("state") not in (None, "stopped", "exited"):
            st["state"] = "dead"  # the supervisor itself is gone
        for k, v in (("state", "down"), ("starts", 0), ("restarts", 0), ("pid", None)):
            st.setdefault(k, v)
        return st


def _stop(pid: int, timeout: float) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + timeout
    while _alive(pid):
        if time.monotonic() > deadline:
            os.kill(pid, signal.SIGKILL)
            break
        time.sleep(0.05)


# ---------------------------------------------------------------- supervisor


def supervise(site: Site, name: str) -> int:
    """Run the host's agent until told to stop; restart it when it fails."""
    hd = site.host_dir(name)
    status_path = hd / "status.json"
    st = {
        "host": name,
        "state": "starting",
        "pid": None,
        "starts": 0,
        "restarts": 0,
        "since": _now(),
        "last_exit": None,
        "supervisor_started": _now(),
    }
    stopping = False
    child: subprocess.Popen | None = None

    def on_term(signum, frame):
        nonlocal stopping
        stopping = True
        if child and child.poll() is None:
            child.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)
    backoff = 1.0
    log = (hd / "host.log").open("ab")
    try:
        runner = runner_binary()
    except HostError as e:
        st.update(state="failed", last_exit={"error": str(e), "time": _now()})
        _write_json(status_path, st)
        (hd / "supervisor.pid").unlink(missing_ok=True)
        return 1
    while not stopping:
        log.write(f"{_now()} supervisor: starting {name}\n".encode())
        log.flush()
        started = time.monotonic()
        child = subprocess.Popen(
            [
                str(runner),
                "--engine",
                str(site.socket),
                "--host",
                name,
                "--drive",
                f"C={site.drive(name)}",
            ],
            stdout=log,
            stderr=log,
            stdin=subprocess.DEVNULL,
        )
        st.update(state="running", pid=child.pid, starts=st["starts"] + 1, since=_now())
        _write_json(status_path, st)
        if stopping:  # a stop that came while starting
            child.send_signal(signal.SIGTERM)
        code = child.wait()
        st["last_exit"] = {
            "code": code,
            "time": _now(),
            "ran_s": round(time.monotonic() - started, 3),
        }
        st["pid"] = None
        if stopping:
            break
        if code == 0:
            # The agent ended on its own, as a stopped service does. Not a failure.
            st.update(state="exited", since=_now())
            _write_json(status_path, st)
            (hd / "supervisor.pid").unlink(missing_ok=True)
            return 0
        # A failure: restart, backing off while it keeps failing fast.
        if time.monotonic() - started > 60:
            backoff = 1.0
        st.update(state="restarting", restarts=st["restarts"] + 1, since=_now())
        _write_json(status_path, st)
        log.write(
            f"{_now()} supervisor: {name} exited with {code}; restarting in {backoff:g}s\n".encode()
        )
        log.flush()
        deadline = time.monotonic() + backoff
        while not stopping and time.monotonic() < deadline:
            time.sleep(0.05)
        backoff = min(backoff * 2, BACKOFF_MAX_S)
    st.update(state="stopped", since=_now())
    _write_json(status_path, st)
    log.write(f"{_now()} supervisor: {name} stopped\n".encode())
    (hd / "supervisor.pid").unlink(missing_ok=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    # Only the supervisor runs here; the user-facing commands are in hostcli.
    import argparse

    ap = argparse.ArgumentParser(prog="xvm_control.hostctl")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("supervise")
    s.add_argument("name")
    s.add_argument("--root", type=Path, required=True)
    args = ap.parse_args(argv)
    return supervise(Site.open(args.root), args.name)


if __name__ == "__main__":
    sys.exit(main())
