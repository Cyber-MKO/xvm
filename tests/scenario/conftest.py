"""A real xvm-engined serving the scenario test profiles."""

from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from xvm_control import profile

ROOT = Path(__file__).resolve().parents[2]
PROFILES = Path(__file__).parent / "profiles"


@pytest.fixture(scope="session")
def engined() -> Path:
    if shutil.which("cargo") is None:
        pytest.skip("cargo is not installed")
    subprocess.run(
        ["cargo", "build", "-q", "-p", "xvm-engine", "--bin", "xvm-engined"],
        cwd=ROOT,
        check=True,
    )
    return ROOT / "target" / "debug" / "xvm-engined"


@pytest.fixture
def engine(engined: Path, tmp_path: Path):
    """A fresh daemon per test. Yields its socket path."""
    compiled = tmp_path / "compiled"
    profile.compile_tree([PROFILES / "bases"], [PROFILES / "hosts"], compiled)
    sock = tmp_path / "engine.sock"
    proc = subprocess.Popen(
        [
            str(engined),
            "--compiled",
            str(compiled),
            "--socket",
            str(sock),
            "--gap-log",
            str(tmp_path / "gaps.jsonl"),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10
    while not sock.exists():
        if proc.poll() is not None or time.monotonic() > deadline:
            proc.kill()
            raise RuntimeError(f"xvm-engined did not start: {proc.stderr.read().decode()}")
        time.sleep(0.02)
    yield sock
    proc.terminate()
    proc.wait(timeout=10)
