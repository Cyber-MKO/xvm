"""The real Wazuh agent enrolls through the Windows personality (T2's first step).

Runs only with the agent's MSI: set XVM_WAZUH_MSI to wazuh-agent-4.14.2-1.msi.
It needs the built binaries (`cargo build --release -p xvm-engine --bin
xvm-engined` and `cargo build --release -p xvm-windows --bin xvm-windows-run
--target i686-unknown-linux-gnu`), or XVM_ENGINED and XVM_RUNNER. The
`enrollment` workflow runs it on GitHub's runners.

The host is `xvm-win-01` on the golden base with its manager set to
127.0.0.1, where `xvm-mock-authd` answers on port 1515. The test passes when
the agent writes the key the mock issued to its `client.keys`.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import time
from pathlib import Path

import pytest

from xvm_control import hostctl
from xvm_control.mockauthd import MockAuthd

ROOT = Path(__file__).resolve().parents[2]
PROFILES = ROOT / "control" / "profiles"
HOST = "xvm-win-01"
MSI = os.environ.get("XVM_WAZUH_MSI")
TIMEOUT = float(os.environ.get("XVM_ENROLL_TIMEOUT", "300"))

pytestmark = pytest.mark.skipif(not MSI, reason="XVM_WAZUH_MSI is not set")


def _port_free(port: int) -> bool:
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _tail(path: Path, n: int = 60) -> str:
    if not path.exists():
        return f"({path.name} missing)"
    return "\n".join(path.read_text(errors="replace").splitlines()[-n:])


def test_agent_enrolls_with_the_mock_manager(tmp_path):
    for find in (hostctl.engined_binary, hostctl.runner_binary):
        try:
            find()
        except hostctl.HostError as e:
            pytest.fail(str(e))
    if not _port_free(1515):
        pytest.skip("port 1515 is taken here")

    hosts = tmp_path / "hosts"
    hosts.mkdir()
    profile = (PROFILES / "hosts" / f"{HOST}.yaml").read_text()
    profile, n = re.subn(r"(?m)^(  manager: ).*$", r"\g<1>127.0.0.1", profile)
    assert n == 1, "the host profile has no agent.manager line"
    (hosts / f"{HOST}.yaml").write_text(profile)

    out = Path(os.environ.get("XVM_ENROLL_OUT", tmp_path / "out"))
    out.mkdir(parents=True, exist_ok=True)
    authd = MockAuthd(port=1515, log=out / "authd.jsonl")
    authd.start()
    site = hostctl.Site(out / "run", [PROFILES / "bases"], hosts, supervisor="python")
    site.save()
    agent_dir = site.drive(HOST) / "Program Files (x86)" / "ossec-agent"
    keys = agent_dir / "client.keys"
    try:
        site.up(HOST, Path(MSI))
        conf = (agent_dir / "ossec.conf").read_text(errors="replace")
        assert "<address>127.0.0.1</address>" in conf
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            if keys.exists() and keys.stat().st_size > 0 and authd.agents:
                break
            time.sleep(1)
        diag = (
            f"mock requests: {json.dumps(authd.requests, indent=1)}\n"
            f"--- host.log\n{_tail(site.host_dir(HOST) / 'host.log')}\n"
            f"--- ossec.log\n{_tail(agent_dir / 'ossec.log')}"
        )
        assert authd.agents, f"no enrollment reached the mock in {TIMEOUT:.0f} s\n{diag}"
        issued = next(r["issued"] for r in authd.requests if "issued" in r)
        assert keys.exists(), f"the agent did not write client.keys\n{diag}"
        assert keys.read_text().strip() == issued, diag
        request = next(r for r in authd.requests if "issued" in r)
        assert request["name"] == "XVM-WIN-01"
        assert request["version"] == "v4.14.2"
        assert request["tls"].startswith("TLSv1.")
    finally:
        site.down(HOST, timeout=40)
        site.stop_engine(force=True)
        authd.stop()
        log = agent_dir / "ossec.log"
        if log.exists():
            shutil.copy(log, out / "ossec.log")
