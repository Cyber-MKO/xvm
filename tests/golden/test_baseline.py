import hashlib
import json
import shutil
import subprocess

import pytest

from xvm_golden import baseline, cli

STEPS = baseline.REQUIRED_STEPS


def _make_baseline(root, bom=True):
    """Build a capture directory shaped like capture.ps1 output."""
    files = []
    for rel in baseline.REQUIRED_FILES:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(f"fake {rel}".encode())
        files.append(
            {
                "path": rel,
                "size": p.stat().st_size,
                "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            }
        )
    steps = [
        {
            "name": n,
            "start": f"2026-10-16T10:00:{i * 5:02d}.000Z",
            "end": f"2026-10-16T10:00:{i * 5 + 4:02d}.000Z",
            "expect": "x",
        }
        for i, n in enumerate(STEPS)
    ]
    manifest = {
        "schema": 1,
        "kind": "windows-golden-baseline",
        "scenario": {
            "start": "2026-10-16T10:00:00.000Z",
            "end": "2026-10-16T10:01:00.000Z",
            "steps": steps,
        },
        "warnings": [],
        "files": files,
    }
    text = json.dumps(manifest)
    (root / "manifest.json").write_text(("﻿" if bom else "") + text, encoding="utf-8")
    return root


def test_valid_baseline(tmp_path):
    assert baseline.verify(_make_baseline(tmp_path)) == []


def test_hash_mismatch(tmp_path):
    root = _make_baseline(tmp_path)
    (root / "host/os.json").write_text("tampered")
    assert baseline.verify(root) == ["hash mismatch: host/os.json"]


def test_missing_step_and_file(tmp_path):
    root = _make_baseline(tmp_path)
    m = baseline.load_manifest(root)
    m["scenario"]["steps"] = [s for s in m["scenario"]["steps"] if s["name"] != "fim_change"]
    m["files"] = [f for f in m["files"] if f["path"] != "wazuh/ossec.conf"]
    (root / "manifest.json").write_text(json.dumps(m))
    problems = baseline.verify(root)
    assert "scenario step missing: fim_change" in problems
    assert "required file missing from manifest: wazuh/ossec.conf" in problems


def test_client_keys_rejected(tmp_path):
    root = _make_baseline(tmp_path)
    (root / "wazuh/client.keys").write_text("001 agent any key")
    assert "secret must not be stored: wazuh/client.keys" in baseline.verify(root)


def test_step_outside_window(tmp_path):
    root = _make_baseline(tmp_path)
    m = baseline.load_manifest(root)
    m["scenario"]["steps"][0]["start"] = "2026-10-16T09:59:00.000Z"
    (root / "manifest.json").write_text(json.dumps(m))
    assert "step marker_start lies outside the scenario window" in baseline.verify(root)


def test_wazuh_timestamp_format():
    a = baseline.parse_time("2026-10-16T10:00:30.123+0000")
    b = baseline.parse_time("2026-10-16T10:00:30.123Z")
    assert a == b


def _ndjson(path, timestamps):
    path.write_text(
        "".join(
            json.dumps({"timestamp": t, "agent": {"name": "golden"}}) + "\n" for t in timestamps
        )
    )


def test_import_manager_windows_events(tmp_path):
    root = _make_baseline(tmp_path / "b")
    archives, alerts = tmp_path / "archives.json", tmp_path / "alerts.json"
    _ndjson(
        archives,
        [
            "2026-10-16T09:50:00.000+0000",  # before window and margin
            "2026-10-16T09:58:30.000+0000",  # inside the 2 minute margin
            "2026-10-16T10:00:30.000+0000",
            "2026-10-16T10:05:00.000+0000",
        ],
    )  # after window and margin
    _ndjson(alerts, ["2026-10-16T10:00:40.000+0000"])
    rc = cli.main(
        ["import-manager", str(root), "--archives", str(archives), "--alerts", str(alerts)]
    )
    assert rc == 0
    m = baseline.load_manifest(root)
    assert m["manager"]["counts"] == {"archives": 2, "alerts": 1}
    assert len((root / "manager/archives.json").read_text().splitlines()) == 2
    assert baseline.verify(root) == []
    # Importing again replaces the manager files instead of listing them twice.
    cli.main(["import-manager", str(root), "--archives", str(archives), "--alerts", str(alerts)])
    paths = [f["path"] for f in baseline.load_manifest(root)["files"]]
    assert paths.count("manager/archives.json") == 1


def test_manager_capture_script(tmp_path):
    if shutil.which("jq") is None:
        pytest.skip("jq not installed")
    ossec = tmp_path / "ossec"
    (ossec / "etc").mkdir(parents=True)
    (ossec / "logs/archives").mkdir(parents=True)
    (ossec / "logs/alerts").mkdir(parents=True)
    (ossec / "etc/ossec.conf").write_text(
        "<ossec_config><global><logall_json>yes</logall_json></global></ossec_config>"
    )
    lines = [
        {"timestamp": "2026-10-16T10:00:30.000+0000", "agent": {"name": n}}
        for n in ("golden", "other", "golden")
    ]
    (ossec / "logs/archives/archives.json").write_text("".join(json.dumps(x) + "\n" for x in lines))
    (ossec / "logs/alerts/alerts.json").write_text(json.dumps(lines[1]) + "\n")
    script = baseline.Path(__file__).parents[2] / "scenarios/golden/windows/manager-capture.sh"
    out = tmp_path / "out"
    subprocess.run(
        ["sh", str(script), "golden", str(out)],
        check=True,
        capture_output=True,
        env={"OSSEC_DIR": str(ossec), "PATH": "/usr/bin:/bin"},
    )
    assert len((out / "archives.json").read_text().splitlines()) == 2
    assert (out / "alerts.json").read_text() == ""


def test_manager_capture_requires_logall_json(tmp_path):
    if shutil.which("jq") is None:
        pytest.skip("jq not installed")
    ossec = tmp_path / "ossec"
    (ossec / "etc").mkdir(parents=True)
    (ossec / "etc/ossec.conf").write_text("<ossec_config></ossec_config>")
    script = baseline.Path(__file__).parents[2] / "scenarios/golden/windows/manager-capture.sh"
    r = subprocess.run(
        ["sh", str(script), "golden", str(tmp_path / "out")],
        capture_output=True,
        env={"OSSEC_DIR": str(ossec), "PATH": "/usr/bin:/bin"},
    )
    assert r.returncode == 1
    assert b"logall_json" in r.stderr
