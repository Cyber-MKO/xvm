"""Manager-side checks: fidelity, T6 detection parity, T5 delivery."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from xvm_golden import cli, fidelity

GOLDEN_SID = "S-1-5-21-7-8-9"
OUR_SID = "S-1-5-21-1111-2222-3333"


def archive(
    computer, sid, record_id, event_id=4720, agent="golden", logon="0x3e7", pid=640, **extra
):
    """One archived Windows event, in the windows_eventchannel decoder's shape."""
    system = {
        "providerName": "Microsoft-Windows-Security-Auditing",
        "providerGuid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
        "eventID": str(event_id),
        "version": "0",
        "level": "0",
        "task": "13824",
        "opcode": "0",
        "keywords": "0x8020000000000000",
        "systemTime": f"2026-10-16T10:00:0{record_id % 10}.1234567Z",
        "eventRecordID": str(record_id),
        "processID": str(pid),
        "threadID": "4",
        "channel": "Security",
        "computer": computer,
        "severityValue": "AUDIT_SUCCESS",
        "message": f'"A user account was created.\r\n\tAccount Domain:\t\t{computer}"',
    }
    return {
        "timestamp": f"2026-10-16T10:00:1{record_id % 10}.000+0000",
        "id": f"1697000{record_id}",
        "agent": {"id": "001" if agent == "golden" else "007", "name": agent, "ip": "192.0.2.9"},
        "manager": {"name": "wazuh-manager"},
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
        "full_log": "{...}",
        "data": {
            "win": {
                "system": system,
                "eventdata": {
                    "targetUserName": "xvmgolden",
                    "targetDomainName": computer,
                    "targetSid": f"{sid}-1001",
                    "subjectLogonId": logon,
                },
            }
        },
        **extra,
    }


def alert(event, rule):
    return {**event, "rule": {"id": rule, "level": 8, "firedtimes": 1}}


def write_ndjson(path: Path, rows) -> Path:
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    return path


def golden_dir(tmp_path: Path, archives, alerts) -> Path:
    root = tmp_path / "golden"
    (root / "manager").mkdir(parents=True)
    (root / "host").mkdir()
    (root / "manifest.json").write_text(json.dumps({"host": {"name": "GOLDEN-VM"}}))
    (root / "host" / "users.json").write_text(
        json.dumps([{"Name": "a", "SID": GOLDEN_SID + "-500"}])
    )
    (root / "host" / "processes.json").write_text(
        json.dumps([{"ProcessId": 640, "Name": "lsass.exe"}])
    )
    write_ndjson(root / "manager" / "archives.json", archives)
    write_ndjson(root / "manager" / "alerts.json", alerts)
    return root


def run_log(tmp_path: Path, record_ids, host="scn-a") -> Path:
    rows = [
        {
            "record": "start",
            "hosts": {
                host: {
                    "skew_s": 0,
                    "identity": {
                        "computer": "SCN-A",
                        "machine_sid": OUR_SID,
                        "processes": {"8": "lsass.exe"},
                    },
                }
            },
        }
    ]
    for i, rid in enumerate(record_ids, start=1):
        rows.append(
            {
                "record": "call",
                "host": host,
                "step": i,
                "op": "evt.write",
                "params": {"channel": "Security", "event": {}},
                "result": {"channel": "Security", "record_id": rid},
            }
        )
        rows.append({"record": "step", "host": host, "step": i, "name": "user_create", "ok": True})
    return write_ndjson(tmp_path / "run.jsonl", rows)


@pytest.fixture
def setup(tmp_path):
    golden = [archive("GOLDEN-VM", GOLDEN_SID, 101), archive("GOLDEN-VM", GOLDEN_SID, 102)]
    noise = archive("GOLDEN-VM", GOLDEN_SID, 103, event_id=4672)
    fim = {
        "timestamp": "x",
        "agent": {"name": "golden"},
        "location": "syscheck",
        "decoder": {"name": "syscheck_new_entry"},
    }
    ours = [
        archive("SCN-A", OUR_SID, 1, agent="emu", logon="0x1a2b3", pid=8),
        archive("SCN-A", OUR_SID, 2, agent="emu", logon="0x1a2b4", pid=8),
    ]
    g_dir = golden_dir(tmp_path, [*golden, noise, fim], [alert(golden[0], "60109")])
    return tmp_path, g_dir, ours


def _check(tmp_path, g_dir, ours, ours_alerts, record_ids=(1, 2)):
    return fidelity.diff_manager(
        g_dir,
        write_ndjson(tmp_path / "a.json", ours),
        write_ndjson(tmp_path / "al.json", ours_alerts),
        run_log(tmp_path, record_ids),
    )


def test_identity_differences_pass(setup):
    tmp_path, g_dir, ours = setup
    r = _check(tmp_path, g_dir, ours, [alert(ours[0], "60109")])
    assert r.errors == 0, r.text()
    # Background events Windows wrote that the emulated run did not are warnings.
    assert {(f.check, f.subject) for f in r.findings} == {
        ("fidelity", "Security Microsoft-Windows-Security-Auditing 4672"),
        ("fidelity", "syscheck syscheck_new_entry"),
    }
    assert r.counts["delivery"] == {"written": 2, "arrived_once": 2, "other_events": 0}
    assert r.counts["archives"]["paired"] == 2


@pytest.mark.parametrize(
    "change, expect",
    [
        (lambda e: e["data"]["win"]["system"].update(task="12544"), "data.win.system.task"),
        (
            lambda e: e["data"]["win"]["system"].update(message='"Other text"'),
            "data.win.system.message",
        ),
        (lambda e: e["data"]["win"]["eventdata"].update(extra="1"), "eventdata.extra extra"),
        (lambda e: e["data"]["win"]["eventdata"].pop("targetSid"), "targetSid missing"),
        (
            lambda e: e["data"]["win"]["eventdata"].update(subjectLogonId="-"),
            "subjectLogonId: Windows hex",
        ),
        (
            lambda e: e["data"]["win"]["eventdata"].update(targetDomainName="GOLDEN-VM"),
            "targetDomainName: Windows '{computer}', ours 'GOLDEN-VM'",
        ),
    ],
)
def test_field_differences_are_errors(setup, change, expect):
    tmp_path, g_dir, ours = setup
    ours = copy.deepcopy(ours)
    change(ours[0])
    r = _check(tmp_path, g_dir, ours, [alert(ours[0], "60109")])
    assert any(
        f.check == "fidelity" and f.severity == "error" and expect in f.text for f in r.findings
    ), r.text()


def test_extra_windows_events_are_errors(setup):
    tmp_path, g_dir, ours = setup
    extra = archive("SCN-A", OUR_SID, 3, event_id=4726, agent="emu")
    r = _check(tmp_path, g_dir, [*ours, extra], [alert(ours[0], "60109")], (1, 2, 3))
    assert ("Security Microsoft-Windows-Security-Auditing 4726", "golden 0, ours 1") in {
        (f.subject, f.text) for f in r.findings if f.severity == "error"
    }


def test_detection_parity(setup):
    tmp_path, g_dir, ours = setup
    r = _check(
        tmp_path,
        g_dir,
        ours,
        [alert(ours[0], "60109"), alert(ours[1], "60109"), alert(ours[1], "18107")],
    )
    t6 = sorted((f.subject, f.text) for f in r.findings if f.check == "t6")
    assert t6 == [("rule 18107", "golden 0, ours 1"), ("rule 60109", "golden 1, ours 2")]


def test_delivery_exactly_once(setup):
    tmp_path, g_dir, ours = setup
    # Record 1 arrives twice, record 3 never, record 2 once.
    r = _check(tmp_path, g_dir, [ours[0], *ours], [alert(ours[0], "60109")], (1, 2, 3))
    t5 = sorted((f.subject, f.text) for f in r.findings if f.check == "t5")
    assert t5 == [("security record 1", "arrived 2 times"), ("security record 3", "missing")]


def test_cli(setup, capsys):
    tmp_path, g_dir, ours = setup
    a = write_ndjson(tmp_path / "a.json", [*ours, archive("X", OUR_SID, 9, agent="other")])
    al = write_ndjson(tmp_path / "al.json", [alert(ours[0], "60109")])
    log = run_log(tmp_path, (1, 2))
    args = ["--archives", str(a), "--run-log", str(log), "--agent", "emu"]
    assert (
        cli.main(
            [
                "diff-manager",
                str(g_dir),
                "--alerts",
                str(al),
                *args,
                "--json",
                str(tmp_path / "r.json"),
            ]
        )
        == 0
    )
    assert json.loads((tmp_path / "r.json").read_text())["errors"] == 0
    assert cli.main(["delivery", *args]) == 0
    assert "arrived_once" in capsys.readouterr().out
    assert (
        cli.main(["delivery", "--archives", str(a), "--run-log", str(log), "--host", "nobody"]) == 2
    )
