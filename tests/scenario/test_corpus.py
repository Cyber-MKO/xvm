"""Golden corpus: parsing, identity rewriting, replay, and the event-layout diff."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from xvm_scenario import layout, replay
from xvm_scenario.cli import main
from xvm_scenario.corpus import Capture, Identity, parse_events, rewrite
from xvm_scenario.engine import Engine
from xvm_scenario.runner import RunLog, load, run

from .capture import GOLDEN, NS, build, event_xml

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_SCENARIO = ROOT / "scenarios" / "library" / "golden-windows.yaml"
START = datetime(2026, 10, 17, 10, 0, tzinfo=UTC)


def _golden_run(sock, tmp_path) -> Path:
    log_path = tmp_path / "golden-run.jsonl"
    log = RunLog(log_path)
    run(load(GOLDEN_SCENARIO), sock, ["scn-a"], start=START, speed=0, log=log)
    log.close()
    return log_path


def _events(sock, host, channel):
    e = Engine(sock, host)
    try:
        return e.call("evt.query", channel=channel, format="json", limit=1000)["events"]
    finally:
        e.close()


# ---------------------------------------------------------------- parsing


def test_parse_rendered_events():
    e = {
        "provider": "Service Control Manager",
        "provider_guid": "{555908d1-a6d7-4695-8e1e-26931d2012f4}",
        "event_source": "Service Control Manager",
        "event_id": 7036,
        "qualifiers": 16384,
        "version": 0,
        "level": 4,
        "keywords": "0x8080000000000000",
        "time": "2026-10-16T10:00:00.1234567Z",
        "process_id": 700,
        "thread_id": 12,
        "data": [{"name": "param1", "value": "Windows Time"}, {"value": "x & y"}],
        "message": "The Windows Time service entered the stopped state.\nLine two",
    }
    user_data = (
        f"<Event xmlns='{NS}'><System><Provider Name='P'/><EventID>1102</EventID></System>"
        "<UserData><LogFileCleared/></UserData></Event>"
    )
    text = "﻿<Events>" + event_xml(e, "System") + user_data + "</Events>"
    (got,), notes = parse_events(text)
    assert got["event_id"] == 7036 and got["qualifiers"] == 16384
    assert got["event_source"] == "Service Control Manager"
    assert got["channel"] == "System"
    assert (got["process_id"], got["thread_id"]) == (700, 12)
    assert got["data"] == [{"name": "param1", "value": "Windows Time"}, {"value": "x & y"}]
    assert got["message"] == "The Windows Time service entered the stopped state.\r\nLine two"
    assert notes == ["P 1102: UserData event skipped"]
    assert parse_events("<Events><broken")[1][0].startswith("events unreadable")


def test_identity_rewrites_whole_names_only():
    ours = Identity("SCN-A", "S-1-5-21-1111-2222-3333", {8: "lsass.exe"})
    text = (
        "GOLDEN-VM\\Administrator GOLDEN-VM$ golden-vm GOLDEN-VMX S-1-5-21-7-8-9-500 S-1-5-21-7-8-9"
    )
    assert GOLDEN.abstract(text) == (
        "{computer}\\Administrator {computer}$ {computer} GOLDEN-VMX "
        "{machine_sid}-500 S-1-5-21-7-8-9"
    )
    e = {
        "provider": "P",
        "event_id": 1,
        "process_id": 640,
        "thread_id": 3,
        "data": [{"name": "SubjectUserSid", "value": "S-1-5-21-7-8-9-500"}],
    }
    out, notes = rewrite(e, GOLDEN, ours)
    assert out["data"][0]["value"] == "S-1-5-21-1111-2222-3333-500"
    assert (out["process_id"], out["thread_id"]) == (8, 3)
    out, notes = rewrite({**e, "process_id": 700}, GOLDEN, ours)
    assert "process_id" not in out
    assert notes == ["P 1: no services.exe on this host; process_id left out"]


# ---------------------------------------------------------------- replay


def test_replay_names_the_emulated_host(engine, tmp_path):
    capture = build(tmp_path / "cap", _golden_run(engine, tmp_path), "scn-a")
    # A fresh engine state for the replay: reset what the golden run changed.
    for h in ("scn-a", "scn-b"):
        e = Engine(engine, h)
        e.call("reset")
        e.close()
    sc, notes = replay.scenario(Capture.load(capture))
    assert notes == []
    log = RunLog(tmp_path / "replay.jsonl")
    run(sc, engine, ["scn-a", "scn-b"], start=START, speed=0, max_skew=5, log=log)
    log.close()
    assert log.errors == 0 and log.gaps == 0

    sec = _events(engine, "scn-b", "Security")
    assert [x["event_id"] for x in sec][:4] == [4720, 4722, 4724, 4738]
    created = {d["name"]: d["value"] for d in sec[0]["data"]}
    assert created["TargetDomainName"] == "SCN-B"
    assert created["SubjectUserSid"] == "S-1-5-21-1111-2222-3333-500"
    b = Engine(engine, "scn-b")
    lsass = next(p["pid"] for p in b.call("proc.list") if p["image"] == "lsass.exe")
    b.close()
    assert sec[0]["process_id"] == lsass
    # Replay keeps the corpus timing: the second step is 10 s after the first.
    app = _events(engine, "scn-a", "Application")
    t0, t1 = (datetime.fromisoformat(x["time"].replace("Z", "+00:00")) for x in app)
    assert round((t1 - t0).total_seconds()) == 86


def test_replay_logs_a_gap_for_unknown_processes(engine, tmp_path):
    def foreign(step, e):
        if e["event_id"] == 4720:
            e["process_id"] = 9999
        return e

    capture = build(tmp_path / "cap", _golden_run(engine, tmp_path), "scn-a", foreign)
    sc, _ = replay.scenario(Capture.load(capture), logs=("Security",))
    log = RunLog(tmp_path / "r.jsonl")
    run(sc, engine, ["scn-b"], start=START, speed=0, log=log)
    log.close()
    gaps = [
        json.loads(x)["gap"]
        for x in (tmp_path / "r.jsonl").read_text().splitlines()
        if '"gap"' in x and json.loads(x)["record"] == "gap"
    ]
    assert gaps == [
        "Microsoft-Windows-Security-Auditing 4720: no pid 9999 on this host; process_id left out"
    ]


# ---------------------------------------------------------------- diff


def test_diff_of_a_matching_capture_is_clean(engine, tmp_path):
    run_log = _golden_run(engine, tmp_path)

    def noise(step, e):
        # Windows also writes events no action covers, such as 4798 here.
        if e["event_id"] == 4720:
            extra = {**e, "event_id": 4798, "data": [{"name": "TargetUserName", "value": "x"}]}
            return [e, extra]
        return e

    capture = build(tmp_path / "cap", run_log, "scn-a", noise)
    report = layout.diff(Capture.load(capture), run_log)
    assert report.errors == 0, report.text()
    assert [(f.severity, f.step, f.kind) for f in report.findings] == [
        ("warning", "user_create", "Security Microsoft-Windows-Security-Auditing 4798")
    ]
    by_step = {s["name"]: s for s in report.steps}
    assert by_step["failed_logon"] == {
        "name": "failed_logon",
        "golden": 3,
        "emulated": 3,
        "paired": 3,
    }


@pytest.mark.parametrize(
    "mutate, expect",
    [
        (lambda s, e: {**e, "task": 1}, "task: Windows 1, ours 13824"),
        (lambda s, e: {**e, "data": e["data"][::-1]}, "data fields"),
        (
            lambda s, e: {
                **e,
                "data": [{**d, "value": "0x0"} if d["name"] == "Status" else d for d in e["data"]],
            },
            "Status: Windows '0x0'",
        ),
        (
            lambda s, e: {
                **e,
                "data": [
                    {**d, "value": "-"} if d["name"] == "SubjectLogonId" else d for d in e["data"]
                ],
            },
            "SubjectLogonId: Windows none",
        ),
        (
            lambda s, e: {**e, "process_id": 700} if "process_id" in e else e,
            "process: Windows 'services.exe', ours 'lsass.exe'",
        ),
        (lambda s, e: None if e["event_id"] == 4625 else e, "we write 3, Windows wrote 0"),
    ],
)
def test_diff_finds_layout_errors(engine, tmp_path, mutate, expect):
    run_log = _golden_run(engine, tmp_path)

    def only_security(step, e):
        return (
            mutate(step, e)
            if e["provider"] == "Microsoft-Windows-Security-Auditing"
            and e["event_id"] in (4625, 4720)
            else e
        )

    capture = build(tmp_path / "cap", run_log, "scn-a", only_security)
    report = layout.diff(Capture.load(capture), run_log)
    assert report.errors >= 1
    assert any(expect in f.text for f in report.findings), report.text()


def test_cli_replay_and_diff(engine, tmp_path, capsys):
    run_log = _golden_run(engine, tmp_path)
    capture = build(tmp_path / "cap", run_log, "scn-a")
    assert (
        main(["diff-events", str(capture), str(run_log), "--json", str(tmp_path / "d.json")]) == 0
    )
    assert json.loads((tmp_path / "d.json").read_text())["errors"] == 0
    capsys.readouterr()
    assert (
        main(
            [
                "replay",
                str(capture),
                "--host",
                "scn-b",
                "--dry-run",
                "--start",
                "2026-10-17T10:00:00Z",
                "--logs",
                "Application",
            ]
        )
        == 0
    )
    out = capsys.readouterr().out
    assert "Application xvm-golden 900" in out and "Security" not in out
    assert (
        main(["replay", str(capture), "--socket", str(engine), "--host", "scn-b", "--speed", "0"])
        == 0
    )
    assert main(["diff-events", str(capture), str(run_log), "--host", "nobody"]) == 2
