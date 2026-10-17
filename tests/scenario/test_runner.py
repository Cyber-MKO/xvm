"""Scenario runner: checks, clocks, and runs against a real engine."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from xvm_scenario import actions
from xvm_scenario.cli import main
from xvm_scenario.clock import HostClock, parse_duration
from xvm_scenario.engine import Engine
from xvm_scenario.runner import RunLog, ScenarioInvalid, load, parse, plan, run

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "scenarios" / "library" / "golden-windows.yaml"
START = datetime(2026, 10, 17, 10, 0, tzinfo=UTC)


def _doc(*steps, **extra) -> dict:
    return {
        "schema": 1,
        "kind": "scenario",
        "name": "t",
        "os": "windows",
        "defaults": {"actor": "Administrator"},
        "steps": list(steps),
        **extra,
    }


def _run(sock, doc, hosts=("scn-a",), tmp_path=None, **kw):
    log_path = tmp_path / "run.jsonl" if tmp_path else None
    log = RunLog(log_path)
    run(parse(doc), sock, list(hosts), start=START, speed=0, log=log, **kw)
    log.close()
    records = [json.loads(x) for x in log_path.read_text().splitlines()] if log_path else []
    return log, records


def _events(sock, host, channel):
    e = Engine(sock, host)
    try:
        return e.call("evt.query", channel=channel, format="json", limit=1000)["events"]
    finally:
        e.close()


def _data(event) -> dict:
    return {d.get("name"): d["value"] for d in event["data"]}


# ---------------------------------------------------------------- checks


def test_library_scenarios_validate():
    for path in (ROOT / "scenarios" / "library").glob("*.yaml"):
        load(path)


def test_durations():
    assert parse_duration("1.5s") == 1.5
    assert parse_duration("500ms") == 0.5
    assert parse_duration("2m") == 120
    assert parse_duration(3) == 3.0
    for bad in ("-1s", "5x", "", True):
        with pytest.raises(ValueError):
            parse_duration(bad)


@pytest.mark.parametrize(
    "step, problem",
    [
        ({"at": "1s", "action": "nope"}, "unknown action 'nope'"),
        ({"at": "1s", "action": "user.create"}, "missing parameter 'name'"),
        (
            {"at": "1s", "action": "user.create", "params": {"name": "x", "colour": 1}},
            "unknown parameter 'colour'",
        ),
        ({"at": "1 week", "action": "marker", "params": {"event_id": 1}}, "/steps/0/at"),
    ],
)
def test_bad_steps_are_refused(step, problem):
    with pytest.raises(ScenarioInvalid) as e:
        parse(_doc(step))
    assert any(problem in p for p in e.value.problems), e.value.problems


def test_steps_must_not_go_back_in_time():
    with pytest.raises(ScenarioInvalid, match="before the step above"):
        parse(
            _doc(
                {"at": "10s", "action": "marker", "params": {"event_id": 1}},
                {"at": "5s", "action": "marker", "params": {"event_id": 2}},
            )
        )


def test_unquoted_dates_are_refused():
    doc = _doc({"at": "0s", "action": "marker", "params": {"event_id": 1}})
    doc["description"] = datetime(2026, 1, 1)
    with pytest.raises(ScenarioInvalid, match="quote dates"):
        parse(doc)


# ---------------------------------------------------------------- clocks


def test_host_clocks_are_repeatable_and_differ():
    a1 = HostClock("a", START, "s", max_skew=30, jitter=2)
    a2 = HostClock("a", START, "s", max_skew=30, jitter=2)
    b = HostClock("b", START, "s", max_skew=30, jitter=2)
    assert a1.at(10, 1) == a2.at(10, 1)
    assert a1.skew != b.skew
    assert abs(a1.skew) <= 30
    assert HostClock("a", START, "other", max_skew=30).skew != a1.skew
    flat = HostClock("a", START)
    assert flat.at(5, 1) == datetime(2026, 10, 17, 10, 0, 5, tzinfo=UTC)


def test_plan_keeps_each_hosts_step_order():
    sc = load(GOLDEN)
    clocks = {h: HostClock(h, START, "x", max_skew=60, jitter=30) for h in ("a", "b", "c")}
    order = plan(sc, clocks)
    assert [p.at for p in order] == sorted(p.at for p in order)
    for h in clocks:
        mine = [p.step.index for p in order if p.host == h]
        assert mine == sorted(mine)


# ---------------------------------------------------------------- runs


def test_golden_scenario_end_to_end(engine, tmp_path):
    log = RunLog(tmp_path / "run.jsonl")
    run(
        load(GOLDEN),
        engine,
        ["scn-a", "scn-b"],
        start=START,
        speed=0,
        seed="t",
        max_skew=5,
        jitter=1,
        log=log,
    )
    log.close()
    assert (log.errors, log.gaps) == (0, 0)

    sec = _events(engine, "scn-a", "Security")
    # The order the golden capture shows.
    assert [e["event_id"] for e in sec] == [
        4728,
        4720,
        4722,
        4738,
        4738,
        4724,
        4732,
        4625,
        4625,
        4625,
        4733,
        4729,
        4726,
    ]
    # The account joins the profile's primary group, RID 513 of the machine SID.
    joined = _data(sec[0])
    assert (joined["TargetUserName"], joined["TargetSid"]) == (
        "None",
        "S-1-5-21-1111-2222-3333-513",
    )
    created = _data(sec[1])
    # The new account takes the next RID after the host's own accounts (alice is 1004).
    assert created["TargetSid"] == "S-1-5-21-1111-2222-3333-1005"
    assert created["TargetDomainName"] == "SCN-A"
    assert created["SubjectUserSid"] == "S-1-5-21-1111-2222-3333-500"
    assert list(created)[:4] == [
        "TargetUserName",
        "TargetDomainName",
        "TargetSid",
        "SubjectUserSid",
    ]
    added = _data(sec[6])
    assert (added["TargetUserName"], added["TargetDomainName"], added["TargetSid"]) == (
        "Administrators",
        "Builtin",
        "S-1-5-32-544",
    )
    assert sec[0]["computer"] == "SCN-A"

    # process_id is lsass.exe's PID from the engine's process table.
    e = Engine(engine, "scn-a")
    lsass = next(p["pid"] for p in e.call("proc.list") if p["image"] == "lsass.exe")
    assert {x["process_id"] for x in sec if x["event_id"] != 4625} == {lsass}
    # The account is gone again, W32Time runs, the FIM file is deleted, the folder stays.
    assert all(u["name"] != "xvmgolden" for u in e.call("list", name="users"))
    w32 = next(s for s in e.call("list", name="services") if s["name"] == "W32Time")
    assert w32["state"] == "running"
    assert e.call("file.stat", path="C:\\xvm-golden-fim")["type"] == "dir"
    e.close()

    assert _data(_events(engine, "scn-b", "Security")[1])["TargetSid"].endswith("-1000")
    system = _events(engine, "scn-a", "System")
    assert [_data(x)["param2"] for x in system] == ["stopped", "running"]
    assert _data(system[0])["param1"] == "Windows Time"
    app = _events(engine, "scn-a", "Application")
    assert [(x["provider"], x["event_id"]) for x in app] == [
        ("xvm-golden", 900),
        ("xvm-golden", 901),
    ]


def test_event_times_follow_the_host_clock(engine):
    doc = _doc({"at": "10s", "action": "marker", "params": {"event_id": 7}})
    run(
        parse(doc),
        engine,
        ["scn-a", "scn-b"],
        start=START,
        speed=0,
        seed="s",
        max_skew=30,
        log=RunLog(None),
    )
    for host in ("scn-a", "scn-b"):
        clock = HostClock(host, START, "s", max_skew=30)
        (ev,) = _events(engine, host, "Application")
        assert ev["time"].startswith(clock.at(10, 1).strftime("%Y-%m-%dT%H:%M:%S"))


def test_service_and_group_errors_are_logged_not_raised(engine, tmp_path):
    doc = _doc(
        {"at": "0s", "action": "service.start", "params": {"name": "W32Time"}},
        {"at": "1s", "action": "group.add", "params": {"user": "alice", "group": "Users"}},
        {"at": "2s", "action": "service.start", "params": {"name": "Spooler"}},
    )
    log, records = _run(engine, doc, tmp_path=tmp_path)
    steps = [r for r in records if r["record"] == "step"]
    assert [s["ok"] for s in steps] == [False, False, True]
    assert "already running" in steps[0]["error"]
    assert "already in Users" in steps[1]["error"]
    assert log.errors == 2


def test_stop_on_error(engine):
    doc = _doc(
        {"at": "0s", "action": "user.delete", "params": {"name": "nobody"}},
        {"at": "1s", "action": "marker", "params": {"event_id": 1}},
    )
    run(parse(doc), engine, ["scn-a"], start=START, speed=0, log=RunLog(None), stop_on_error=True)
    assert _events(engine, "scn-a", "Application") == []


def test_missing_process_is_a_gap(engine, tmp_path):
    doc = _doc(
        {"at": "0s", "action": "process.exit", "params": {"image": "services.exe"}},
        {"at": "1s", "action": "service.stop", "params": {"name": "W32Time"}},
    )
    log, records = _run(engine, doc, tmp_path=tmp_path)
    assert log.errors == 0
    gaps = [r["gap"] for r in records if r["record"] == "gap"]
    assert gaps == ["event 7036: no running services.exe for process_id; left out"]
    (ev,) = _events(engine, "scn-a", "System")
    assert "process_id" not in ev or ev["process_id"] in (None, 0)


def test_processes_and_files(engine, tmp_path):
    doc = _doc(
        {
            "at": "0s",
            "action": "process.start",
            "params": {
                "image": "tool.exe",
                "parent": "services.exe",
                "command_line": "tool -x",
                "pid": 4400,
            },
        },
        {"at": "1s", "action": "file.mkdir", "params": {"path": "C:\\Data"}},
        {"at": "1s", "action": "file.write", "params": {"path": "C:\\Data\\a.txt", "text": "a"}},
        {"at": "2s", "action": "file.append", "params": {"path": "C:\\Data\\a.txt", "text": "b"}},
        {
            "at": "3s",
            "action": "file.rename",
            "params": {"from": "C:\\Data\\a.txt", "to": "C:\\Data\\b.txt"},
        },
        {
            "at": "4s",
            "action": "registry.set",
            "params": {"key": "HKLM\\SOFTWARE\\T", "name": "V", "type": "REG_SZ", "data": "x"},
        },
        {"at": "5s", "action": "process.exit", "params": {"image": "tool.exe"}},
    )
    log, _ = _run(engine, doc, tmp_path=tmp_path)
    assert log.errors == 0
    e = Engine(engine, "scn-a")
    assert all(p["image"] != "tool.exe" for p in e.call("proc.list"))
    assert e.call("changes")["changes"][0]["pid"] == 4400
    data = e.call("file.read", path="C:\\Data\\b.txt")["data"]
    assert data == "YWI="
    assert e.call("reg.query_value", key="HKLM\\SOFTWARE\\T", name="V")["data"] == "x"
    changes = e.call("changes")["changes"]
    assert changes[0]["time"].startswith("2026-10-17T10:00:00")
    e.close()


def test_logon_success_and_failed_counts(engine):
    doc = _doc(
        {"at": "0s", "action": "logon.success", "params": {"user": "alice", "count": 2}},
        {
            "at": "1s",
            "action": "logon.failed",
            "params": {"user": "mallory", "count": 4, "logon_type": 10, "ip_address": "192.0.2.9"},
        },
    )
    run(parse(doc), engine, ["scn-a"], start=START, speed=0, log=RunLog(None))
    sec = _events(engine, "scn-a", "Security")
    ok = [x for x in sec if x["event_id"] == 4624]
    bad = [x for x in sec if x["event_id"] == 4625]
    assert len(ok) == 2 and len(bad) == 4
    assert _data(ok[0])["TargetLogonId"] != _data(ok[1])["TargetLogonId"]
    assert _data(ok[0])["TargetUserSid"] == "S-1-5-21-1111-2222-3333-1004"
    assert (_data(bad[0])["LogonType"], _data(bad[0])["IpAddress"]) == ("10", "192.0.2.9")


def test_wrong_os_host_is_refused(engine):
    doc = _doc({"at": "0s", "action": "marker", "params": {"event_id": 1}})
    doc["os"] = "linux"
    with pytest.raises(ScenarioInvalid):
        parse(doc)


def test_every_action_has_a_doc_line_and_the_events_load():
    for name, fn in actions.ACTIONS.items():
        assert fn.__doc__ or name.startswith(("file.", "registry.")), name
    events = actions.load_events("windows")
    assert {"4720", "4625", "7036", "marker"} <= events.keys()


def test_cli(engine, tmp_path, capsys):
    assert main(["validate", str(GOLDEN)]) == 0
    assert (
        main(
            ["run", str(GOLDEN), "--host", "scn-a", "--dry-run", "--start", "2026-10-17T10:00:00Z"]
        )
        == 0
    )
    assert "marker_end" in capsys.readouterr().out
    log = tmp_path / "cli.jsonl"
    assert (
        main(
            [
                "run",
                str(GOLDEN),
                "--socket",
                str(engine),
                "--host",
                "scn-b",
                "--speed",
                "0",
                "--log",
                str(log),
            ]
        )
        == 0
    )
    assert json.loads(log.read_text().splitlines()[-1])["errors"] == 0
    bad = tmp_path / "bad.yaml"
    bad.write_text("schema: 1\nkind: scenario\nname: b\nos: windows\nsteps: []\n")
    assert main(["validate", str(bad)]) == 1
