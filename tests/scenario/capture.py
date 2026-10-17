"""A synthetic golden capture for the replay and diff tests.

Its events are built from a run of library/golden-windows.yaml on an emulated
host, rewritten to name a made-up capture VM and rendered as `wevtutil qe
/f:RenderedXml` output. So the capture agrees with our actions, and each test
changes one thing to see the diff catch it.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from xvm_scenario.clock import format_time, parse_time
from xvm_scenario.corpus import Identity

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
GOLDEN = Identity("GOLDEN-VM", "S-1-5-21-7-8-9", {640: "lsass.exe", 700: "services.exe"})


def event_xml(e: dict, channel: str, computer: str = "GOLDEN-VM") -> str:
    q = f" Qualifiers='{e['qualifiers']}'" if "qualifiers" in e else ""
    src = f" EventSourceName={quoteattr(e['event_source'])}" if "event_source" in e else ""
    guid = f" Guid='{e['provider_guid']}'" if "provider_guid" in e else ""
    system = [
        f"<Provider Name={quoteattr(e['provider'])}{guid}{src}/>",
        f"<EventID{q}>{e['event_id']}</EventID>",
    ]
    for tag, key in (
        ("Version", "version"),
        ("Level", "level"),
        ("Task", "task"),
        ("Opcode", "opcode"),
        ("Keywords", "keywords"),
    ):
        if key in e:
            system.append(f"<{tag}>{e[key]}</{tag}>")
    system.append(f"<TimeCreated SystemTime='{e['time']}'/>")
    if "process_id" in e:
        system.append(
            f"<Execution ProcessID='{e['process_id']}' ThreadID='{e.get('thread_id', 1)}'/>"
        )
    system.append(f"<Channel>{channel}</Channel><Computer>{computer}</Computer>")
    data = "".join(
        f"<Data Name={quoteattr(d['name'])}>{escape(d['value'])}</Data>"
        if d.get("name")
        else f"<Data>{escape(d['value'])}</Data>"
        for d in e.get("data", [])
    )
    msg = (
        f"<RenderingInfo Culture='en-US'><Message>{escape(e['message'])}</Message></RenderingInfo>"
        if e.get("message")
        else ""
    )
    return (
        f"<Event xmlns='{NS}'><System>{''.join(system)}</System>"
        f"<EventData>{data}</EventData>{msg}</Event>"
    )


def build(root: Path, run_log: Path, host: str, mutate=None) -> Path:
    """Write a capture under root from a run log. `mutate(step, event)` may change
    or drop (return None) a captured event; it may also return a list to add events."""
    records = [json.loads(x) for x in run_log.read_text().splitlines()]
    start = next(r for r in records if r["record"] == "start")
    ours = Identity.from_json(start["hosts"][host]["identity"])
    names = {
        r["step"]: r["name"] for r in records if r.get("record") == "step" and r["host"] == host
    }
    logs: dict[str, list[str]] = {"Security": [], "System": [], "Application": []}
    windows: dict[str, list] = {}
    for r in records:
        if r.get("record") != "call" or r["host"] != host or r["op"] != "evt.write":
            continue
        step = names[r["step"]]
        e = json.loads(ours.abstract(json.dumps(r["params"]["event"])))
        e = json.loads(GOLDEN.concrete(json.dumps(e)))
        if e.get("process_id"):  # process ID 0 is the same on every host
            image = ours.processes[e["process_id"]]
            e["process_id"] = next(p for p, i in GOLDEN.processes.items() if i == image)
        e["time"] = r["params"]["time"]
        out = mutate(step, e) if mutate else e
        for ev in out if isinstance(out, list) else [out] if out else []:
            channel = ev.pop("channel", r["params"]["channel"])
            logs[channel].append(event_xml(ev, channel))
        t = parse_time(r["params"]["time"])
        w = windows.setdefault(step, [t, t])
        w[0], w[1] = min(w[0], t), max(w[1], t)
    (root / "evtx" / "scenario").mkdir(parents=True)
    for log, events in logs.items():
        text = "﻿<Events>" + "".join(events) + "</Events>"
        (root / "evtx" / "scenario" / f"{log}.rendered.xml").write_text(text, encoding="utf-8")
    steps = [
        {
            "name": n,
            "start": format_time(a - timedelta(milliseconds=500)),
            "end": format_time(b + timedelta(milliseconds=500)),
        }
        for n, (a, b) in windows.items()
    ]
    manifest = {
        "schema": 1,
        "kind": "windows-golden-baseline",
        "host": {"name": "GOLDEN-VM"},
        "scenario": {"steps": steps},
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    (root / "host").mkdir()
    (root / "host" / "users.json").write_text(
        json.dumps([{"Name": "Administrator", "SID": "S-1-5-21-7-8-9-500", "Enabled": True}])
    )
    (root / "host" / "processes.json").write_text(
        json.dumps([{"ProcessId": p, "Name": n} for p, n in GOLDEN.processes.items()])
    )
    return root
