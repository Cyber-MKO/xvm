"""Event-layout diff: the events our actions write against what Windows wrote.

The golden capture runs a scenario on a real Windows VM and records the window
of each step. `library/golden-windows.yaml` runs the same steps on an emulated
host. This module pairs the two step by step and compares every event:

Checks, from most to least severe:

- error: an event kind we write that Windows did not write in that step.
- error: a paired event's header differs (version, level, task, opcode,
  keywords, qualifiers, provider GUID, source).
- error: data field names or their order differ.
- error: a data value differs after host identity is replaced by placeholders
  and line ends by LF. Fields that vary by run (logon IDs, ports, GUIDs) are
  compared by shape only.
- error: a different process wrote the event.
- warning: an event kind Windows wrote that we did not. An action may be
  incomplete, or the event is background noise.

Our side comes from a run log (`xvm-scenario run --log`), which records every
event written, the step it belongs to, and each host's identity.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .clock import parse_time
from .corpus import LOGS, Capture, Identity

HEADER = (
    "version",
    "level",
    "task",
    "opcode",
    "keywords",
    "qualifiers",
    "provider_guid",
    "event_source",
)
# Values that differ between any two runs, even on the same host. Compared by shape.
VARIES = {
    "SubjectLogonId",
    "TargetLogonId",
    "TargetLinkedLogonId",
    "LogonGuid",
    "IpPort",
    "ProcessId",
}
_SHAPES = (
    ("hex", re.compile(r"^0x[0-9a-fA-F]+$")),
    ("decimal", re.compile(r"^\d+$")),
    ("guid", re.compile(r"^\{[0-9a-fA-F-]{36}\}$")),
    ("none", re.compile(r"^-?$")),
)


def shape(value: str) -> str:
    return next((name for name, rx in _SHAPES if rx.match(value)), "text")


@dataclass
class Finding:
    step: str
    severity: str  # error, warning
    kind: str  # channel provider event_id
    text: str

    def to_json(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Report:
    host: str
    findings: list[Finding] = field(default_factory=list)
    steps: list[dict] = field(default_factory=list)  # name, golden, emulated, paired
    notes: list[str] = field(default_factory=list)

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    def to_json(self) -> dict:
        return {
            "host": self.host,
            "errors": self.errors,
            "warnings": self.warnings,
            "steps": self.steps,
            "findings": [f.to_json() for f in self.findings],
            "notes": self.notes,
        }

    def text(self) -> str:
        lines = [
            f"Event layout diff for {self.host}: {self.errors} errors, {self.warnings} warnings"
        ]
        lines.append("")
        lines.append(f"{'step':<18} {'golden':>6} {'ours':>6} {'paired':>6}")
        for s in self.steps:
            lines.append(f"{s['name']:<18} {s['golden']:>6} {s['emulated']:>6} {s['paired']:>6}")
        for f in self.findings:
            lines.append(f"{f.severity:<7} {f.step}: {f.kind}: {f.text}")
        lines.extend(f"note    {n}" for n in self.notes)
        return "\n".join(lines)


def kind(e: dict) -> str:
    return f"{e['channel']} {e['provider']} {e['event_id']}"


def _header(e: dict) -> dict:
    out = {}
    for k in HEADER:
        v = e.get(k)
        if isinstance(v, str) and k in ("keywords", "provider_guid"):
            v = v.lower()
        out[k] = v
    return out


def _data(e: dict, ident: Identity) -> list[tuple[str | None, str]]:
    # XML parsing turns CRLF into LF, so line ends are compared as LF.
    return [
        (d.get("name"), ident.abstract(str(d.get("value", ""))).replace("\r\n", "\n"))
        for d in e.get("data", [])
    ]


def compare_pair(step: str, g: dict, gi: Identity, o: dict, oi: Identity) -> list[Finding]:
    k = kind(g)
    out = []
    gh, oh = _header(g), _header(o)
    for f in HEADER:
        if gh[f] != oh[f]:
            out.append(Finding(step, "error", k, f"{f}: Windows {gh[f]!r}, ours {oh[f]!r}"))
    gd, od = _data(g, gi), _data(o, oi)
    gnames, onames = [n for n, _ in gd], [n for n, _ in od]
    if gnames != onames:
        out.append(Finding(step, "error", k, f"data fields: Windows {gnames}, ours {onames}"))
    else:
        for (name, gv), (_, ov) in zip(gd, od, strict=True):
            if name in VARIES:
                if shape(gv) != shape(ov):
                    out.append(
                        Finding(
                            step,
                            "error",
                            k,
                            f"{name}: Windows {shape(gv)} {gv!r}, ours {shape(ov)} {ov!r}",
                        )
                    )
            elif gv != ov:
                out.append(Finding(step, "error", k, f"{name}: Windows {gv!r}, ours {ov!r}"))
    gp = gi.processes.get(g["process_id"]) if "process_id" in g else None
    op = oi.processes.get(o["process_id"]) if "process_id" in o else None
    if (gp or "").lower() != (op or "").lower():
        out.append(Finding(step, "error", k, f"process: Windows {gp!r}, ours {op!r}"))
    return out


def compare(
    golden: dict[str, list[dict]],
    gi: Identity,
    ours: dict[str, list[dict]],
    oi: Identity,
    host: str,
    order: list[str],
) -> Report:
    """Compare events grouped by step name. `order` lists step names in report order."""
    report = Report(host)
    for step in order:
        g_events, o_events = golden.get(step, []), ours.get(step, [])
        paired = 0
        kinds = list(dict.fromkeys([kind(e) for e in g_events] + [kind(e) for e in o_events]))
        for k in kinds:
            gs = [e for e in g_events if kind(e) == k]
            os_ = [e for e in o_events if kind(e) == k]
            for g, o in zip(gs, os_, strict=False):
                report.findings.extend(compare_pair(step, g, gi, o, oi))
                paired += 1
            if len(os_) > len(gs):
                report.findings.append(
                    Finding(step, "error", k, f"we write {len(os_)}, Windows wrote {len(gs)}")
                )
            elif len(gs) > len(os_):
                report.findings.append(
                    Finding(step, "warning", k, f"Windows wrote {len(gs)}, we write {len(os_)}")
                )
        report.steps.append(
            {"name": step, "golden": len(g_events), "emulated": len(o_events), "paired": paired}
        )
    return report


def read_run_log(
    path: Path, host: str | None
) -> tuple[str, Identity, dict[str, list[dict]], list[str]]:
    """Events our actions wrote, grouped by step name, with the host's identity."""
    records = [
        json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    start = next((r for r in reversed(records) if r.get("record") == "start"), None)
    if start is None:
        raise ValueError(f"{path}: no start record")
    hosts = start["hosts"]
    host = host or next(iter(hosts))
    if host not in hosts:
        raise ValueError(f"{path}: host {host} is not in the last run ({', '.join(hosts)})")
    ident = Identity.from_json(hosts[host]["identity"])
    run = records[records.index(start) :]
    names = {r["step"]: r["name"] for r in run if r.get("record") == "step" and r["host"] == host}
    by_step: dict[str, list[dict]] = {}
    for r in run:
        if r.get("record") != "call" or r["host"] != host or r["op"] != "evt.write":
            continue
        if "result" not in r:
            continue  # the engine refused it
        e = {**r["params"]["event"], "channel": r["result"]["channel"]}
        by_step.setdefault(names.get(r["step"], f"step {r['step']}"), []).append(e)
    return host, ident, by_step, list(names.values())


def diff(capture: Capture, run_log: Path, host: str | None = None, logs=LOGS) -> Report:
    host, ident, ours, our_steps = read_run_log(run_log, host)
    events, notes = capture.events("scenario", logs)
    golden: dict[str, list[dict]] = {}
    outside = 0
    for e in events:
        step = capture.step_of(parse_time(e["time"])) if e.get("time") else None
        if step is None:
            outside += 1
            continue
        golden.setdefault(step, []).append(e)
    order = list(dict.fromkeys([s["name"] for s in capture.steps] + our_steps))
    report = compare(golden, capture.identity, ours, ident, host, order)
    report.notes = capture.notes + notes
    if outside:
        report.notes.append(f"{outside} captured events fall outside every step window")
    return report
