"""Manager-side checks: the fidelity test, detection parity (T6) and event delivery (T5).

Inputs are the manager's `archives.json` and `alerts.json` (one JSON object per
line, as `manager-capture.sh` copies them) for the golden run and for an
emulated run, plus the emulated run's log from `xvm-scenario`.

Windows events reach the manager through Wazuh's `windows_eventchannel`
decoder. Their fields are under `data.win.system` (providerName, eventID,
channel, eventRecordID...) and `data.win.eventdata` (the event's data fields,
first letter lower case). This follows Wazuh's public documentation; the
golden capture is the authority.

Checks and their pass conditions (docs/BRIEF.md section 11):

- Fidelity: archived Windows events match the golden run field by field.
  Only host-identity fields differ.
- T6 detection parity: each rule ID fires as many times as in the golden run.
- T5 event delivery: every event the emulated host wrote arrives exactly once.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from xvm_scenario.corpus import Capture, Identity
from xvm_scenario.layout import VARIES, read_run_log, shape

# Fields that name the agent or the receiving moment, not the event.
IDENTITY_PATHS = {
    "timestamp",
    "id",
    "agent.id",
    "agent.name",
    "agent.ip",
    "manager.name",
    "full_log",  # the raw event as JSON; its fields are compared under data.win
    "data.win.system.systemTime",
    "data.win.system.eventRecordID",
    "data.win.system.computer",
    "data.win.system.processID",
    "data.win.system.threadID",
    "rule.firedtimes",
}
_VARIES = {"data.win.eventdata." + n[0].lower() + n[1:] for n in VARIES}


def read_ndjson(path: Path, agent: str | None = None) -> list[dict]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            e = json.loads(line)
            if agent is None or (e.get("agent") or {}).get("name") == agent:
                out.append(e)
    return out


def flatten(obj, prefix: str = "") -> dict[str, object]:
    out: dict[str, object] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.update(flatten(v, f"{prefix}.{k}" if prefix else k))
    else:
        out[prefix] = obj
    return out


def win_system(e: dict) -> dict:
    return ((e.get("data") or {}).get("win") or {}).get("system") or {}


def kind(e: dict) -> str:
    s = win_system(e)
    if s:
        return f"{s.get('channel')} {s.get('providerName')} {s.get('eventID')}"
    return f"{e.get('location', '?')} {(e.get('decoder') or {}).get('name', '?')}"


@dataclass
class Finding:
    check: str  # fidelity, t6, t5
    severity: str  # error, warning
    subject: str
    text: str


@dataclass
class Report:
    findings: list[Finding] = field(default_factory=list)
    counts: dict = field(default_factory=dict)

    @property
    def errors(self) -> int:
        return sum(1 for f in self.findings if f.severity == "error")

    @property
    def warnings(self) -> int:
        return sum(1 for f in self.findings if f.severity == "warning")

    def add(self, *args) -> None:
        self.findings.append(Finding(*args))

    def to_json(self) -> dict:
        return {
            "errors": self.errors,
            "warnings": self.warnings,
            "counts": self.counts,
            "findings": [f.__dict__ for f in self.findings],
        }

    def text(self) -> str:
        lines = [f"{self.errors} errors, {self.warnings} warnings"]
        lines += [f"{k}: {v}" for k, v in self.counts.items()]
        lines += [f"{f.severity:<7} {f.check} {f.subject}: {f.text}" for f in self.findings]
        return "\n".join(lines)


def _value(v, ident: Identity) -> str:
    text = v if isinstance(v, str) else json.dumps(v)
    return ident.abstract(text).replace("\r\n", "\n")


def compare_archive(g: dict, gi: Identity, o: dict, oi: Identity, report: Report) -> None:
    k = kind(g)
    gf, of = flatten(g), flatten(o)
    for path in sorted(set(gf) | set(of)):
        if path in IDENTITY_PATHS:
            continue
        if path not in of:
            report.add("fidelity", "error", k, f"{path} missing (Windows {gf[path]!r})")
            continue
        if path not in gf:
            report.add("fidelity", "error", k, f"{path} extra (ours {of[path]!r})")
            continue
        gv, ov = _value(gf[path], gi), _value(of[path], oi)
        if path in _VARIES:
            if shape(gv) != shape(ov):
                report.add(
                    "fidelity",
                    "error",
                    k,
                    f"{path}: Windows {shape(gv)} {gv!r}, ours {shape(ov)} {ov!r}",
                )
        elif gv != ov:
            report.add("fidelity", "error", k, f"{path}: Windows {gv!r}, ours {ov!r}")


def fidelity(
    golden: list[dict], gi: Identity, ours: list[dict], oi: Identity, report: Report
) -> None:
    """Pair archived events by kind, in order, and compare them field by field."""
    g_by: dict[str, list[dict]] = {}
    o_by: dict[str, list[dict]] = {}
    for e in golden:
        g_by.setdefault(kind(e), []).append(e)
    for e in ours:
        o_by.setdefault(kind(e), []).append(e)
    paired = 0
    for k in sorted(set(g_by) | set(o_by)):
        gs, os_ = g_by.get(k, []), o_by.get(k, [])
        windows_event = bool(win_system((gs or os_)[0]))
        if windows_event:
            for g, o in zip(gs, os_, strict=False):
                compare_archive(g, gi, o, oi, report)
                paired += 1
        if len(os_) != len(gs):
            # Windows events must match; other agent output (FIM, inventory) is reported.
            sev = "error" if windows_event and len(os_) > len(gs) else "warning"
            report.add("fidelity", sev, k, f"golden {len(gs)}, ours {len(os_)}")
    report.counts["archives"] = {"golden": len(golden), "ours": len(ours), "paired": paired}


def detection(golden: list[dict], ours: list[dict], report: Report) -> None:
    """T6: each rule ID fires as many times as in the golden run."""

    def rules(alerts):
        return Counter(str((a.get("rule") or {}).get("id")) for a in alerts)

    g, o = rules(golden), rules(ours)
    for rule in sorted(set(g) | set(o), key=lambda r: (len(r), r)):
        if g[rule] != o[rule]:
            report.add("t6", "error", f"rule {rule}", f"golden {g[rule]}, ours {o[rule]}")
    report.counts["alerts"] = {"golden": sum(g.values()), "ours": sum(o.values())}


def delivery(run_log: Path, archives: list[dict], host: str | None, report: Report) -> None:
    """T5: every event the run wrote arrives exactly once."""
    records = [json.loads(x) for x in run_log.read_text(encoding="utf-8").splitlines() if x.strip()]
    host, _, _, _ = read_run_log(run_log, host)
    written = Counter()
    for r in records:
        if (
            r.get("record") == "call"
            and r.get("host") == host
            and r.get("op") == "evt.write"
            and "result" in r
        ):
            written[(r["result"]["channel"].lower(), int(r["result"]["record_id"]))] += 1
    arrived = Counter()
    for e in archives:
        s = win_system(e)
        if s.get("channel") and str(s.get("eventRecordID", "")).isdigit():
            arrived[(s["channel"].lower(), int(s["eventRecordID"]))] += 1
    for key in sorted(written):
        n = arrived.get(key, 0)
        if n != 1:
            what = "missing" if n == 0 else f"arrived {n} times"
            report.add("t5", "error", f"{key[0]} record {key[1]}", what)
    unexpected = sum(n for key, n in arrived.items() if key not in written)
    report.counts["delivery"] = {
        "written": len(written),
        "arrived_once": sum(1 for k in written if arrived.get(k) == 1),
        "other_events": unexpected,
    }


def diff_manager(
    golden_dir: Path,
    archives: Path,
    alerts: Path,
    run_log: Path,
    host: str | None = None,
    agent: str | None = None,
) -> Report:
    """The fidelity test and T6 against the golden run, and T5 for the emulated run."""
    capture = Capture.load(golden_dir)
    report = Report()
    _, ident, _, _ = read_run_log(run_log, host)
    g_archives = read_ndjson(golden_dir / "manager" / "archives.json")
    g_alerts = read_ndjson(golden_dir / "manager" / "alerts.json")
    o_archives = read_ndjson(archives, agent)
    o_alerts = read_ndjson(alerts, agent)
    fidelity(g_archives, capture.identity, o_archives, ident, report)
    detection(g_alerts, o_alerts, report)
    delivery(run_log, o_archives, host, report)
    return report
