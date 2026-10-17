"""The golden corpus: events from a golden capture, and the identity they carry.

Events come from `wevtutil qe /f:RenderedXml` output in the capture
(`evtx/scenario/LOG.rendered.xml` for the scenario window, `evtx/rendered/LOG.xml`
for the newest events of each log). Each becomes an event in the engine's form.

Captured events name the capture VM: its computer name, its machine SID, its
process IDs. `Identity` turns those into placeholders and back, so a replayed
event names the emulated host instead (CLAUDE.md rule 5), and a diff compares
like with like.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .clock import parse_time

LOGS = ("Security", "System", "Application")
_MACHINE_SID = re.compile(r"^(S-1-5-21-\d+-\d+-\d+)-\d+$")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el, name: str):
    return next((c for c in el if _local(c.tag) == name), None)


def _int(text: str | None) -> int | None:
    try:
        return int((text or "").strip())
    except ValueError:
        return None


def parse_events(text: str) -> tuple[list[dict], list[str]]:
    """Events from RenderedXml or plain XML event output, and notes on what was skipped."""
    notes: list[str] = []
    try:
        root = ET.fromstring(text.lstrip("﻿"))
    except ET.ParseError as exc:
        return [], [f"events unreadable: {exc}"]
    elements = (
        [root] if _local(root.tag) == "Event" else [e for e in root if _local(e.tag) == "Event"]
    )
    out = []
    for ev in elements:
        system = _child(ev, "System")
        if system is None:
            continue
        provider = _child(system, "Provider")
        event_id = _child(system, "EventID")
        if provider is None or event_id is None or _int(event_id.text) is None:
            notes.append("event without a provider or event ID skipped")
            continue
        label = f"{provider.get('Name')} {event_id.text.strip()}"
        if _child(ev, "UserData") is not None:
            # The engine stores EventData only; UserData has its own schema per provider.
            notes.append(f"{label}: UserData event skipped")
            continue
        e: dict = {"provider": provider.get("Name") or "", "event_id": _int(event_id.text)}
        if provider.get("Guid"):
            e["provider_guid"] = provider.get("Guid")
        if provider.get("EventSourceName"):
            e["event_source"] = provider.get("EventSourceName")
        if event_id.get("Qualifiers") is not None:
            e["qualifiers"] = _int(event_id.get("Qualifiers"))
        for name, key in (
            ("Version", "version"),
            ("Level", "level"),
            ("Task", "task"),
            ("Opcode", "opcode"),
        ):
            el = _child(system, name)
            if el is not None and _int(el.text) is not None:
                e[key] = _int(el.text)
        keywords = _child(system, "Keywords")
        if keywords is not None and keywords.text:
            e["keywords"] = keywords.text.strip()
        created = _child(system, "TimeCreated")
        if created is not None and created.get("SystemTime"):
            e["time"] = created.get("SystemTime")
        execution = _child(system, "Execution")
        if execution is not None:
            for attr, key in (("ProcessID", "process_id"), ("ThreadID", "thread_id")):
                if _int(execution.get(attr)) is not None:
                    e[key] = _int(execution.get(attr))
        security = _child(system, "Security")
        if security is not None and security.get("UserID"):
            e["user_id"] = security.get("UserID")
        channel = _child(system, "Channel")
        e["channel"] = (channel.text or "").strip() if channel is not None else ""
        data = []
        event_data = _child(ev, "EventData")
        if event_data is not None:
            for d in event_data:
                if _local(d.tag) == "Data":
                    item = {"value": d.text or ""}
                    if d.get("Name") is not None:
                        item = {"name": d.get("Name"), **item}
                    data.append(item)
                elif _local(d.tag) == "Binary":
                    notes.append(f"{label}: Binary data left out")
        e["data"] = data
        info = _child(ev, "RenderingInfo")
        message = _child(info, "Message") if info is not None else None
        if message is not None and message.text:
            # XML parsing turns CRLF into LF; Windows messages use CRLF.
            e["message"] = message.text.replace("\r\n", "\n").replace("\n", "\r\n")
        out.append(e)
    return out, notes


def machine_sid(sids) -> str | None:
    """The machine SID prefix (S-1-5-21-a-b-c) shared by local accounts."""
    for sid in sids:
        m = _MACHINE_SID.match(str(sid or ""))
        if m:
            return m.group(1)
    return None


@dataclass
class Identity:
    """What names one host in event text: computer name, machine SID, process IDs."""

    computer: str
    machine_sid: str | None = None
    processes: dict[int, str] = field(default_factory=dict)  # pid -> image

    def _name(self) -> re.Pattern:
        return re.compile(rf"(?<![A-Za-z0-9-]){re.escape(self.computer)}(?![A-Za-z0-9-])", re.I)

    def abstract(self, text: str) -> str:
        """Replace this host's names with {computer} and {machine_sid}."""
        if self.machine_sid:
            text = re.sub(
                rf"{re.escape(self.machine_sid)}(?=-\d)", "{machine_sid}", text, flags=re.I
            )
        if self.computer:
            text = self._name().sub("{computer}", text)
        return text

    def concrete(self, text: str) -> str:
        """Fill {computer} and {machine_sid} with this host's names."""
        text = text.replace("{computer}", self.computer)
        if self.machine_sid:
            text = text.replace("{machine_sid}", self.machine_sid)
        return text

    def to_json(self) -> dict:
        return {
            "computer": self.computer,
            "machine_sid": self.machine_sid,
            "processes": {str(k): v for k, v in sorted(self.processes.items())},
        }

    @classmethod
    def from_json(cls, d: dict) -> Identity:
        return cls(
            d["computer"],
            d.get("machine_sid"),
            {int(k): v for k, v in (d.get("processes") or {}).items()},
        )


def rewrite(event: dict, src: Identity, dst: Identity) -> tuple[dict, list[str]]:
    """The event as the destination host would have written it. Returns notes on
    what could not be carried over."""
    notes: list[str] = []

    def conv(value):
        if isinstance(value, str):
            return dst.concrete(src.abstract(value))
        if isinstance(value, list):
            return [conv(v) for v in value]
        if isinstance(value, dict):
            return {k: conv(v) for k, v in value.items()}
        return value

    out = {k: conv(v) for k, v in event.items() if k not in ("process_id", "thread_id")}
    pid = event.get("process_id")
    if pid is not None:
        image = src.processes.get(pid)
        mapped = next(
            (p for p, img in dst.processes.items() if image and img.lower() == image.lower()), None
        )
        if mapped is not None:
            out["process_id"] = mapped
            if "thread_id" in event:
                out["thread_id"] = event["thread_id"]
        else:
            what = image or f"pid {pid}"
            notes.append(
                f"{event['provider']} {event['event_id']}: no {what} on this host; "
                "process_id left out"
            )
    return out, notes


@dataclass
class Capture:
    root: Path
    identity: Identity
    steps: list[dict]  # name, start, end
    notes: list[str]

    @classmethod
    def load(cls, root: Path) -> Capture:
        notes: list[str] = []
        manifest = _read_json(root / "manifest.json") or {}
        computer = str((manifest.get("host") or {}).get("name") or "")
        if not computer:
            notes.append("manifest names no host; the computer name is not rewritten")
        users = _as_list(_read_json(root / "host" / "users.json"))
        sid = machine_sid(u.get("SID") for u in users)
        if sid is None:
            notes.append("no local account SIDs; the machine SID is not rewritten")
        procs = {
            p["ProcessId"]: str(p.get("Name") or "")
            for p in _as_list(_read_json(root / "host" / "processes.json"))
            if isinstance(p.get("ProcessId"), int)
        }
        steps = []
        for s in (manifest.get("scenario") or {}).get("steps") or []:
            if s.get("start") and s.get("end"):
                steps.append(
                    {
                        "name": s["name"],
                        "start": parse_time(s["start"]),
                        "end": parse_time(s["end"]),
                    }
                )
        return cls(root, Identity(computer, sid, procs), steps, notes)

    def events(self, source: str = "scenario", logs=LOGS) -> tuple[list[dict], list[str]]:
        """Events of the given logs in time order. `source` is `scenario` (the
        scenario window) or `recent` (the newest events of each log)."""
        events: list[dict] = []
        notes: list[str] = []
        for log in logs:
            path = (
                self.root / "evtx" / "scenario" / f"{log}.rendered.xml"
                if source == "scenario"
                else self.root / "evtx" / "rendered" / f"{log}.xml"
            )
            if not path.is_file():
                notes.append(f"{path.relative_to(self.root)} missing")
                continue
            evs, n = parse_events(path.read_text(encoding="utf-8-sig"))
            for e in evs:
                e["channel"] = e.get("channel") or log
            events.extend(evs)
            notes.extend(f"{path.name}: {x}" for x in n)
        events.sort(key=lambda e: _when(e))
        return events, notes

    def step_of(self, when: datetime) -> str | None:
        for s in self.steps:
            if s["start"] <= when <= s["end"]:
                return s["name"]
        return None


def _when(e: dict) -> datetime:
    return parse_time(e["time"]) if e.get("time") else datetime.min.replace(tzinfo=UTC)


def _read_json(path: Path):
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]
