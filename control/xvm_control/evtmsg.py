"""Derive event message templates from rendered events in a golden capture.

`wevtutil qe /f:RenderedXml` gives, for each event, its data values and the
message text Windows rendered for it. A template is that text with each data
value replaced by its insertion number (%1, %2...). Templates are data taken
from the host's own output, never from Microsoft binaries (CLAUDE.md rule 1).

Steps:

1. Group events by provider, event ID and version.
2. Build a candidate from one event: each data value, longest first, becomes
   %N where it stands as a whole field. A value of one or two characters
   counts only as a whole field after a tab or colon at a line end, so a lone
   "0" or "-" elsewhere in the text stays literal.
3. Check: a candidate must reproduce events of its group exactly. The one that
   reproduces the most wins; ties go to the first.
4. Keep a template that reproduces at least one event besides its own, or the
   only event of its group. Others are dropped with a note.
5. XML parsing turns CRLF into LF; templates use CRLF, as Windows messages do.

Parameter strings (%%1833 and the like) are resolved by Windows before
rendering, so a field holding one stays literal text in the template. When
another event has a different parameter, the template cannot reproduce it and
the coverage note says so.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
# Characters XML 1.0 forbids. EvtRender and ToXml can still emit them inside
# event data (a 4739 policy value of \x01, for example).
_XML_INVALID = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def xml_clean(text: str) -> str:
    """Event XML as Windows wrote it, minus characters no XML parser accepts."""
    return _XML_INVALID.sub("", text)


_BOUNDARY_BEFORE = " \t:(\"'=\n[,"
_BOUNDARY_AFTER = " \t\r\n.,;:)\"']"


@dataclass
class Sample:
    provider: str
    event_id: int
    version: int
    values: list[str]
    message: str


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_rendered(text: str) -> tuple[list[Sample], list[str]]:
    """Samples from `wevtutil qe /f:RenderedXml /e:Events` output, and notes."""
    notes: list[str] = []
    text = text.lstrip("﻿")
    try:
        root = ET.fromstring(xml_clean(text))
    except ET.ParseError as exc:
        return [], [f"rendered events unreadable: {exc}"]
    events = (
        [root] if _local(root.tag) == "Event" else [e for e in root if _local(e.tag) == "Event"]
    )
    out: list[Sample] = []
    for ev in events:
        system = next((c for c in ev if _local(c.tag) == "System"), None)
        info = next((c for c in ev if _local(c.tag) == "RenderingInfo"), None)
        if system is None or info is None:
            continue
        provider = next((c for c in system if _local(c.tag) == "Provider"), None)
        event_id = next((c for c in system if _local(c.tag) == "EventID"), None)
        version = next((c for c in system if _local(c.tag) == "Version"), None)
        message = next((c for c in info if _local(c.tag) == "Message"), None)
        if provider is None or event_id is None or message is None or not message.text:
            continue
        data_el = next((c for c in ev if _local(c.tag) == "EventData"), None)
        values = []
        if data_el is not None:
            values = [d.text or "" for d in data_el if _local(d.tag) == "Data"]
        elif any(_local(c.tag) == "UserData" for c in ev):
            # UserData has no insertion order Windows documents for messages.
            notes.append(f"{provider.get('Name')} {event_id.text}: UserData events skipped")
            continue
        try:
            out.append(
                Sample(
                    provider=provider.get("Name") or "",
                    event_id=int((event_id.text or "").strip()),
                    version=int((version.text or "0").strip()) if version is not None else 0,
                    values=values,
                    message=message.text.replace("\r\n", "\n"),
                )
            )
        except ValueError:
            continue
    return out, notes


def _fits(text: str, start: int, end: int, short: bool) -> bool:
    before = text[start - 1] if start > 0 else "\n"
    after = text[end] if end < len(text) else "\n"
    if short:
        return (
            before in "\t:"
            and after in "\r\n"
            or (before == " " and text[start - 2 : start] == ": " and after in "\r\n")
        )
    return before in _BOUNDARY_BEFORE and after in _BOUNDARY_AFTER


def candidate(sample: Sample) -> list:
    """The sample's message as a list of literal strings and insertion numbers."""
    parts: list = [sample.message]
    order = sorted(range(len(sample.values)), key=lambda i: (-len(sample.values[i]), i))
    for i in order:
        value = sample.values[i]
        if not value.strip():
            continue
        short = len(value) <= 2
        new: list = []
        for part in parts:
            if not isinstance(part, str):
                new.append(part)
                continue
            pos = 0
            for m in re.finditer(re.escape(value), part):
                if _fits(part, m.start(), m.end(), short):
                    new.append(part[pos : m.start()])
                    new.append(i + 1)
                    pos = m.end()
            new.append(part[pos:])
        parts = [p for p in new if p != ""]
    return parts


def render(parts: list, values: list[str]) -> str | None:
    out = []
    for p in parts:
        if isinstance(p, int):
            if p > len(values):
                return None
            out.append(values[p - 1])
        else:
            out.append(p)
    return "".join(out)


def to_template(parts: list) -> str:
    """Engine template text: %N for insertions, %% for a literal percent sign, CRLF line ends."""
    out = []
    for p in parts:
        out.append(f"%{p}" if isinstance(p, int) else p.replace("%", "%%"))
    return "".join(out).replace("\n", "\r\n")


def derive(samples: list[Sample]) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Templates as the profile's `event_messages`, and notes on what was dropped."""
    groups: dict[tuple[str, int, int], list[Sample]] = {}
    for s in samples:
        groups.setdefault((s.provider, s.event_id, s.version), []).append(s)
    templates: dict[str, dict[str, str]] = {}
    notes: list[str] = []
    versions: dict[tuple[str, int], set[int]] = {}
    for (provider, event_id, version), group in sorted(groups.items()):
        # Distinct events only: repeats prove nothing extra.
        unique = list({(tuple(s.values), s.message): s for s in group}.values())
        best, best_hits = None, -1
        for src in unique[:20]:
            parts = candidate(src)
            hits = sum(1 for s in unique if render(parts, s.values) == s.message)
            if hits > best_hits:
                best, best_hits = parts, hits
        label = f"{provider} {event_id} v{version}"
        if best is None:
            continue
        if (
            not any(isinstance(p, int) for p in best)
            and any(s.values for s in unique)
            and len(unique) > 1
        ):
            notes.append(f"{label}: no data value appears in the text; kept as fixed text")
        confirmed = best_hits >= 2 or len(unique) == 1
        if not confirmed:
            notes.append(
                f"{label}: template reproduced only its own event of {len(unique)}; dropped"
            )
            continue
        if best_hits < len(unique):
            notes.append(
                f"{label}: template reproduces {best_hits} of {len(unique)} distinct events"
            )
        templates.setdefault(provider, {})[f"{event_id}/{version}"] = to_template(best)
        versions.setdefault((provider, event_id), set()).add(version)
    # A bare "ID" key when only one version was seen, for events written without a version.
    for (provider, event_id), vs in versions.items():
        if len(vs) == 1:
            (v,) = vs
            templates[provider][str(event_id)] = templates[provider][f"{event_id}/{v}"]
    return templates, notes


def from_capture(root: Path) -> tuple[dict[str, dict[str, str]], list[str]]:
    """Templates from every rendered export in a capture folder."""
    samples: list[Sample] = []
    notes: list[str] = []
    files = sorted((root / "evtx").glob("rendered/*.xml")) + sorted(
        (root / "evtx").glob("scenario/*.rendered.xml")
    )
    if not files:
        return {}, ["no rendered events in the capture; event_messages left out"]
    for f in files:
        s, n = parse_rendered(f.read_text(encoding="utf-8-sig"))
        samples.extend(s)
        notes.extend(f"{f.name}: {x}" for x in n)
    templates, derive_notes = derive(samples)
    return templates, notes + derive_notes
