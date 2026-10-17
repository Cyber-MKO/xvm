"""Replay the golden corpus on emulated hosts.

The capture's events become one scenario: each event is a `replay.event` step at
its offset from the first event, so the corpus keeps its own timing. Each host
plays it on its own clock, and every event is rewritten to name that host.
"""

from __future__ import annotations

from .clock import parse_time
from .corpus import LOGS, Capture
from .runner import Scenario, Step


def scenario(capture: Capture, source: str = "scenario", logs=LOGS) -> tuple[Scenario, list[str]]:
    events, notes = capture.events(source, logs)
    notes = capture.notes + notes
    timed = [e for e in events if e.get("time")]
    if len(timed) < len(events):
        notes.append(f"{len(events) - len(timed)} events without a time skipped")
    steps = []
    if timed:
        first = parse_time(timed[0]["time"])
        src = capture.identity.to_json()
        for i, e in enumerate(timed, start=1):
            offset = (parse_time(e["time"]) - first).total_seconds()
            steps.append(
                Step(
                    i,
                    offset,
                    "replay.event",
                    {"event": e, "source": src},
                    f"{e['channel']} {e['provider']} {e['event_id']}",
                )
            )
    return Scenario(f"golden-{source}", "windows", {}, steps), notes
