"""Scenario time.

Steps say when they happen as an offset from the scenario start. Each host
runs on its own clock: a fixed skew for the host and a small jitter per step,
both derived from the host name and a seed, so a run is repeatable and a fleet
of hosts does not act in lockstep (brief section 8).
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta

_DURATION = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*(ms|s|m|h)?\s*$")
_UNITS = {"ms": 0.001, "s": 1.0, "m": 60.0, "h": 3600.0, None: 1.0}


def parse_duration(value) -> float:
    """Seconds from `1.5s`, `500ms`, `2m`, `1h`, or a bare number of seconds."""
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if value < 0:
            raise ValueError(f"negative duration {value}")
        return float(value)
    m = _DURATION.match(str(value))
    if not m:
        raise ValueError(f"bad duration {value!r}: use for example 5s, 500ms, 2m")
    return float(m.group(1)) * _UNITS[m.group(2)]


def _unit(*parts: str) -> float:
    """A repeatable number in [0, 1) from text."""
    digest = hashlib.sha256("\0".join(parts).encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def parse_time(text: str) -> datetime:
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def format_time(dt: datetime) -> str:
    """RFC 3339 UTC with milliseconds, as the engine takes it."""
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class HostClock:
    def __init__(
        self, host: str, start: datetime, seed: str = "", max_skew: float = 0.0, jitter: float = 0.0
    ):
        self.host = host
        self.start = start
        self.seed = seed
        self.jitter = jitter
        # Skew in [-max_skew, +max_skew], fixed for the host.
        self.skew = (2 * _unit(seed, host, "skew") - 1) * max_skew

    def at(self, offset: float, step: int) -> datetime:
        """When step `step`, `offset` seconds into the scenario, happens on this host."""
        j = _unit(self.seed, self.host, "jitter", str(step)) * self.jitter
        return self.start + timedelta(seconds=offset + self.skew + j)
