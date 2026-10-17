"""T2 (enrollment and keepalive) and T3 (identity) against the Wazuh manager.

- T2, pass condition "agent Active with no disconnects over 24 hours": poll the
  agent's status. It must become `active` within the enroll timeout, then stay
  `active` for the whole window, with every keepalive younger than the limit.
- T3, pass condition "manager shows the OS name and version from the host
  profile": compare the agent's `os` fields with the profile's `os_info`.

Pass conditions are from docs/BRIEF.md section 11.
The manager's agent fields (`status`, `lastKeepAlive`, `os.name`,
`os.version`, `os.platform`, `version`) follow Wazuh's public API reference.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .manager import Manager, ManagerError


def _parse(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _fmt(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class Result:
    test: str
    passed: bool
    summary: dict = field(default_factory=dict)
    problems: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        return {
            "test": self.test,
            "passed": self.passed,
            "summary": self.summary,
            "problems": self.problems,
        }

    def text(self) -> str:
        lines = [f"{self.test}: {'PASS' if self.passed else 'FAIL'}"]
        lines += [f"  {k}: {v}" for k, v in self.summary.items()]
        lines += [f"  problem: {p}" for p in self.problems]
        return "\n".join(lines)


# ---------------------------------------------------------------- T2


def sample(mgr: Manager, agent: str, now: datetime) -> dict:
    """One look at the agent, as a run-log line."""
    s: dict = {"time": _fmt(now)}
    try:
        a = mgr.agent(agent)
    except ManagerError as e:
        s["error"] = str(e)
        return s
    if a is None:
        s["status"] = "unknown"
        return s
    s["status"] = a.get("status")
    s["id"] = a.get("id")
    if a.get("lastKeepAlive"):
        s["last_keepalive"] = a["lastKeepAlive"]
    return s


def score_t2(
    samples: list[dict],
    duration_s: float,
    max_keepalive_s: float,
    interval_s: float,
    enroll_timeout_s: float,
) -> Result:
    """Score a series of samples. The window starts at the first active sample."""
    r = Result("T2", False)
    if not samples:
        r.problems.append("no samples")
        return r
    t0 = _parse(samples[0]["time"])
    first = next((i for i, s in enumerate(samples) if s.get("status") == "active"), None)
    if first is None:
        r.problems.append(f"never active (last status: {samples[-1].get('status')})")
        r.summary["samples"] = len(samples)
        return r
    start = _parse(samples[first]["time"])
    r.summary["enrolled_after_s"] = round((start - t0).total_seconds(), 3)
    if r.summary["enrolled_after_s"] > enroll_timeout_s:
        r.problems.append(f"active only after {r.summary['enrolled_after_s']} s")
    window = [
        s for s in samples[first:] if (_parse(s["time"]) - start).total_seconds() <= duration_s
    ]
    disconnects, prev, errors = [], "active", 0
    worst_age, longest_gap = 0.0, 0.0
    last_t = start
    for s in window:
        t = _parse(s["time"])
        longest_gap = max(longest_gap, (t - last_t).total_seconds())
        last_t = t
        if "error" in s:
            errors += 1
            continue
        status = s.get("status")
        if status != "active" and prev == "active":
            disconnects.append(f"{s['time']}: {status}")
        prev = status
        ka = _parse(s.get("last_keepalive"))
        if status == "active" and ka:
            worst_age = max(worst_age, (t - ka).total_seconds())
    observed = (last_t - start).total_seconds()
    r.summary.update(
        {
            "samples": len(window),
            "observed_s": round(observed, 3),
            "required_s": duration_s,
            "disconnects": len(disconnects),
            "oldest_keepalive_s": round(worst_age, 3),
            "longest_sample_gap_s": round(longest_gap, 3),
            "api_errors": errors,
        }
    )
    r.problems += [f"not active at {d}" for d in disconnects]
    if worst_age > max_keepalive_s:
        r.problems.append(f"a keepalive was {worst_age:g} s old (limit {max_keepalive_s:g} s)")
    if observed + interval_s < duration_s:
        r.problems.append(f"watched {observed:g} s of {duration_s:g} s")
    if longest_gap > 3 * interval_s:
        # A long blind spot could hide a disconnect.
        r.problems.append(f"no sample for {longest_gap:g} s (interval {interval_s:g} s)")
    r.passed = not r.problems
    return r


def watch_t2(
    mgr: Manager,
    agent: str,
    duration_s: float,
    interval_s: float,
    enroll_timeout_s: float,
    max_keepalive_s: float,
    log: Path | None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    sleep: Callable[[float], None] = time.sleep,
) -> Result:
    """Watch the agent live for the enroll time plus the window, then score it."""
    samples: list[dict] = []
    out = log.open("a", encoding="utf-8") if log else None
    started = now()
    active_since: datetime | None = None
    try:
        while True:
            t = now()
            s = sample(mgr, agent, t)
            samples.append(s)
            if out:
                out.write(json.dumps(s, sort_keys=True) + "\n")
                out.flush()
            if active_since is None and s.get("status") == "active":
                active_since = t
            if active_since is None and (t - started).total_seconds() > enroll_timeout_s:
                break
            if active_since and (t - active_since).total_seconds() >= duration_s:
                break
            sleep(interval_s)
    finally:
        if out:
            out.close()
    return score_t2(samples, duration_s, max_keepalive_s, interval_s, enroll_timeout_s)


def read_samples(path: Path) -> list[dict]:
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


# ---------------------------------------------------------------- T3


def check_t3(agent: dict | None, host: dict) -> Result:
    """The manager's view of the agent against the resolved host profile."""
    r = Result("T3", False)
    if agent is None:
        r.problems.append("the manager does not know this agent")
        return r
    os_seen = agent.get("os") or {}
    info = host.get("os_info") or {}
    r.summary = {
        "manager_os_name": os_seen.get("name"),
        "manager_os_version": os_seen.get("version"),
        "manager_os_platform": os_seen.get("platform"),
        "manager_agent_version": agent.get("version"),
        "profile_product_name": info.get("product_name"),
        "profile_version": ".".join(str(x) for x in (info.get("version"), info.get("build")) if x),
    }
    name = info.get("product_name")
    if not name:
        r.problems.append("the profile has no os_info.product_name")
    elif name.lower() not in str(os_seen.get("name", "")).lower():
        r.problems.append(f"os.name {os_seen.get('name')!r} does not show {name!r}")
    want = r.summary["profile_version"]
    if want and not str(os_seen.get("version", "")).startswith(want):
        r.problems.append(f"os.version {os_seen.get('version')!r} does not start with {want!r}")
    if host.get("os") and os_seen.get("platform") != host["os"]:
        r.problems.append(f"os.platform {os_seen.get('platform')!r}, profile os {host['os']!r}")
    agent_version = (host.get("agent") or {}).get("version")
    if agent_version and agent_version not in str(agent.get("version", "")):
        r.problems.append(f"agent version {agent.get('version')!r}, profile {agent_version!r}")
    r.passed = not r.problems
    return r
