"""Load, check and run scenarios against the host-state engine.

A run plays every step on every host. Each host has its own clock
(`clock.HostClock`), so the same step lands at slightly different times on
different hosts. Steps run in the order of those times across all hosts. Every
engine call, its result, and every gap go to a JSON Lines run log.
"""

from __future__ import annotations

import json
import time as systime
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import yaml

from . import actions
from .clock import HostClock, format_time, parse_duration
from .engine import Engine, EngineError

SCHEMA = Path(__file__).parent / "schema" / "scenario.schema.json"


class ScenarioInvalid(Exception):
    def __init__(self, problems: list[str]):
        super().__init__("\n".join(problems))
        self.problems = problems


@dataclass
class Step:
    index: int
    offset: float
    action: str
    params: dict
    name: str


@dataclass
class Scenario:
    name: str
    os: str
    defaults: dict
    steps: list[Step]


def _reject_timestamps(node, path="") -> list[str]:
    """YAML turns unquoted dates into datetime objects. Ask for quotes instead."""
    if isinstance(node, datetime) or type(node).__name__ == "date":
        return [f"{path or '/'}: quote dates and times"]
    if isinstance(node, dict):
        return [p for k, v in node.items() for p in _reject_timestamps(v, f"{path}/{k}")]
    if isinstance(node, list):
        return [p for i, v in enumerate(node) for p in _reject_timestamps(v, f"{path}/{i}")]
    return []


def parse(doc: dict) -> Scenario:
    """Check a scenario document and return it ready to run."""
    problems = _reject_timestamps(doc)
    if problems:
        raise ScenarioInvalid(problems)
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(jsonschema.Draft202012Validator(schema).iter_errors(doc), key=str)
    if errors:
        raise ScenarioInvalid(
            [f"/{'/'.join(map(str, e.absolute_path))}: {e.message}" for e in errors]
        )
    steps, last = [], 0.0
    for i, raw in enumerate(doc["steps"]):
        label = f"step {i + 1}"
        offset = parse_duration(raw["at"])
        if offset < last:
            problems.append(f"{label}: at {raw['at']} is before the step above it")
        last = max(last, offset)
        params = raw.get("params", {})
        problems += [f"{label}: {p}" for p in actions.check_params(raw["action"], params)]
        steps.append(Step(i + 1, offset, raw["action"], params, raw.get("name", raw["action"])))
    if doc["os"] != "windows":
        problems.append(f"os {doc['os']}: only windows scenarios have actions so far")
    if problems:
        raise ScenarioInvalid(problems)
    return Scenario(doc["name"], doc["os"], doc.get("defaults", {}), steps)


def load(path: Path) -> Scenario:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ScenarioInvalid([f"{path}: {e}"]) from e
    if not isinstance(doc, dict):
        raise ScenarioInvalid([f"{path}: not a mapping"])
    return parse(doc)


@dataclass
class Planned:
    host: str
    step: Step
    at: datetime


def plan(sc: Scenario, clocks: dict[str, HostClock]) -> list[Planned]:
    """Every step on every host, in the order the hosts' clocks put them."""
    out = [
        Planned(host, step, clock.at(step.offset, step.index))
        for host, clock in clocks.items()
        for step in sc.steps
    ]
    hosts = list(clocks)
    out.sort(key=lambda p: (p.at, p.step.index, hosts.index(p.host)))
    # A host's own steps keep their order even if jitter would swap them.
    seen: dict[str, datetime] = {}
    for p in sorted(out, key=lambda p: (hosts.index(p.host), p.step.index)):
        if p.host in seen and p.at < seen[p.host]:
            p.at = seen[p.host]
        seen[p.host] = p.at
    out.sort(key=lambda p: (p.at, p.step.index, hosts.index(p.host)))
    return out


class RunLog:
    def __init__(self, path: Path | None):
        self._f = path.open("a", encoding="utf-8") if path else None
        self.errors = 0
        self.gaps = 0

    def write(self, record: dict) -> None:
        if record.get("record") == "step" and not record.get("ok"):
            self.errors += 1
        if "gap" in record:
            self.gaps += 1
        if self._f:
            self._f.write(json.dumps(record, sort_keys=True) + "\n")
            self._f.flush()

    def close(self) -> None:
        if self._f:
            self._f.close()


def run(
    sc: Scenario,
    socket_path: Path | str,
    hosts: list[str],
    start: datetime | None = None,
    speed: float = 1.0,
    seed: str = "",
    max_skew: float = 0.0,
    jitter: float = 0.0,
    log: RunLog | None = None,
    stop_on_error: bool = False,
) -> RunLog:
    """Play the scenario on each host. With `speed` 0 the steps run back to back;
    otherwise the runner waits so step offsets pass at `speed` times real time."""
    log = log or RunLog(None)
    start = start or datetime.now(UTC)
    clocks = {h: HostClock(h, start, seed or sc.name, max_skew, jitter) for h in hosts}
    conns: dict[str, Engine] = {}
    contexts: dict[str, actions.HostContext] = {}
    t0 = systime.monotonic()
    try:
        for h in hosts:
            conns[h] = Engine(socket_path, h)
            if conns[h].hello.get("os") != sc.os:
                raise ScenarioInvalid([f"host {h} is {conns[h].hello.get('os')}, not {sc.os}"])
        log.write(
            {
                "record": "start",
                "scenario": sc.name,
                "start": format_time(start),
                "seed": seed or sc.name,
                "hosts": {h: {"skew_s": round(c.skew, 3)} for h, c in clocks.items()},
            }
        )
        for p in plan(sc, clocks):
            if speed > 0:
                wait = (p.at - start).total_seconds() / speed - (systime.monotonic() - t0)
                if wait > 0:
                    systime.sleep(wait)
            ctx = contexts.get(p.host)
            if ctx is None:
                ctx = contexts[p.host] = _context(conns[p.host], p.host, sc, log)
            ctx._step = p.step.index  # for the log records the action makes
            base = {"host": p.host, "step": p.step.index, "name": p.step.name}
            try:
                actions.ACTIONS[p.step.action](ctx, p.step.params, p.at)
                log.write(
                    {
                        **base,
                        "record": "step",
                        "action": p.step.action,
                        "time": format_time(p.at),
                        "ok": True,
                    }
                )
            except (actions.ScenarioError, EngineError) as e:
                log.write(
                    {
                        **base,
                        "record": "step",
                        "action": p.step.action,
                        "time": format_time(p.at),
                        "ok": False,
                        "error": str(e),
                    }
                )
                if stop_on_error:
                    break
        log.write({"record": "end", "errors": log.errors, "gaps": log.gaps})
    finally:
        for c in conns.values():
            c.close()
    return log


def _context(conn: Engine, host: str, sc: Scenario, log: RunLog) -> actions.HostContext:
    ctx: actions.HostContext

    def call(op: str, **params):
        rec = {"host": host, "step": ctx._step, "record": "call", "op": op, "params": params}
        try:
            result = conn.call(op, **params)
        except EngineError as e:
            log.write({**rec, "error": {"code": e.code, "message": e.message}})
            raise
        if op not in actions.READ_OPS:
            log.write({**rec, "result": result})
        return result

    def gap(text: str) -> None:
        log.write({"host": host, "step": ctx._step, "record": "gap", "gap": text})

    ctx = actions.HostContext(host=host, call=call, gap=gap, os=sc.os, defaults=sc.defaults)
    return ctx
