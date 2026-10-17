"""Named scenario actions.

Each action changes a host the way the real operation would: it updates the
engine's state and writes the events Windows writes for it. Every value in an
event comes from the host's state in the engine or from the step's parameters
(CLAUDE.md rule 5). Event layouts are in `events/windows.yaml`.

An action is a function `(host, params, time) -> None`. `host` is a `HostContext`;
`time` is when the step happens on that host's clock.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

import yaml

from . import corpus
from .clock import format_time
from .engine import EngineError

EVENTS_DIR = Path(__file__).parent / "events"
_PLACEHOLDER = re.compile(r"\{([a-z_][a-z0-9_]*)\}")
_INT_FIELDS = {"event_id", "qualifiers", "version", "level", "task", "opcode"}
_LOCAL_SID = re.compile(r"^(S-1-5-21-\d+-\d+-\d+)-(\d+)$")
_BUILTIN = "S-1-5-32-"
# Lookups the run log leaves out: they change nothing.
READ_OPS = {"section", "list", "proc.list", "proc.get", "resolved"}


class ScenarioError(Exception):
    """A step cannot run: bad parameters, or the host lacks a fact it needs."""


def load_events(os_name: str) -> dict[str, dict]:
    path = EVENTS_DIR / f"{os_name}.yaml"
    if not path.exists():
        return {}
    return yaml.safe_load(path.read_text(encoding="utf-8"))["events"]


def fill(value, values: dict, where: str):
    """Replace {name} placeholders. Braces holding anything else (GUIDs) stay."""
    if isinstance(value, str):

        def one(m: re.Match) -> str:
            key = m.group(1)
            if key not in values or values[key] is None:
                raise ScenarioError(f"{where}: no value for {{{key}}}")
            return str(values[key])

        return _PLACEHOLDER.sub(one, value)
    if isinstance(value, list):
        return [fill(v, values, where) for v in value]
    if isinstance(value, dict):
        return {k: fill(v, values, where) for k, v in value.items()}
    return value


@dataclass
class HostContext:
    """One host during a run: its engine connection, its events, and the run log."""

    host: str
    call: Callable  # call(op, **params) -> result; logged by the runner
    gap: Callable  # gap(text): an unmet need, written to the run log (rule 4)
    os: str
    defaults: dict = field(default_factory=dict)
    _events: dict | None = None
    _step: int = 0

    @property
    def events(self) -> dict:
        if self._events is None:
            self._events = load_events(self.os)
        return self._events

    # ------------------------------------------------------------ host facts

    def identity(self) -> dict:
        return self.call("section", name="identity") or {}

    def computer_short(self) -> str:
        name = self.identity().get("hostname")
        if not name:
            raise ScenarioError("the host profile has no identity.hostname")
        return name

    def users(self) -> list[dict]:
        return self.call("list", name="users")

    def user(self, name: str) -> dict:
        for u in self.users():
            if u["name"].lower() == name.lower():
                return u
        raise ScenarioError(f"no user {name!r} on {self.host}")

    def group(self, name_or_sid: str) -> dict:
        for g in self.call("list", name="groups"):
            if name_or_sid.lower() in (g["name"].lower(), str(g.get("sid", "")).lower()):
                return g
        raise ScenarioError(f"no group {name_or_sid!r} on {self.host}")

    def service(self, name: str) -> dict:
        for s in self.call("list", name="services"):
            if s["name"].lower() == name.lower():
                return s
        raise ScenarioError(f"no service {name!r} on {self.host}")

    def pid_of(self, image: str) -> int | None:
        for p in self.call("proc.list"):
            if p["image"].lower() == image.lower():
                return p["pid"]
        return None

    def host_identity(self) -> corpus.Identity:
        """This host's computer name, machine SID and process table."""
        return corpus.Identity(
            self.computer_short(),
            corpus.machine_sid(u.get("sid") for u in self.users()),
            {p["pid"]: p["image"] for p in self.call("proc.list")},
        )

    def logon_id(self, *parts: str) -> str:
        """A repeatable logon ID for a session, unique enough per host."""
        digest = hashlib.sha256("\0".join((self.host, *parts)).encode()).digest()
        return hex(0x10000 + int.from_bytes(digest[:3], "big"))

    def actor(self, params: dict) -> dict:
        """The account a step acts as: the step's `actor`, else the scenario's."""
        name = params.get("actor") or self.defaults.get("actor")
        if not name:
            raise ScenarioError("no actor: set defaults.actor or the step's actor")
        u = self.user(name)
        if not u.get("sid"):
            raise ScenarioError(f"user {u['name']!r} has no SID in the profile")
        return {
            "actor": u["name"],
            "actor_sid": u["sid"],
            "actor_domain": self.computer_short(),
            "actor_logon_id": self.logon_id("actor", u["name"].lower()),
        }

    # ------------------------------------------------------------ events

    def write_event(self, key: str, values: dict, time: datetime) -> int:
        template = self.events.get(key)
        if template is None:
            raise ScenarioError(f"no {self.os} event layout {key!r}")
        where = f"event {key}"
        event: dict = {}
        if key.isdigit():
            event["event_id"] = int(key)
        for name, value in template.items():
            if name in ("channel", "process", "data"):
                continue
            v = fill(value, values, where)
            event[name] = int(v) if name in _INT_FIELDS else v
        data = fill(template.get("data", {}), values, where)
        if isinstance(data, dict):
            event["data"] = [{"name": k, "value": str(v)} for k, v in data.items()]
        else:
            event["data"] = [{"value": str(v)} for v in data]
        image = template.get("process")
        if image:
            pid = self.pid_of(image)
            if pid is None:
                self.gap(f"event {key}: no running {image} for process_id; left out")
            else:
                event["process_id"] = pid
        channel = fill(template["channel"], values, where)
        result = self.call("evt.write", channel=channel, event=event, time=format_time(time))
        return result["record_id"]


# ---------------------------------------------------------------- the actions

ACTIONS: dict[str, Callable] = {}
PARAMS: dict[str, tuple[set[str], set[str]]] = {}  # action -> (required, optional)


def action(name: str, required: tuple = (), optional: tuple = ()):
    def register(fn):
        ACTIONS[name] = fn
        PARAMS[name] = (set(required), set(optional))
        return fn

    return register


def check_params(name: str, params: dict) -> list[str]:
    """Problems with a step's action and parameters, before anything runs."""
    if name not in ACTIONS:
        return [f"unknown action {name!r}"]
    required, optional = PARAMS[name]
    problems = [f"{name}: missing parameter {p!r}" for p in sorted(required - params.keys())]
    problems += [
        f"{name}: unknown parameter {p!r}" for p in sorted(params.keys() - required - optional)
    ]
    return problems


def _ms(time: datetime, n: int) -> datetime:
    """Events of one step are a millisecond apart, in the order Windows writes them."""
    return time + timedelta(milliseconds=n)


@action("marker", required=("event_id",), optional=("source", "log", "description"))
def marker(h: HostContext, p: dict, time: datetime) -> None:
    """eventcreate.exe: an Information event from a named source."""
    h.write_event(
        "marker",
        {
            "event_id": p["event_id"],
            "source": p.get("source", "xvm-scenario"),
            "log": p.get("log", "Application"),
            "description": p.get("description", ""),
        },
        time,
    )


def _user_values(h: HostContext, user: dict) -> dict:
    if not user.get("sid"):
        raise ScenarioError(f"user {user['name']!r} has no SID in the profile")
    return {"user": user["name"], "user_sid": user["sid"], "computer_short": h.computer_short()}


def _next_sid(h: HostContext) -> str:
    """The machine's SID prefix from its local accounts, and the next free RID from 1000."""
    prefix, rid = None, 999
    for u in h.users():
        m = _LOCAL_SID.match(str(u.get("sid", "")))
        if m:
            prefix = prefix or m.group(1)
            if m.group(1) == prefix:
                rid = max(rid, int(m.group(2)))
    if prefix is None:
        raise ScenarioError("no local account with an S-1-5-21 SID: cannot derive the machine SID")
    return f"{prefix}-{rid + 1}"


def _group_values(h: HostContext, group: dict) -> dict:
    sid = group.get("sid")
    if not sid:
        raise ScenarioError(f"group {group['name']!r} has no SID in the profile")
    domain = "Builtin" if sid.startswith(_BUILTIN) else h.computer_short()
    return {"group": group["name"], "group_sid": sid, "group_domain": domain}


@action("user.create", required=("name",), optional=("sid", "groups", "enabled", "actor"))
def user_create(h: HostContext, p: dict, time: datetime) -> None:
    """New-LocalUser: 4720 created, 4722 enabled, 4724 password set, 4738 changed."""
    name = p["name"]
    if any(u["name"].lower() == name.lower() for u in h.users()):
        raise ScenarioError(f"user {name!r} already exists on {h.host}")
    enabled = p.get("enabled", True)
    item = {"name": name, "sid": p.get("sid") or _next_sid(h), "enabled": enabled, "groups": []}
    h.call("list.upsert", name="users", item=item, time=format_time(time))
    values = {**h.actor(p), **_user_values(h, item)}
    ids = ["4720", "4722", "4724", "4738"] if enabled else ["4720", "4724", "4738"]
    for n, key in enumerate(ids):
        h.write_event(key, values, _ms(time, n))
    for n, g in enumerate(p.get("groups", []), start=len(ids)):
        group_add(h, {"user": name, "group": g, **_actor_param(p)}, _ms(time, n))


def _actor_param(p: dict) -> dict:
    return {"actor": p["actor"]} if "actor" in p else {}


@action("user.delete", required=("name",), optional=("actor",))
def user_delete(h: HostContext, p: dict, time: datetime) -> None:
    """Remove-LocalUser: 4726."""
    user = h.user(p["name"])
    values = {**h.actor(p), **_user_values(h, user)}
    h.call("list.remove", name="users", item=user["name"], time=format_time(time))
    h.write_event("4726", values, time)


def _membership(h: HostContext, p: dict, time: datetime, add: bool) -> None:
    user = h.user(p["user"])
    group = h.group(p["group"])
    groups = list(user.get("groups", []))
    member = any(g.lower() == group["name"].lower() for g in groups)
    if add and member:
        raise ScenarioError(f"{user['name']} is already in {group['name']}")
    if not add and not member:
        raise ScenarioError(f"{user['name']} is not in {group['name']}")
    if add:
        groups.append(group["name"])
    else:
        groups = [g for g in groups if g.lower() != group["name"].lower()]
    values = {**h.actor(p), **_user_values(h, user), **_group_values(h, group)}
    h.call(
        "list.upsert",
        name="users",
        item={"name": user["name"], "groups": groups},
        time=format_time(time),
    )
    h.write_event("4732" if add else "4733", values, time)


@action("group.add", required=("user", "group"), optional=("actor",))
def group_add(h: HostContext, p: dict, time: datetime) -> None:
    """Add-LocalGroupMember: 4732. `group` is a name or a SID."""
    _membership(h, p, time, add=True)


@action("group.remove", required=("user", "group"), optional=("actor",))
def group_remove(h: HostContext, p: dict, time: datetime) -> None:
    """Remove-LocalGroupMember: 4733."""
    _membership(h, p, time, add=False)


_LOGON = (
    "count",
    "domain",
    "logon_type",
    "workstation",
    "ip_address",
    "ip_port",
)


def _logon_values(h: HostContext, p: dict) -> dict:
    short = h.computer_short()
    return {
        "user": p["user"],
        "target_domain": p.get("domain", short),
        "logon_type": p.get("logon_type", 3),
        "workstation": p.get("workstation", short),
        "ip_address": p.get("ip_address", "-"),
        "ip_port": p.get("ip_port", "-"),
    }


@action("logon.failed", required=("user",), optional=(*_LOGON, "status", "sub_status"))
def logon_failed(h: HostContext, p: dict, time: datetime) -> None:
    """A rejected logon: 4625, `count` times. The user need not exist."""
    values = {
        **_logon_values(h, p),
        "status": p.get("status", "0xc000006d"),
        "sub_status": p.get("sub_status", "0xc000006a"),
    }
    for n in range(int(p.get("count", 1))):
        h.write_event("4625", values, _ms(time, n))


@action("logon.success", required=("user",), optional=_LOGON)
def logon_success(h: HostContext, p: dict, time: datetime) -> None:
    """An accepted logon: 4624 v2, `count` times, each with its own logon ID."""
    user = h.user(p["user"])
    values = {**_logon_values(h, p), **_user_values(h, user)}
    values["user"] = user["name"]
    for n in range(int(p.get("count", 1))):
        t = _ms(time, n)
        values["logon_id"] = h.logon_id("logon", user["name"].lower(), format_time(t))
        h.write_event("4624", values, t)


def _service_state(h: HostContext, name: str, state: str, time: datetime) -> None:
    svc = h.service(name)
    if svc.get("state") == state:
        raise ScenarioError(f"service {svc['name']} is already {state}")
    h.call(
        "list.upsert",
        name="services",
        item={"name": svc["name"], "state": state},
        time=format_time(time),
    )
    display = svc.get("display_name") or svc["name"]
    h.write_event("7036", {"display_name": display, "state": state}, time)


@action("service.stop", required=("name",))
def service_stop(h: HostContext, p: dict, time: datetime) -> None:
    """Stop-Service: 7036 stopped."""
    _service_state(h, p["name"], "stopped", time)


@action("service.start", required=("name",))
def service_start(h: HostContext, p: dict, time: datetime) -> None:
    """Start-Service: 7036 running."""
    _service_state(h, p["name"], "running", time)


@action("service.restart", required=("name",))
def service_restart(h: HostContext, p: dict, time: datetime) -> None:
    """Restart-Service: 7036 stopped, then 7036 running."""
    _service_state(h, p["name"], "stopped", time)
    _service_state(h, p["name"], "running", _ms(time, 1))


def _content(p: dict) -> str:
    if "text" in p and "base64" in p:
        raise ScenarioError("give text or base64, not both")
    if "base64" in p:
        return p["base64"]
    return base64.b64encode(str(p.get("text", "")).encode()).decode()


@action("file.write", required=("path",), optional=("text", "base64"))
def file_write(h: HostContext, p: dict, time: datetime) -> None:
    """Create or replace a file. The folder must exist."""
    h.call("file.write", path=p["path"], data=_content(p), time=format_time(time))


@action("file.append", required=("path",), optional=("text", "base64"))
def file_append(h: HostContext, p: dict, time: datetime) -> None:
    h.call("file.write", path=p["path"], data=_content(p), append=True, time=format_time(time))


@action("file.delete", required=("path",), optional=("recursive",))
def file_delete(h: HostContext, p: dict, time: datetime) -> None:
    h.call(
        "file.delete",
        path=p["path"],
        recursive=bool(p.get("recursive", False)),
        time=format_time(time),
    )


@action("file.mkdir", required=("path",), optional=("exist_ok",))
def file_mkdir(h: HostContext, p: dict, time: datetime) -> None:
    """New-Item -ItemType Directory. With `exist_ok`, an existing folder is fine."""
    try:
        h.call("file.mkdir", path=p["path"], time=format_time(time))
    except EngineError as e:
        if not (e.code == "exists" and p.get("exist_ok")):
            raise


@action("file.rename", required=("from", "to"))
def file_rename(h: HostContext, p: dict, time: datetime) -> None:
    h.call("file.rename", **{"from": p["from"], "to": p["to"]}, time=format_time(time))


@action(
    "process.start",
    required=("image",),
    optional=("path", "command_line", "user", "session", "parent", "pid"),
)
def process_start(h: HostContext, p: dict, time: datetime) -> None:
    """A process starts. `parent` is an image name or a PID. No audit event is
    written: process auditing is off by default, and the census has not shown
    an agent reading 4688."""
    params = {
        k: p[k] for k in ("image", "path", "command_line", "user", "session", "pid") if k in p
    }
    parent = p.get("parent")
    if parent is not None:
        pid = parent if isinstance(parent, int) else h.pid_of(str(parent))
        if pid is None:
            raise ScenarioError(f"no running process {parent!r} to be the parent")
        params["parent_pid"] = pid
    h.call("proc.start", **params, time=format_time(time))


@action("process.exit", optional=("image", "pid", "exit_code"))
def process_exit(h: HostContext, p: dict, time: datetime) -> None:
    """A process ends: by `pid`, or the newest running process of `image`."""
    if ("pid" in p) == ("image" in p):
        raise ScenarioError("process.exit takes pid or image")
    pid = p.get("pid")
    if pid is None:
        running = [x for x in h.call("proc.list") if x["image"].lower() == p["image"].lower()]
        if not running:
            raise ScenarioError(f"no running process {p['image']!r}")
        pid = max(running, key=lambda x: (x["start_time"], x["pid"]))["pid"]
    params = {"pid": pid, "time": format_time(time)}
    if "exit_code" in p:
        params["exit_code"] = p["exit_code"]
    h.call("proc.exit", **params)


@action("registry.set", required=("key", "name", "type", "data"))
def registry_set(h: HostContext, p: dict, time: datetime) -> None:
    h.call(
        "reg.set_value",
        key=p["key"],
        name=p["name"],
        type=p["type"],
        data=p["data"],
        time=format_time(time),
    )


@action("registry.delete_value", required=("key", "name"))
def registry_delete_value(h: HostContext, p: dict, time: datetime) -> None:
    h.call("reg.delete_value", key=p["key"], name=p["name"], time=format_time(time))


@action("registry.delete_key", required=("key",), optional=("recursive",))
def registry_delete_key(h: HostContext, p: dict, time: datetime) -> None:
    h.call(
        "reg.delete_key",
        key=p["key"],
        recursive=bool(p.get("recursive", False)),
        time=format_time(time),
    )


@action("event", required=("channel", "event"))
def raw_event(h: HostContext, p: dict, time: datetime) -> None:
    """Any event, written as given. For events no named action covers yet."""
    h.call("evt.write", channel=p["channel"], event=p["event"], time=format_time(time))


@action("replay.event", required=("event", "source"))
def replay_event(h: HostContext, p: dict, time: datetime) -> None:
    """A captured event, rewritten to name this host instead of the capture VM.
    `source` is the capture's identity (`corpus.Identity.to_json`)."""
    event = dict(p["event"])
    channel = event.pop("channel", None)
    if not channel:
        raise ScenarioError("replayed event has no channel")
    event.pop("time", None)
    out, notes = corpus.rewrite(event, corpus.Identity.from_json(p["source"]), h.host_identity())
    for n in notes:
        h.gap(n)
    h.call("evt.write", channel=channel, event=out, time=format_time(time))
