"""Build a Windows base image from a golden capture (scenarios/golden/windows).

A base image holds what many hosts share. Facts that identify one machine are
left out, so each host profile must supply them:

| Left out | Why |
| --- | --- |
| Host name and domain, in `identity` and in the registry | Per host |
| MAC and IP addresses, gateway, DNS servers | Per host |
| BIOS and system serial numbers | Per host |
| Wazuh service and Wazuh Agent package | Our installer step adds them from the host profile |
| The scenario test user | Deleted during the capture |
| The capture's PowerShell tree and the Wazuh agent processes | Not part of the OS at boot |
| The boot time | Per host; the engine boots each host itself |
| The VM's name in process owners | Written as `.\\user`, meaning the host itself |

Event message templates are derived from the capture's rendered events (see
evtmsg.py). Software comes from the Uninstall registry keys. Users, groups, services,
hardware, processes and file metadata come from the host JSON files. Files
carry metadata and the captured SHA-256 only, never bytes (CLAUDE.md rule 1).
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from xvm_golden import baseline

from . import evtmsg, profile, regfile

# Registry exports that become registry keys in the base. The others are
# converted into structured sections or dropped.
REGISTRY_EXPORTS = (
    "os-currentversion",
    "os-currentversion-wow64",
    "computername",
    "tcpip-parameters",
    "profilelist",
    "timezone",
    "codepage",
    "cpu0",
    "environment",
    "eventlog-security",
    "eventlog-system",
    "eventlog-application",
)
UNINSTALL_EXPORTS = {"uninstall": "x86_64", "uninstall-wow64": "x86"}
# Values that name this machine. (key suffix, value name), compared without case.
IDENTITY_VALUES = (
    (r"Control\ComputerName\ComputerName", "ComputerName"),
    (r"Control\ComputerName\ActiveComputerName", "ComputerName"),
    (r"Services\Tcpip\Parameters", "Hostname"),
    (r"Services\Tcpip\Parameters", "NV Hostname"),
    (r"Services\Tcpip\Parameters", "Domain"),
    (r"Services\Tcpip\Parameters", "NV Domain"),
    (r"Services\Tcpip\Parameters", "DhcpDomain"),
)
# Per-interface keys under Tcpip\Parameters\Interfaces hold this machine's addresses.
INTERFACE_KEYS = re.compile(r"(?i)\\Services\\Tcpip\\Parameters\\(Interfaces|Adapters)(\\|$)")
AGENT_SERVICES = ("WazuhSvc",)
AGENT_PACKAGES = re.compile(r"(?i)^wazuh agent\b")
TEST_USERS = ("xvmgolden",)
START_MODES = {
    "auto": "auto",
    "manual": "manual",
    "disabled": "disabled",
    "boot": "boot",
    "system": "system",
}
_MS_DATE = re.compile(r"^/Date\((-?\d+)(?:[+-]\d{4})?\)/$")


class ConvertError(ValueError):
    pass


def _read_json(path: Path):
    """Read capture JSON. A single object becomes a one-element list where a list is expected."""
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _instant(value) -> datetime | None:
    """Accept Windows PowerShell 5.1 "/Date(ms)/" and ISO 8601 text, at full precision."""
    if not value:
        return None
    if isinstance(value, dict) and "value" in value:  # PowerShell 7 DateTime with extras
        value = value["value"]
    m = _MS_DATE.match(str(value))
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, UTC)
    dt = baseline.parse_time(str(value))
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def _date(value) -> str | None:
    """ISO UTC text to the second, as profiles store times."""
    dt = _instant(value)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else None


def _identity_value(key: str, name: str) -> bool:
    k = key.lower()
    return any(
        k.endswith(suffix.lower()) and name.lower() == v.lower() for suffix, v in IDENTITY_VALUES
    )


def _registry(root: Path, notes: list[str]) -> dict[str, dict]:
    keys: dict[str, dict] = {}
    for name in REGISTRY_EXPORTS:
        path = root / "registry" / f"{name}.reg"
        if not path.is_file():
            notes.append(f"registry export missing: {name}.reg")
            continue
        exp = regfile.parse(regfile.decode(path.read_bytes()))
        notes.extend(f"{name}.reg: skipped {s}" for s in exp.skipped)
        for key, values in exp.keys.items():
            if INTERFACE_KEYS.search(key):
                continue
            kept = {n: v for n, v in values.items() if not _identity_value(key, n)}
            keys.setdefault(key, {}).update(kept)
    return dict(sorted(keys.items(), key=lambda kv: kv[0].lower()))


def _software(root: Path, notes: list[str]) -> list[dict]:
    found: dict[str, dict] = {}
    for name, arch in UNINSTALL_EXPORTS.items():
        path = root / "registry" / f"{name}.reg"
        if not path.is_file():
            continue
        exp = regfile.parse(regfile.decode(path.read_bytes()))
        for values in exp.keys.values():
            display = values.get("DisplayName", {}).get("data")
            if not display or values.get("SystemComponent", {}).get("data") == 1:
                continue
            if AGENT_PACKAGES.match(display):
                continue
            entry = {"name": display, "architecture": arch}
            for field, value_name in (
                ("version", "DisplayVersion"),
                ("vendor", "Publisher"),
                ("location", "InstallLocation"),
            ):
                v = values.get(value_name, {}).get("data")
                if v:
                    entry[field] = v
            date = values.get("InstallDate", {}).get("data")
            if date and re.fullmatch(r"\d{8}", date):
                entry["install_date"] = f"{date[:4]}-{date[4:6]}-{date[6:]}"
            if display.lower() in found:
                notes.append(f"software listed twice, kept the first: {display}")
                continue
            found[display.lower()] = entry
    return sorted(found.values(), key=lambda e: e["name"].lower())


def _os_info(root: Path, keys: dict[str, dict]) -> dict:
    os_json = _as_list(_read_json(root / "host" / "os.json"))
    if not os_json:
        raise ConvertError("host/os.json is missing or empty")
    o = os_json[0]
    cv = keys.get(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", {})

    def reg(name):
        return cv.get(name, {}).get("data")

    # Agents read ProductName from the registry, so it wins over the WMI caption.
    info: dict = {"product_name": reg("ProductName") or o.get("Caption")}
    full = str(o.get("Version") or "")
    if full.count(".") >= 2:
        info["version"] = ".".join(full.split(".")[:2])
    info["build"] = str(o.get("BuildNumber") or reg("CurrentBuildNumber"))
    for field, name in (("edition", "EditionID"), ("display_version", "DisplayVersion")):
        if reg(name):
            info[field] = reg(name)
    if isinstance(reg("UBR"), int):
        info["ubr"] = reg("UBR")
    arch = str(o.get("OSArchitecture") or "")
    if "64" in arch and "ARM" not in arch.upper():
        info["architecture"] = "x86_64"
    elif "ARM" in arch.upper():
        info["architecture"] = "arm64"
    elif arch:
        info["architecture"] = "x86"
    if installed := _date(o.get("InstallDate")):
        info["install_date"] = installed
    locale = _read_json(root / "host" / "locale.json") or {}
    if locale.get("culture"):
        info["locale"] = locale["culture"]
    if locale.get("timezone"):
        info["timezone"] = locale["timezone"]
    return {k: v for k, v in info.items() if v not in (None, "", "None")}


def _hardware(root: Path) -> dict:
    hw: dict = {}
    cpus = _as_list(_read_json(root / "host" / "cpu.json"))
    if cpus:
        c = cpus[0]
        hw["cpu"] = {
            k: v
            for k, v in {
                "name": (c.get("Name") or "").strip() or None,
                "vendor": c.get("Manufacturer"),
                "cores": sum(int(x.get("NumberOfCores") or 0) for x in cpus) or None,
                "logical_processors": sum(
                    int(x.get("NumberOfLogicalProcessors") or 0) for x in cpus
                )
                or None,
                "mhz": c.get("MaxClockSpeed"),
            }.items()
            if v
        }
    comp = _as_list(_read_json(root / "host" / "computer.json"))
    if comp:
        c = comp[0]
        if c.get("TotalPhysicalMemory"):
            hw["memory_mb"] = int(c["TotalPhysicalMemory"]) // (1024 * 1024)
        system = {
            k: v
            for k, v in {"manufacturer": c.get("Manufacturer"), "model": c.get("Model")}.items()
            if v
        }
        if system:
            hw["system"] = system
    bios = _as_list(_read_json(root / "host" / "bios.json"))
    if bios:
        b = bios[0]
        entry = {"vendor": b.get("Manufacturer"), "version": b.get("SMBIOSBIOSVersion")}
        if released := _date(b.get("ReleaseDate")):
            entry["release_date"] = released[:10]
        entry = {k: v for k, v in entry.items() if v}
        if entry:
            hw["bios"] = entry
    return hw


# IF_OPER_STATUS values (ifOperStatus) as profile names.
OPER_STATUS = {
    1: "up",
    2: "down",
    3: "testing",
    4: "unknown",
    5: "dormant",
    6: "not_present",
    7: "lower_layer_down",
}


def _network(root: Path) -> dict:
    """Adapters without the facts that name this machine (GUID, MAC, addresses)."""
    adapters = _as_list(_read_json(root / "host" / "netadapters.json"))
    configs = _as_list(_read_json(root / "host" / "network.json"))
    ipv4 = _as_list(_read_json(root / "host" / "netipinterfaces.json"))
    dhcp = {c.get("Description"): bool(c.get("DHCPEnabled")) for c in configs}
    metric = {i.get("InterfaceIndex"): i.get("InterfaceMetric") for i in ipv4}
    interfaces = []
    for a in adapters:
        entry = {"name": a["Name"]}
        if a.get("InterfaceDescription"):
            entry["description"] = a["InterfaceDescription"]
            if a["InterfaceDescription"] in dhcp:
                entry["dhcp"] = dhcp[a["InterfaceDescription"]]
        for field, key in (("index", "ifIndex"), ("type", "InterfaceType"), ("mtu", "MtuSize")):
            if isinstance(a.get(key), int):
                entry[field] = a[key]
        if isinstance(a.get("Speed"), int):
            entry["speed"] = a["Speed"]
        if a.get("ifOperStatus") in OPER_STATUS:
            entry["status"] = OPER_STATUS[a["ifOperStatus"]]
        if isinstance(metric.get(a.get("ifIndex")), int):
            entry["metric"] = metric[a["ifIndex"]]
        interfaces.append(entry)
    return {"interfaces": interfaces} if interfaces else {}


def _hotfixes(root: Path) -> list[dict]:
    out = []
    for h in _as_list(_read_json(root / "host" / "hotfixes.json")):
        if not h.get("HotFixID"):
            continue
        entry = {"name": h["HotFixID"]}
        if h.get("Description"):
            entry["description"] = h["Description"]
        installed = _instant(h.get("InstalledOn"))
        if installed:
            entry["installed_on"] = installed.strftime("%Y-%m-%d")
        if h.get("InstalledBy"):
            entry["installed_by"] = h["InstalledBy"]
        out.append(entry)
    return out


def _accounts(root: Path) -> tuple[list[dict], list[dict]]:
    groups = []
    for g in _as_list(_read_json(root / "host" / "groups.json")):
        entry = {"name": g["Name"]}
        if isinstance(g.get("SID"), str):
            entry["sid"] = g["SID"]
        groups.append(entry)
    membership: dict[str, list[str]] = {}
    for m in _as_list(_read_json(root / "host" / "group-members.json")):
        if str(m.get("source", "")).lower() not in ("", "local"):
            continue
        user = str(m["member"]).split("\\")[-1].lower()
        membership.setdefault(user, []).append(m["group"])
    users = []
    for u in _as_list(_read_json(root / "host" / "users.json")):
        if u["Name"].lower() in TEST_USERS:
            continue
        entry = {"name": u["Name"], "enabled": bool(u.get("Enabled"))}
        if isinstance(u.get("SID"), str):
            entry["sid"] = u["SID"]
        if membership.get(u["Name"].lower()):
            entry["groups"] = sorted(membership[u["Name"].lower()])
        users.append(entry)
    return users, groups


def _services(root: Path) -> list[dict]:
    out = []
    for s in _as_list(_read_json(root / "host" / "services.json")):
        if s["Name"] in AGENT_SERVICES:
            continue
        entry = {"name": s["Name"]}
        if s.get("DisplayName"):
            entry["display_name"] = s["DisplayName"]
        state = str(s.get("State", "")).lower()
        if state in ("running", "stopped"):
            entry["state"] = state
        mode = START_MODES.get(str(s.get("StartMode", "")).lower())
        if mode:
            entry["start_mode"] = mode
        if s.get("PathName"):
            entry["path"] = s["PathName"]
        if s.get("StartName"):
            entry["account"] = s["StartName"]
        out.append(entry)
    return sorted(out, key=lambda e: e["name"].lower())


# Windows FileAttributes names (as PowerShell prints them) to profile attributes.
FILE_ATTRIBUTES = {
    "readonly": "readonly",
    "hidden": "hidden",
    "system": "system",
    "archive": "archive",
    "compressed": "compressed",
    "encrypted": "encrypted",
    "temporary": "temporary",
    "offline": "offline",
    "notcontentindexed": "not_content_indexed",
    "sparsefile": "sparse",
    "reparsepoint": "reparse_point",
}
# Processes that belong to the agent, not to the OS. Lower case.
AGENT_PROCESSES = ("wazuh-agent.exe", "ossec-agent.exe")
# Pinned PIDs: fixed on every Windows host.
FIXED_PIDS = {"system idle process": 0, "system": 4}


def _files(root: Path, notes: list[str]) -> list[dict]:
    out: list[dict] = []
    for f in _as_list(_read_json(root / "host" / "files.json")):
        path = str(f.get("path", ""))
        if not profile._WIN_PATH.match(path):
            notes.append(f"file skipped, not a plain absolute path: {path}")
            continue
        entry: dict = {"path": path}
        if f.get("dir"):
            entry["type"] = "dir"
        else:
            if isinstance(f.get("size"), int):
                entry["size"] = f["size"]
            if isinstance(f.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", f["sha256"]):
                entry["sha256"] = f["sha256"]
        for field in ("created", "modified", "accessed"):
            if t := _date(f.get(field)):
                entry[field] = t
        names = [a.strip().lower() for a in str(f.get("attributes", "")).split(",")]
        attrs = sorted({FILE_ATTRIBUTES[a] for a in names if a in FILE_ATTRIBUTES})
        if attrs:
            entry["attributes"] = attrs
        out.append(entry)
    # Folders listed only as parents of captured files stay implied.
    return out


def _processes(root: Path, manifest: dict, notes: list[str]) -> list[dict]:
    procs = _as_list(_read_json(root / "host" / "processes.json"))
    os_json = _as_list(_read_json(root / "host" / "os.json"))
    boot = _instant(os_json[0].get("LastBootUpTime")) if os_json else None
    by_pid = {p["ProcessId"]: p for p in procs if isinstance(p.get("ProcessId"), int)}
    children: dict[int, list[int]] = {}
    for p in by_pid.values():
        children.setdefault(p.get("ParentProcessId"), []).append(p["ProcessId"])

    # Drop the capture's own PowerShell tree and the agent's processes, with their children.
    dropped: set[int] = set()
    roots = [manifest.get("capture_pid")] + [
        pid for pid, p in by_pid.items() if str(p.get("Name", "")).lower() in AGENT_PROCESSES
    ]
    stack = [r for r in roots if r in by_pid]
    while stack:
        pid = stack.pop()
        if pid in dropped:
            continue
        dropped.add(pid)
        stack.extend(c for c in children.get(pid, []) if c != pid)
    if manifest.get("capture_pid") not in by_pid:
        notes.append("capture PowerShell process not found in processes.json")

    def start(p: dict) -> datetime:
        # Processes without a start time (System Idle) sort first.
        return _instant(p.get("CreationDate")) or datetime.min.replace(tzinfo=UTC)

    kept = sorted(
        (p for pid, p in by_pid.items() if pid not in dropped),
        key=lambda p: (start(p), p["ProcessId"]),
    )
    ids: dict[int, str] = {}
    counts: dict[str, int] = {}
    for p in kept:
        stem = re.sub(r"\.exe$", "", str(p.get("Name", "process")).lower())
        stem = re.sub(r"[^a-z0-9._-]+", "-", stem).strip("-.") or "process"
        counts[stem] = counts.get(stem, 0) + 1
        ids[p["ProcessId"]] = stem if counts[stem] == 1 else f"{stem}-{counts[stem]}"
    machine = str(manifest.get("host", {}).get("name") or "").lower()

    def owner(value: str) -> str:
        # Local accounts name the capture VM; ".\\user" means "this host" (rule 5).
        domain, sep, user = value.partition("\\")
        if sep and machine and domain.lower() == machine:
            return f".\\{user}"
        return value

    out = []
    for p in kept:
        name = str(p.get("Name") or "")
        entry: dict = {"id": ids[p["ProcessId"]], "image": name or "unknown"}
        if name.lower() in FIXED_PIDS and p["ProcessId"] == FIXED_PIDS[name.lower()]:
            entry["pid"] = p["ProcessId"]
        for field, src in (
            ("path", "ExecutablePath"),
            ("command_line", "CommandLine"),
        ):
            if p.get(src):
                entry[field] = str(p[src])
        if p.get("Owner"):
            entry["user"] = owner(str(p["Owner"]))
        if isinstance(p.get("SessionId"), int):
            entry["session"] = p["SessionId"]
        parent = p.get("ParentProcessId")
        # Parent PID 0 means no parent on Windows.
        if parent and parent in ids and parent != p["ProcessId"]:
            entry["parent"] = ids[parent]
        started = _instant(p.get("CreationDate"))
        if boot and started:
            offset = (started - boot).total_seconds()
            entry["start_offset_s"] = max(0, round(offset, 3))
        out.append(entry)
    return out


def _event_messages(root: Path, notes: list[str]) -> dict:
    templates, derive_notes = evtmsg.from_capture(root)
    notes.extend(f"event messages: {n}" for n in derive_notes)
    return templates


def build_base(capture: Path, name: str, description: str | None = None) -> tuple[dict, list[str]]:
    """Return (base image, notes). Raises ConvertError if the capture is unusable."""
    problems = baseline.verify(capture)
    if problems:
        raise ConvertError("capture failed verification:\n" + "\n".join(problems))
    manifest = baseline.load_manifest(capture)
    notes: list[str] = []
    keys = _registry(capture, notes)
    users, groups = _accounts(capture)
    base: dict = {
        "schema": 1,
        "kind": "base-image",
        "name": name,
        "description": description or f"Built from golden capture {capture.name}",
        "source": {
            "golden_capture": capture.name,
            "manifest_sha256": hashlib.sha256((capture / "manifest.json").read_bytes()).hexdigest(),
        },
        "os": "windows",
        "os_info": _os_info(capture, keys),
        "hardware": _hardware(capture),
        "network": _network(capture),
        "users": users,
        "groups": groups,
        "software": _software(capture, notes),
        "hotfixes": _hotfixes(capture),
        "services": _services(capture),
        "files": _files(capture, notes),
        "processes": _processes(capture, manifest, notes),
        "registry": {"keys": keys},
        "event_messages": _event_messages(capture, notes),
    }
    base = {k: v for k, v in base.items() if v not in ({}, [])}
    host = manifest.get("host", {})
    if host.get("build") and str(host["build"]) != base["os_info"].get("build"):
        notes.append(f"manifest build {host['build']} differs from os.json")
    try:
        profile.validate(base, f"base {name}")
    except profile.ProfileError as exc:
        raise ConvertError(str(exc)) from exc
    return base, notes
