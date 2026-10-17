"""Install an MSI package onto a host's drive folders.

Decisions in docs/BRIEF.md: the installer step writes to the host's drive
folders, and install properties come from the host profile. The tables
are read with msitools and the cabinet unpacked with bsdtar.

| Step | Source |
| --- | --- |
| Folders | Directory table, resolved as "Directory Table" on Microsoft Learn describes |
| Searches | AppSearch with RegLocator rows, read from the host profile's registry |
| Components | Component table; conditions evaluated from the host's OS facts and the searches |
| Files | File table; bytes from the embedded cabinet, named by File key |
| Empty folders | CreateFolder table |
| `ossec.conf` | Wazuh's documented deployment variables, from the profile's `agent` section |

Custom actions, registry rows, services, shortcuts and permissions are
not run. Each kind that the package holds is reported as a gap, so the
caller can see what a real install would also have done.
"""

from __future__ import annotations

import contextlib
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from .condition import ConditionError, evaluate

CURRENT_VERSION = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
PRODUCT_OPTIONS = r"HKLM\SYSTEM\CurrentControlSet\Control\ProductOptions"
# Tables whose rows a real install acts on and this step does not.
NOT_RUN = {
    "CustomAction": "custom actions",
    "Registry": "registry values",
    "ServiceInstall": "service installation",
    "ServiceControl": "service control",
    "Shortcut": "shortcuts",
    "SecureObjects": "permissions",
    "RemoveFile": "file removal",
}
# Properties the profile's `agent` section sets.
AGENT_PROPERTIES = {"manager": "WAZUH_MANAGER", "group": "WAZUH_AGENT_GROUP"}


class InstallError(RuntimeError):
    pass


@dataclass
class Result:
    files: int = 0
    folders: int = 0
    gaps: list[str] = field(default_factory=list)


def _run(cmd: list[str]) -> bytes:
    try:
        return subprocess.run(cmd, check=True, capture_output=True).stdout
    except FileNotFoundError as exc:
        raise InstallError(f"{cmd[0]} is not installed") from exc
    except subprocess.CalledProcessError as exc:
        raise InstallError(f"{' '.join(cmd)}: {exc.stderr.decode(errors='replace')}") from exc


def table(msi: Path, name: str) -> list[dict[str, str]]:
    """Rows of one table, as `msiinfo export` gives them."""
    if name not in _run(["msiinfo", "tables", str(msi)]).decode().split():
        return []
    lines = _run(["msiinfo", "export", str(msi), name]).decode("utf-8", "replace").splitlines()
    columns = lines[0].split("\t")
    return [dict(zip(columns, line.split("\t"), strict=False)) for line in lines[3:] if line]


def long_name(default_dir: str) -> str:
    """The target long name of a DefaultDir or FileName value."""
    target = default_dir.split(":", 1)[0]
    return target.split("|", 1)[-1]


def resolve_directories(rows: list[dict[str, str]], roots: dict[str, str]) -> dict[str, str]:
    """Each Directory key's Windows path. `roots` gives TARGETDIR and the
    standard folders (such as ProgramFilesFolder)."""
    by_key = {r["Directory"]: r for r in rows}
    paths: dict[str, str] = {}

    def path(key: str, depth: int = 0) -> str:
        if key in paths:
            return paths[key]
        if key in roots:
            paths[key] = roots[key]
            return paths[key]
        if depth > 64 or key not in by_key:
            raise InstallError(f"directory {key} has no root")
        row = by_key[key]
        name = long_name(row["DefaultDir"])
        parent = path(row["Directory_Parent"], depth + 1)
        paths[key] = parent if name == "." else str(PureWindowsPath(parent) / name)
        return paths[key]

    for key in by_key:
        with contextlib.suppress(InstallError):
            path(key)
    return paths


def host_path(drives: dict[str, Path], windows_path: str) -> Path:
    """The host folder behind a Windows path, matching existing names
    without regard to case, as the loader's drive table does."""
    p = PureWindowsPath(windows_path)
    letter = p.drive.rstrip(":").upper()
    if letter not in drives:
        raise InstallError(f"{windows_path}: no drive {letter}:")
    out = drives[letter]
    for part in p.parts[1:]:
        match = None
        if out.is_dir():
            match = next((c for c in out.iterdir() if c.name.lower() == part.lower()), None)
        out = match or out / part
    return out


def _registry_value(host: dict, key: str, name: str) -> dict | None:
    for k, values in (host.get("registry", {}).get("keys") or {}).items():
        if k.lower() == key.lower():
            for n, v in (values or {}).items():
                if n.lower() == name.lower() and isinstance(v, dict):
                    return v
    return None


def _registry(host: dict, key: str, name: str) -> str | None:
    value = _registry_value(host, key, name)
    return None if value is None else str(value.get("data"))


def raw_value(value: dict) -> str:
    """A registry value as a RegLocator raw search gives it ("RegLocator
    Table" on Microsoft Learn)."""
    kind, data = value.get("type"), value.get("data")
    if kind in ("REG_DWORD", "REG_QWORD"):
        return f"#{int(data)}"
    if kind == "REG_EXPAND_SZ":
        return f"#%{data}"
    if kind == "REG_MULTI_SZ":
        return "[~]".join(data) if isinstance(data, list) else str(data)
    if kind == "REG_BINARY":
        return "#x" + str(data).replace(" ", "").lower()
    text = str(data)
    return "#" + text if text.startswith("#") else text


ROOTS = {0: "HKCR", 1: "HKCU", 2: "HKLM", 3: "HKU"}
LOCATOR_TYPE_RAW = 2
LOCATOR_64BIT = 0x10


def app_search(msi: Path, host: dict, msi_properties: dict[str, str]) -> tuple[dict, list[str]]:
    """Properties the AppSearch table sets from RegLocator rows. A 32-bit
    search on 64-bit Windows reads HKLM\\SOFTWARE through WOW6432Node."""
    found: dict[str, str] = {}
    gaps: list[str] = []
    locators = {r["Signature_"]: r for r in table(msi, "RegLocator")}
    is64 = str((host.get("os_info") or {}).get("architecture", "")).lower() in (
        "x86_64",
        "amd64",
        "arm64",
    )
    for row in table(msi, "AppSearch"):
        loc = locators.get(row["Signature_"])
        if loc is None:
            gaps.append(f"AppSearch {row['Property']}: only registry searches are supported")
            continue
        kind = int(loc.get("Type") or 0)
        if kind & 0x0F != LOCATOR_TYPE_RAW:
            gaps.append(f"AppSearch {row['Property']}: registry search type {kind}")
            continue
        sub = re.sub(r"\[([^\]]+)\]", lambda m: msi_properties.get(m.group(1), ""), loc["Key"])
        key = f"{ROOTS.get(int(loc['Root']), '?')}\\{sub}"
        candidates = [key]
        prefix = "software\\"
        if is64 and not kind & LOCATOR_64BIT and sub.lower().startswith(prefix):
            rest = sub[len(prefix) :]
            candidates.insert(0, f"HKLM\\SOFTWARE\\WOW6432Node\\{rest}")
        for i, candidate in enumerate(candidates):
            value = _registry_value(host, candidate, loc.get("Name") or "")
            if value is not None:
                found[row["Property"]] = raw_value(value)
                if i == 1:
                    gaps.append(f"AppSearch {row['Property']}: read the 64-bit view of {key}")
                break
    return found, gaps


def os_properties(host: dict) -> tuple[dict[str, str], list[str]]:
    """VersionNT, VersionNT64 and MsiNTProductType for a resolved host
    profile, as "Operating System Property Values" on Microsoft Learn
    gives them (Windows 8.1 and later report 603)."""
    gaps: list[str] = []
    info = host.get("os_info") or {}
    props: dict[str, str] = {}
    m = re.fullmatch(r"(\d+)\.(\d+)", str(info.get("version", "")))
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        version = 603 if (major, minor) >= (6, 3) else major * 100 + minor
        props["VersionNT"] = str(version)
        if str(info.get("architecture", "")).lower() in ("x86_64", "amd64", "arm64"):
            props["VersionNT64"] = str(version)
    else:
        gaps.append("os_info.version is missing: VersionNT is unset")
    product = _registry(host, PRODUCT_OPTIONS, "ProductType")
    kind = {"winnt": "1", "lanmannt": "2", "servernt": "3"}.get((product or "").lower())
    if kind is None:
        installation = (_registry(host, CURRENT_VERSION, "InstallationType") or "").lower()
        kind = {"client": "1", "server": "3", "server core": "3"}.get(installation)
    if kind is None:
        gaps.append("no ProductType or InstallationType: MsiNTProductType is unset")
    else:
        props["MsiNTProductType"] = kind
    return props, gaps


def _set_element(block: str, tag: str, value: str, newline: str, indent: str) -> str:
    pattern = re.compile(rf"(<{tag}>)(.*?)(</{tag}>)", re.S)
    if pattern.search(block):
        return pattern.sub(lambda m: m.group(1) + value + m.group(3), block, count=1)
    close = block.rindex("</")
    return f"{block[:close]}  <{tag}>{value}</{tag}>{newline}{indent}{block[close:]}"


def apply_properties(conf: str, properties: dict[str, str]) -> tuple[str, list[str]]:
    """Set the documented deployment variables in an ossec.conf text."""
    gaps: list[str] = []
    newline = "\r\n" if "\r\n" in conf else "\n"
    client = re.search(r"( *)<client>.*?</client>", conf, re.S)
    if not client:
        raise InstallError("ossec.conf has no <client> block")
    indent = client.group(1)
    block = client.group(0)
    for name, value in properties.items():
        if name == "WAZUH_MANAGER":
            if "," in value:
                gaps.append("WAZUH_MANAGER with several managers")
                value = value.split(",", 1)[0]
            server = re.search(r"( *)<server>.*?</server>", block, re.S)
            if not server:
                raise InstallError("ossec.conf has no <server> block")
            updated = _set_element(server.group(0), "address", value, newline, server.group(1))
            block = block.replace(server.group(0), updated, 1)
        elif name in ("WAZUH_AGENT_GROUP", "WAZUH_AGENT_NAME"):
            tag = "groups" if name == "WAZUH_AGENT_GROUP" else "agent_name"
            enrollment = re.search(r"( *)<enrollment>.*?</enrollment>", block, re.S)
            if not enrollment:
                inner = indent + "  "
                new = f"{inner}<enrollment>{newline}{inner}</enrollment>{newline}"
                close = block.rindex(f"{indent}</client>")
                block = block[:close] + new + block[close:]
                enrollment = re.search(r"( *)<enrollment>.*?</enrollment>", block, re.S)
            assert enrollment
            updated = _set_element(enrollment.group(0), tag, value, newline, enrollment.group(1))
            block = block.replace(enrollment.group(0), updated, 1)
        else:
            gaps.append(f"install property {name}")
    return conf.replace(client.group(0), block, 1), gaps


def _searchable(msi: Path) -> set[str]:
    return {r["Property"] for r in table(msi, "AppSearch")}


def install(
    msi: Path,
    drives: dict[str, Path],
    host: dict,
    program_files: str,
    target_drive: str = "C",
) -> Result:
    """Install `msi` for the resolved host profile `host`.

    `program_files` is the host's ProgramFilesFolder for this package,
    such as `C:\\Program Files (x86)` for a 32-bit package on 64-bit
    Windows.
    """
    result = Result()
    os_props, gaps = os_properties(host)
    result.gaps.extend(gaps)
    msi_properties = {r["Property"]: r["Value"] for r in table(msi, "Property")}
    searched, gaps = app_search(msi, host, msi_properties)
    result.gaps.extend(gaps)
    os_props = {**os_props, **searched}
    roots = {
        "TARGETDIR": f"{target_drive}:\\",
        "ProgramFilesFolder": program_files,
    }
    if "APPLICATIONFOLDER" in searched:
        roots["APPLICATIONFOLDER"] = searched["APPLICATIONFOLDER"]
    dirs = resolve_directories(table(msi, "Directory"), roots)
    components = {}
    unset: dict[str, list[str]] = {}
    searchable = _searchable(msi)
    for row in table(msi, "Component"):
        try:
            wanted, used = evaluate(row.get("Condition", ""), os_props)
        except ConditionError as exc:
            result.gaps.append(f"component {row['Component']}: {exc}")
            continue
        # VersionNT64 is unset on 32-bit Windows, and a search may find
        # nothing: those are real answers, not gaps.
        for name in sorted(used - set(os_props) - {"VersionNT64"} - searchable):
            unset.setdefault(name, []).append(row["Component"])
        if wanted:
            components[row["Component"]] = row["Directory_"]
    for name, names in unset.items():
        result.gaps.append(f"{name} is unset for the conditions of {', '.join(names)}")

    def folder(directory: str) -> Path | None:
        if directory not in dirs:
            result.gaps.append(f"directory {directory} is outside the drives")
            return None
        return host_path(drives, dirs[directory])

    for row in table(msi, "CreateFolder"):
        if row["Component_"] in components and (target := folder(row["Directory_"])):
            target.mkdir(parents=True, exist_ok=True)
            result.folders += 1

    media = table(msi, "Media")
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for m in media:
            cabinet = m.get("Cabinet", "")
            if not cabinet.startswith("#"):
                result.gaps.append(f"external cabinet {cabinet!r}")
                continue
            cab = work / "media.cab"
            cab.write_bytes(_run(["msiinfo", "extract", str(msi), cabinet[1:]]))
            _run(["bsdtar", "-xf", str(cab), "-C", str(work)])
        for row in table(msi, "File"):
            directory = components.get(row["Component_"])
            if directory is None:
                continue
            source = work / row["File"]
            target_dir = folder(directory)
            if target_dir is None:
                continue
            if not source.is_file():
                result.gaps.append(f"file {row['File']} is not in the cabinet")
                continue
            target_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target_dir / long_name(row["FileName"]))
            result.files += 1

    for name, label in NOT_RUN.items():
        if table(msi, name):
            result.gaps.append(f"{label} ({name} table) not run")

    agent = host.get("agent") or {}
    properties = {AGENT_PROPERTIES[k]: str(v) for k, v in agent.items() if k in AGENT_PROPERTIES}
    if properties and "APPLICATIONFOLDER" in dirs:
        conf = host_path(drives, dirs["APPLICATIONFOLDER"]) / "ossec.conf"
        if conf.is_file():
            text = conf.read_bytes().decode("utf-8")
            text, gaps = apply_properties(text, properties)
            result.gaps.extend(gaps)
            conf.write_bytes(text.encode("utf-8"))
        else:
            result.gaps.append("no ossec.conf to apply install properties to")
    return result
