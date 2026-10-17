"""Host profiles: load, validate, and resolve a profile onto its base image.

Merge rules (profile over base):

- Scalars and objects: the profile value wins; objects merge key by key.
- users, groups, software, hotfixes, services and network.interfaces: entries
  merge by name (case-insensitive, keeping the base's spelling); an entry with
  `remove: true` deletes the base entry.
- registry.keys: merge key by key, then value by value; a null value deletes it.
- registry.delete_keys: deletes the key and every subkey from the base.
- files: entries merge by path (case-insensitive on Windows and macOS, keeping
  the base's spelling), in profile order; `remove: true` deletes the entry
  and, for a directory, everything below it. The result is sorted by the
  path's normal form.
- processes: entries merge by id; `remove: true` deletes the base entry.
"""

from __future__ import annotations

import base64
import binascii
import copy
import datetime
import hashlib
import json
import re
from importlib import resources
from pathlib import Path

import jsonschema
import yaml

KEYED_LISTS = ("users", "groups", "software", "hotfixes", "services")
NESTED_KEYED_LISTS = (("network", "interfaces"),)
SPECIAL_FIELDS = (*KEYED_LISTS, "registry", "network", "files", "processes")
_WIN_PATH = re.compile(r"^[A-Za-z]:(\\[^\\/:*?\"<>|]+)*\\?$")
_UNIX_PATH = re.compile(r"^/([^/\0]+/?)*$")


def path_rules(os_name: str) -> tuple[str, bool]:
    """(separator, case-insensitive) for an OS. macOS volumes are case-insensitive by default."""
    if os_name == "windows":
        return "\\", True
    return "/", os_name == "macos"


def norm_path(path: str, os_name: str) -> str:
    """Normal form used to match paths. The root is "c:" on Windows and "" elsewhere."""
    sep, fold = path_rules(os_name)
    if os_name == "windows":
        path = path.replace("/", "\\")
    path = path.rstrip(sep)
    return path.lower() if fold else path


# Fields that belong to the file, not to the host, and never inherit from the base.
OWN_FIELDS = ("schema", "kind", "name", "description", "base", "source")


class ProfileError(ValueError):
    pass


def _schema() -> dict:
    text = resources.files(__package__).joinpath("schema/host-profile.schema.json").read_text()
    return json.loads(text)


_VALIDATOR = jsonschema.Draft202012Validator(
    _schema(), format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
)


def validate(doc: dict, where: str = "profile") -> None:
    errors = sorted(_VALIDATOR.iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        lines = [
            f"{where}: {'/'.join(map(str, e.absolute_path)) or '(root)'}: {e.message}"
            for e in errors
        ]
        raise ProfileError("\n".join(lines))
    if doc["kind"] == "base-image":
        _check_no_removals(doc, where)
    _check_unique_names(doc, where)
    _check_windows(doc, where)


def _check_windows(doc: dict, where: str) -> None:
    """Rules for the agent's launch settings and the `windows` section."""
    pid = doc.get("agent", {}).get("pid")
    if pid is not None and doc["os"] == "windows" and pid % 4:
        raise ProfileError(f"{where}: agent: pid {pid} is not a multiple of 4")
    win = doc.get("windows")
    if win is None:
        return
    if doc["os"] != "windows":
        raise ProfileError(f"{where}: windows: only for os windows")
    for store, certs in win.get("cert_stores", {}).items():
        for i, cert in enumerate(certs):
            try:
                base64.b64decode(cert["der"], validate=True)
            except binascii.Error as exc:
                bad = f"{where}: windows: cert_stores: {store}/{i}: bad base64"
                raise ProfileError(bad) from exc
    for path in win.get("trusted_files", {}):
        if not _WIN_PATH.match(path):
            raise ProfileError(f"{where}: windows: trusted_files: {path!r} is not an absolute path")


def _keyed_lists(doc: dict):
    for field in KEYED_LISTS:
        yield field, doc.get(field)
    for parent, field in NESTED_KEYED_LISTS:
        yield f"{parent}.{field}", doc.get(parent, {}).get(field)


def _check_paths(doc: dict, where: str) -> None:
    os_name = doc["os"]
    pattern = _WIN_PATH if os_name == "windows" else _UNIX_PATH
    sep, _ = path_rules(os_name)
    seen: dict[str, dict] = {}
    for f in doc.get("files", []):
        if not pattern.match(f["path"]):
            raise ProfileError(f"{where}: files: {f['path']!r} is not an absolute {os_name} path")
        key = norm_path(f["path"], os_name)
        if key in seen:
            raise ProfileError(f"{where}: files: duplicate path {f['path']!r}")
        seen[key] = f
        if f.get("content") and "base64" in f["content"]:
            try:
                base64.b64decode(f["content"]["base64"], validate=True)
            except binascii.Error as exc:
                raise ProfileError(f"{where}: files: {f['path']!r}: bad base64") from exc
    for key, f in seen.items():
        if f.get("remove"):
            continue
        parent = key.rsplit(sep, 1)[0] if sep in key else None
        while parent:
            above = seen.get(parent)
            if (
                above is not None
                and not above.get("remove")
                and above.get("type", "file") == "file"
            ):
                raise ProfileError(
                    f"{where}: files: {f['path']!r} is below the file {above['path']!r}"
                )
            parent = parent.rsplit(sep, 1)[0] if sep in parent else None


def _check_processes(doc: dict, where: str, resolved: bool) -> None:
    procs = doc.get("processes", [])
    ids = [p["id"] for p in procs]
    if len(ids) != len(set(ids)):
        raise ProfileError(f"{where}: processes: duplicate id")
    if not resolved:
        return
    pins = [p["pid"] for p in procs if "pid" in p]
    if len(pins) != len(set(pins)):
        raise ProfileError(f"{where}: processes: two processes pin the same pid")
    known = set(ids)
    for p in procs:
        if "image" not in p:
            raise ProfileError(f"{where}: processes: {p['id']!r} has no image")
        if p.get("parent") is not None and p["parent"] not in known:
            raise ProfileError(
                f"{where}: processes: {p['id']!r} names unknown parent {p['parent']!r}"
            )


def _check_unique_names(doc: dict, where: str) -> None:
    _check_paths(doc, where)
    _check_processes(doc, where, resolved=doc["kind"] != "host-profile")
    for label, items in _keyed_lists(doc):
        seen: set[str] = set()
        for item in items or []:
            key = item["name"].lower()
            if key in seen:
                raise ProfileError(f"{where}: {label}: duplicate name {item['name']!r}")
            seen.add(key)


def _check_no_removals(doc: dict, where: str) -> None:
    for label in ("files", "processes"):
        for item in doc.get(label, []):
            if item.get("remove"):
                raise ProfileError(f"{where}: {label}: a base image cannot remove entries")
    for label, items in _keyed_lists(doc):
        for item in items or []:
            if item.get("remove"):
                raise ProfileError(f"{where}: {label}: a base image cannot remove {item['name']!r}")
    reg = doc.get("registry", {})
    if reg.get("delete_keys"):
        raise ProfileError(f"{where}: registry: a base image cannot delete keys")
    for key, values in reg.get("keys", {}).items():
        if any(v is None for v in values.values()):
            raise ProfileError(f"{where}: registry: a base image cannot delete values in {key}")


def _reject_dates(node, where: str, path: str = "") -> None:
    """Unquoted YAML timestamps become date objects. Require quotes so every
    consumer (and the engine, which reads compiled JSON) sees the same text."""
    if isinstance(node, dict):
        for k, v in node.items():
            _reject_dates(v, where, f"{path}/{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _reject_dates(v, where, f"{path}/{i}")
    elif isinstance(node, datetime.date):
        raise ProfileError(
            f'{where}: {path.lstrip("/")}: quote timestamps, for example "{node.isoformat()}"'
        )


def load(path: Path) -> dict:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProfileError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ProfileError(f"{path}: expected a mapping at the top level")
    _reject_dates(doc, str(path))
    validate(doc, str(path))
    return doc


def _merge_dict(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in over.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_dict(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def _merge_keyed(base: list[dict] | None, over: list[dict] | None, label: str) -> list[dict]:
    result = {i["name"].lower(): copy.deepcopy(i) for i in base or []}
    for item in over or []:
        key = item["name"].lower()
        if item.get("remove"):
            if key not in result:
                raise ProfileError(f"{label}: cannot remove {item['name']!r}: not in the base")
            del result[key]
        elif key in result:
            # Keep the base's spelling of the name, as the registry merge does.
            result[key] = {**_merge_dict(result[key], item), "name": result[key]["name"]}
        else:
            result[key] = copy.deepcopy(item)
    return list(result.values())


def _merge_processes(base: list[dict], over: list[dict]) -> list[dict]:
    result = {p["id"]: copy.deepcopy(p) for p in base}
    for item in over:
        if item.get("remove"):
            if item["id"] not in result:
                raise ProfileError(f"processes: cannot remove {item['id']!r}: not in the base")
            del result[item["id"]]
        elif item["id"] in result:
            result[item["id"]] = _merge_dict(result[item["id"]], item)
        else:
            result[item["id"]] = copy.deepcopy(item)
    return list(result.values())


def _merge_files(base: list[dict], over: list[dict], os_name: str) -> list[dict]:
    sep, _ = path_rules(os_name)
    result = {norm_path(f["path"], os_name): copy.deepcopy(f) for f in base}
    for item in over:
        key = norm_path(item["path"], os_name)
        if item.get("remove"):
            doomed = [k for k in result if k == key or k.startswith(key + sep)]
            if not doomed:
                raise ProfileError(f"files: cannot remove {item['path']!r}: not in the base")
            for k in doomed:
                del result[k]
        elif key in result:
            merged = _merge_dict(result[key], item)
            merged["path"] = result[key]["path"]
            result[key] = merged
        else:
            result[key] = copy.deepcopy(item)
    # Sorted by normal form: one canonical order for Python and the engine.
    return [result[k] for k in sorted(result)]


def _key_norm(key: str) -> str:
    return key.lower().rstrip("\\")


def _merge_registry(base: dict, over: dict) -> dict:
    keys = {k: dict(v) for k, v in base.get("keys", {}).items()}
    for dead in over.get("delete_keys", []):
        d = _key_norm(dead)
        matched = [k for k in keys if _key_norm(k) == d or _key_norm(k).startswith(d + "\\")]
        if not matched:
            raise ProfileError(f"registry: cannot delete {dead!r}: not in the base")
        for k in matched:
            del keys[k]
    by_norm = {_key_norm(k): k for k in keys}
    for key, values in over.get("keys", {}).items():
        target = by_norm.get(_key_norm(key), key)
        merged = keys.setdefault(target, {})
        by_norm[_key_norm(key)] = target
        lowered = {n.lower(): n for n in merged}
        for name, value in values.items():
            existing = lowered.get(name.lower(), name)
            if value is None:
                merged.pop(existing, None)
            else:
                merged[existing] = copy.deepcopy(value)
                lowered[name.lower()] = existing
    return {"keys": dict(sorted(keys.items(), key=lambda kv: kv[0].lower()))}


def resolve(profile: dict, base: dict) -> dict:
    """Return the complete host: the base with the profile's deltas applied."""
    if base["kind"] != "base-image":
        raise ProfileError(f"{base['name']}: not a base image")
    if profile.get("base") != base["name"]:
        raise ProfileError(f"profile names base {profile.get('base')!r}, got {base['name']!r}")
    if profile["os"] != base["os"]:
        raise ProfileError(f"profile os {profile['os']!r} does not match base os {base['os']!r}")

    host_fields = {k: v for k, v in base.items() if k not in OWN_FIELDS}
    deltas = {k: v for k, v in profile.items() if k not in OWN_FIELDS}
    out = _merge_dict(
        host_fields,
        {k: v for k, v in deltas.items() if k not in SPECIAL_FIELDS},
    )
    for field in KEYED_LISTS:
        if field in base or field in profile:
            out[field] = _merge_keyed(base.get(field), profile.get(field), field)
    if "network" in base or "network" in profile:
        net = _merge_dict(
            base.get("network", {}),
            {k: v for k, v in profile.get("network", {}).items() if k != "interfaces"},
        )
        net["interfaces"] = _merge_keyed(
            base.get("network", {}).get("interfaces"),
            profile.get("network", {}).get("interfaces"),
            "network.interfaces",
        )
        out["network"] = net
    if "registry" in base or "registry" in profile:
        out["registry"] = _merge_registry(base.get("registry", {}), profile.get("registry", {}))
    if "files" in base or "files" in profile:
        out["files"] = _merge_files(base.get("files", []), profile.get("files", []), base["os"])
    if "processes" in base or "processes" in profile:
        out["processes"] = _merge_processes(base.get("processes", []), profile.get("processes", []))

    resolved = {
        "schema": 1,
        "kind": "resolved-host",
        "name": profile["name"],
        "base": base["name"],
        **({"source": base["source"]} if "source" in base else {}),
        **out,
    }
    validate(resolved, f"{profile['name']} (resolved)")
    return resolved


def find_base(name: str, search: list[Path]) -> Path:
    for d in search:
        for ext in (".yaml", ".yml"):
            p = d / f"{name}{ext}"
            if p.is_file():
                return p
    raise ProfileError(f"base image {name!r} not found in: {', '.join(map(str, search))}")


def resolve_file(path: Path, search: list[Path]) -> dict:
    profile = load(path)
    if profile["kind"] != "host-profile":
        raise ProfileError(f"{path}: expected kind host-profile, got {profile['kind']}")
    base = load(find_base(profile["base"], search))
    return resolve(profile, base)


def _yaml_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted([*p.glob("*.yaml"), *p.glob("*.yml")]))
        elif p.is_file():
            out.append(p)
        else:
            raise ProfileError(f"not found: {p}")
    return out


def content_bytes(content: dict) -> bytes:
    if "text" in content:
        return content["text"].encode("utf-8")
    return base64.b64decode(content["base64"], validate=True)


def _store_blobs(doc: dict, blobs: Path) -> None:
    """Move inline file content into the content-addressed blob store.

    Identical bytes are stored once, however many hosts carry them. Size and
    sha256 are filled in, and must match if the profile already gave them.
    """
    for f in doc.get("files", []):
        content = f.get("content")
        if not content or "blob" in content:
            continue
        data = content_bytes(content)
        digest = hashlib.sha256(data).hexdigest()
        for field, value in (("size", len(data)), ("sha256", digest)):
            if field in f and f[field] != value:
                raise ProfileError(
                    f"{doc['name']}: files: {f['path']!r}: {field} does not match content"
                )
            f[field] = value
        target = blobs / digest
        if not target.exists():
            target.write_bytes(data)
        f["content"] = {"blob": digest}


def compile_tree(base_paths: list[Path], host_paths: list[Path], out: Path) -> dict:
    """Validate base images and host profiles and write them as JSON for the engine.

    Profiles stay unmerged: the engine layers each host over its base itself.
    Every host is resolved here once, so a host that cannot resolve is an error.
    Returns the index written to out/compiled.json.
    """
    bases: dict[str, dict] = {}
    for path in _yaml_files(base_paths):
        doc = load(path)
        if doc["kind"] != "base-image":
            raise ProfileError(f"{path}: expected kind base-image, got {doc['kind']}")
        if doc["name"] in bases:
            raise ProfileError(f"{path}: duplicate base image name {doc['name']!r}")
        bases[doc["name"]] = doc
    hosts: dict[str, dict] = {}
    for path in _yaml_files(host_paths):
        doc = load(path)
        if doc["kind"] != "host-profile":
            raise ProfileError(f"{path}: expected kind host-profile, got {doc['kind']}")
        if doc["name"] in hosts:
            raise ProfileError(f"{path}: duplicate host name {doc['name']!r}")
        if doc["base"] not in bases:
            raise ProfileError(f"{path}: base image {doc['base']!r} not among the bases given")
        resolve(doc, bases[doc["base"]])
        hosts[doc["name"]] = doc
    for sub in ("bases", "hosts"):
        (out / sub).mkdir(parents=True, exist_ok=True)
        for stale in (out / sub).glob("*.json"):
            stale.unlink()
    (out / "blobs").mkdir(exist_ok=True)
    for doc in [*bases.values(), *hosts.values()]:
        _store_blobs(doc, out / "blobs")
    for name, doc in bases.items():
        (out / "bases" / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n")
    for name, doc in hosts.items():
        (out / "hosts" / f"{name}.json").write_text(json.dumps(doc, indent=1) + "\n")
    index = {"schema": 1, "bases": sorted(bases), "hosts": sorted(hosts)}
    (out / "compiled.json").write_text(json.dumps(index, indent=1) + "\n")
    return index
