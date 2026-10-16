"""Host profiles: load, validate, and resolve a profile onto its base image.

Merge rules (profile over base):

- Scalars and objects: the profile value wins; objects merge key by key.
- users, groups, software, services and network.interfaces: entries merge by
  name (case-insensitive); an entry with `remove: true` deletes the base entry.
- registry.keys: merge key by key, then value by value; a null value deletes it.
- registry.delete_keys: deletes the key and every subkey from the base.
"""

from __future__ import annotations

import copy
import datetime
import json
from importlib import resources
from pathlib import Path

import jsonschema
import yaml

KEYED_LISTS = ("users", "groups", "software", "services")
NESTED_KEYED_LISTS = (("network", "interfaces"),)
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


def _keyed_lists(doc: dict):
    for field in KEYED_LISTS:
        yield field, doc.get(field)
    for parent, field in NESTED_KEYED_LISTS:
        yield f"{parent}.{field}", doc.get(parent, {}).get(field)


def _check_unique_names(doc: dict, where: str) -> None:
    for label, items in _keyed_lists(doc):
        seen: set[str] = set()
        for item in items or []:
            key = item["name"].lower()
            if key in seen:
                raise ProfileError(f"{where}: {label}: duplicate name {item['name']!r}")
            seen.add(key)


def _check_no_removals(doc: dict, where: str) -> None:
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


def _dates_to_text(node):
    """YAML turns unquoted timestamps into date objects; the schema expects text."""
    if isinstance(node, dict):
        return {k: _dates_to_text(v) for k, v in node.items()}
    if isinstance(node, list):
        return [_dates_to_text(v) for v in node]
    if isinstance(node, datetime.datetime):
        if node.tzinfo is None:
            node = node.replace(tzinfo=datetime.UTC)
        return node.isoformat().replace("+00:00", "Z")
    if isinstance(node, datetime.date):
        return node.isoformat()
    return node


def load(path: Path) -> dict:
    try:
        doc = _dates_to_text(yaml.safe_load(path.read_text(encoding="utf-8")))
    except yaml.YAMLError as exc:
        raise ProfileError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(doc, dict):
        raise ProfileError(f"{path}: expected a mapping at the top level")
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
            result[key] = _merge_dict(result[key], item)
        else:
            result[key] = copy.deepcopy(item)
    return list(result.values())


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
        {k: v for k, v in deltas.items() if k not in (*KEYED_LISTS, "registry", "network")},
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
