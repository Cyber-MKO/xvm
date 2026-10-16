"""Verify a Windows golden baseline and import the manager-side events."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

SCHEMA = 1
KIND = "windows-golden-baseline"
LOGS = ("Security", "System", "Application")
REQUIRED_FILES = (
    *(f"evtx/full/{log}.evtx" for log in LOGS),
    *(f"evtx/scenario/{log}.evtx" for log in LOGS),
    "registry/os-currentversion.reg",
    "registry/computername.reg",
    "host/os.json",
    "wazuh/ossec.conf",
)
FORBIDDEN_NAMES = ("client.keys",)
REQUIRED_STEPS = (
    "marker_start",
    "user_create",
    "group_add",
    "failed_logon",
    "group_remove",
    "user_delete",
    "service_restart",
    "fim_change",
    "marker_end",
)


def parse_time(value: str) -> datetime:
    """Parse manifest times (2026-10-16T21:13:45.123Z) and Wazuh times (...+0000)."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(root: Path) -> dict:
    # capture.ps1 writes UTF-8 with a byte order mark under Windows PowerShell 5.1.
    return json.loads((root / "manifest.json").read_text(encoding="utf-8-sig"))


def verify(root: Path) -> list[str]:
    """Return a list of problems. An empty list means the baseline is usable."""
    problems: list[str] = []
    try:
        m = load_manifest(root)
    except (OSError, ValueError) as exc:
        return [f"manifest.json unreadable: {exc}"]

    if m.get("schema") != SCHEMA or m.get("kind") != KIND:
        problems.append(f"unexpected schema or kind: {m.get('schema')}, {m.get('kind')}")

    listed = {f["path"]: f for f in m.get("files", [])}
    for rel in REQUIRED_FILES:
        if rel not in listed:
            problems.append(f"required file missing from manifest: {rel}")
    for rel, entry in sorted(listed.items()):
        path = root / rel
        if not path.is_file():
            problems.append(f"listed file not on disk: {rel}")
        elif _sha256(path) != entry["sha256"]:
            problems.append(f"hash mismatch: {rel}")
    for path in root.rglob("*"):
        if path.name.lower() in FORBIDDEN_NAMES:
            problems.append(f"secret must not be stored: {path.relative_to(root)}")

    scenario = m.get("scenario", {})
    steps = {s["name"]: s for s in scenario.get("steps", [])}
    for name in REQUIRED_STEPS:
        if name not in steps:
            problems.append(f"scenario step missing: {name}")
    try:
        start, end = parse_time(scenario["start"]), parse_time(scenario["end"])
        if not start < end:
            problems.append("scenario start is not before its end")
        for s in steps.values():
            s_start, s_end = parse_time(s["start"]), parse_time(s["end"])
            if not (start <= s_start <= s_end <= end):
                problems.append(f"step {s['name']} lies outside the scenario window")
    except (KeyError, ValueError) as exc:
        problems.append(f"bad scenario times: {exc}")
    return problems


def _window_filter(src: Path, dest: Path, start: datetime, end: datetime) -> int:
    kept = 0
    with src.open(encoding="utf-8") as fin, dest.open("w", encoding="utf-8") as fout:
        for line in fin:
            line = line.strip()
            if not line:
                continue
            event = json.loads(line)
            if start <= parse_time(event["timestamp"]) <= end:
                fout.write(json.dumps(event, sort_keys=True) + "\n")
                kept += 1
    return kept


def import_manager(
    root: Path, archives: Path, alerts: Path, margin: timedelta = timedelta(minutes=2)
) -> dict:
    """Copy the scenario window of the manager logs into root/manager/.

    The margin covers shipping delay between the agent and the manager. The
    manifest gains a "manager" section with event counts and file hashes.
    """
    m = load_manifest(root)
    start = parse_time(m["scenario"]["start"]) - margin
    end = parse_time(m["scenario"]["end"]) + margin
    out = root / "manager"
    out.mkdir(exist_ok=True)
    counts = {
        "archives": _window_filter(archives, out / "archives.json", start, end),
        "alerts": _window_filter(alerts, out / "alerts.json", start, end),
    }
    m["manager"] = {
        "window_margin_seconds": int(margin.total_seconds()),
        "counts": counts,
        "files": [
            {"path": f"manager/{n}", "sha256": _sha256(out / n)}
            for n in ("archives.json", "alerts.json")
        ],
    }
    m["files"] = [f for f in m["files"] if not f["path"].startswith("manager/")] + [
        {**f, "size": (root / f["path"]).stat().st_size} for f in m["manager"]["files"]
    ]
    (root / "manifest.json").write_text(json.dumps(m, indent=2) + "\n", encoding="utf-8")
    return counts
