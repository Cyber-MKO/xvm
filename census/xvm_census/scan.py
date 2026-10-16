"""Scan an unpacked tree and build the census for one agent."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

from . import __version__, macho, pe

ELF_MAGIC = b"\x7fELF"


def classify_dll(name: str, bundled: set[str]) -> str:
    """Where a DLL comes from: shipped in the package, an API set, or the OS."""
    if name in bundled:
        return "bundled"
    if name.startswith(("api-ms-win-", "ext-ms-win-")):
        return "api-set"
    return "system"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_tree(root: Path) -> tuple[list[dict], dict]:
    """Analyse every binary under root. Identical files are analysed once."""
    binaries: list[dict] = []
    seen: dict[str, dict] = {}
    counts = {"files": 0, "pe": 0, "macho": 0, "elf": 0, "duplicates": 0}
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        counts["files"] += 1
        rel = str(PurePosixPath(path.relative_to(root)))
        with path.open("rb") as f:
            head = f.read(64)
        if head.startswith(ELF_MAGIC):
            counts["elf"] += 1
            continue
        if not (pe.is_pe(head) or macho.is_macho(head)):
            continue
        digest = _sha256(path)
        if digest in seen:
            seen[digest]["also_at"].append(rel)
            counts["duplicates"] += 1
            continue
        if pe.is_pe(head):
            info = pe.analyze(path, rel)
            if info is None:
                continue
            counts["pe"] += 1
        else:
            info = macho.analyze(path, rel)
            counts["macho"] += 1
        entry = info.to_dict()
        entry["sha256"] = digest
        entry["also_at"] = []
        seen[digest] = entry
        binaries.append(entry)
    return binaries, counts


def aggregate(binaries: list[dict]) -> dict:
    """Build per-DLL function lists and the dynamic loading summary for PE binaries."""
    pes = [b for b in binaries if b["format"] == "pe"]
    bundled = {PurePosixPath(p).name.lower() for b in pes for p in [b["path"], *b["also_at"]]}

    dlls: dict[str, dict] = {}
    for b in pes:
        for table, delay in (("imports", False), ("delay_imports", True)):
            for dll, funcs in b[table].items():
                d = dlls.setdefault(
                    dll,
                    {"kind": classify_dll(dll, bundled), "delay_loaded": False, "functions": {}},
                )
                d["delay_loaded"] |= delay
                for fn in funcs:
                    d["functions"].setdefault(fn, []).append(b["path"])
    for d in dlls.values():
        d["functions"] = {k: sorted(set(v)) for k, v in sorted(d["functions"].items())}

    imported = {fn for d in dlls.values() for fn in d["functions"]}
    dynamic = []
    for b in pes:
        if not b["dynamic_loaders"]:
            continue
        linked = set(b["imports"]) | set(b["delay_imports"])
        dynamic.append(
            {
                "path": b["path"],
                "loaders": b["dynamic_loaders"],
                "unlinked_dll_strings": [
                    {"name": s, "kind": classify_dll(s, bundled)}
                    for s in b["dll_strings"]
                    if s not in linked and PurePosixPath(b["path"]).name.lower() != s
                ],
                "function_candidates": b["function_strings"],
                "function_candidates_imported_elsewhere": sorted(
                    set(b["function_strings"]) & imported
                ),
            }
        )
    dylibs: dict[str, set[str]] = {}
    for b in binaries:
        if b["format"] != "macho":
            continue
        for s in b["slices"]:
            for lib in s["dylibs"]:
                dylibs.setdefault(lib["name"], set()).add(b["path"])

    return {
        "dlls": dict(sorted(dlls.items())),
        "dylibs": {k: sorted(v) for k, v in sorted(dylibs.items())},
        "dynamic_loading": dynamic,
    }


def build_census(root: Path, agent: str, source: str, notes: list[str] | None = None) -> dict:
    binaries, counts = scan_tree(root)
    agg = aggregate(binaries)
    return {
        "schema": 1,
        "tool": f"xvm-census {__version__}",
        "generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent": agent,
        "source": source,
        "counts": counts,
        "unpack_notes": notes or [],
        "dlls": agg["dlls"],
        "dylibs": agg["dylibs"],
        "dynamic_loading": agg["dynamic_loading"],
        "binaries": binaries,
    }
