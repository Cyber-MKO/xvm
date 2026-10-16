"""Write the census as JSON and a Markdown summary."""

from __future__ import annotations

import json
from pathlib import Path

_KIND_ORDER = {"system": 0, "api-set": 1, "bundled": 2}


def write(census: dict, out_dir: Path, name: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{name}.json"
    md_path = out_dir / f"{name}.md"
    json_path.write_text(json.dumps(census, indent=2, sort_keys=False) + "\n")
    md_path.write_text(markdown(census))
    return json_path, md_path


def _code(items: list[str]) -> str:
    return ", ".join(f"`{i}`" for i in items) if items else "none"


def markdown(c: dict) -> str:
    lines: list[str] = []
    add = lines.append
    counts = c["counts"]
    dlls = c["dlls"]
    os_dlls = {k: v for k, v in dlls.items() if v["kind"] != "bundled"}
    os_funcs = sum(len(v["functions"]) for v in os_dlls.values())

    add(f"# API census: {c['agent']}\n")
    add(f"- Source: `{c['source']}`")
    if c.get("source_sha256"):
        add(f"- SHA-256: `{c['source_sha256']}`")
    add(f"- Generated: {c['generated']} by {c['tool']}")
    add("- JSON with per-binary detail sits next to this file.\n")

    add("## Summary\n")
    add("| Measure | Value |")
    add("| --- | --- |")
    add(f"| Files unpacked | {counts['files']} |")
    add(f"| PE images (unique) | {counts['pe']} |")
    add(f"| Mach-O images (unique) | {counts['macho']} |")
    add(f"| ELF files | {counts['elf']} |")
    add(f"| Duplicate binaries skipped | {counts['duplicates']} |")
    add(f"| OS DLLs imported (system and API set) | {len(os_dlls)} |")
    add(f"| OS functions imported | {os_funcs} |")
    add(f"| Bundled DLLs imported | {len(dlls) - len(os_dlls)} |")
    add(f"| Binaries with dynamic loading | {len(c['dynamic_loading'])} |")
    add("")

    pes = [b for b in c["binaries"] if b["format"] == "pe"]
    if pes:
        add("## Binaries\n")
        add("| Binary | Machine | Subsystem | OS DLLs | OS functions | Dynamic loading |")
        add("| --- | --- | --- | --- | --- | --- |")
        for b in pes:
            tables = [*b["imports"].items(), *b["delay_imports"].items()]
            os_tables = [(d, f) for d, f in tables if dlls.get(d, {}).get("kind") != "bundled"]
            n_funcs = sum(len(f) for _, f in os_tables)
            dynamic = "yes" if b["dynamic_loaders"] else "no"
            add(
                f"| `{b['path']}` | {b['machine']} | {b['subsystem']} | {len(os_tables)} "
                f"| {n_funcs} | {dynamic} |"
            )
        add("")

    if c.get("runtime_loaded_modules"):
        add("## Bundled DLLs loaded only at run time\n")
        add("No binary imports these statically. They are loaded with `LoadLibrary*`.\n")
        for m in c["runtime_loaded_modules"]:
            add(f"- `{m}`")
        add("")

    if dlls:
        add("## DLLs by function count\n")
        add("Bundled DLLs ship with the agent. We load them, we do not emulate them.\n")
        add("| DLL | Kind | Delay-loaded | Functions | Callers |")
        add("| --- | --- | --- | --- | --- |")
        ordered = sorted(
            dlls.items(), key=lambda kv: (_KIND_ORDER[kv[1]["kind"]], -len(kv[1]["functions"]))
        )
        for name, d in ordered:
            callers = {p for ps in d["functions"].values() for p in ps}
            add(
                f"| `{name}` | {d['kind']} | {'yes' if d['delay_loaded'] else 'no'} "
                f"| {len(d['functions'])} | {len(callers)} |"
            )
        add("")

        add("## OS functions per DLL\n")
        for name, d in ordered:
            if d["kind"] == "bundled":
                continue
            add(f"### `{name}` ({len(d['functions'])})\n")
            add(_code(list(d["functions"])) + "\n")

    ordinals = sorted({o for b in c["binaries"] for o in b.get("by_ordinal", [])})
    if ordinals:
        add("## Ordinal imports\n")
        add("The emulated DLL must export these ordinals, not only the names.\n")
        add(_code(ordinals) + "\n")

    if c["dynamic_loading"]:
        add("## Dynamic loading\n")
        add(
            "These binaries resolve APIs at run time. The names below come from string "
            "heuristics and are candidates only. The runtime gap log confirms real lookups.\n"
        )
        for d in c["dynamic_loading"]:
            add(f"### `{d['path']}`\n")
            add(f"- Loaders imported: {_code(d['loaders'])}")
            unlinked = [f"{u['name']} ({u['kind']})" for u in d["unlinked_dll_strings"]]
            add(f"- DLL names in strings but not linked: {_code(unlinked)}")
            add(
                f"- Function-like strings: {len(d['function_candidates'])}; "
                f"of these, imported elsewhere in the package: "
                f"{_code(d['function_candidates_imported_elsewhere'])}"
            )
            if d["function_candidates"]:
                add("")
                add("<details><summary>Function-like strings</summary>\n")
                add(_code(d["function_candidates"]))
                add("\n</details>")
            add("")

    if c.get("dylibs"):
        add("## Mach-O linked libraries\n")
        add("Symbol-level imports are not parsed yet (Phase 6).\n")
        add("| Library | Callers |")
        add("| --- | --- |")
        for name, callers in c["dylibs"].items():
            add(f"| `{name}` | {len(callers)} |")
        add("")

    if c["unpack_notes"]:
        add("## Unpack notes\n")
        for n in c["unpack_notes"]:
            add(f"- {n}")
        add("")

    errors = [(b["path"], e) for b in c["binaries"] for e in b["errors"]]
    if errors:
        add("## Parse warnings\n")
        for path, e in errors:
            add(f"- `{path}`: {e}")
        add("")
    return "\n".join(lines).rstrip() + "\n"
