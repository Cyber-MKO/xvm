"""PE32/PE32+ analysis: imports, delay-load imports, exports and dynamic loading."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pefile

from .strings import dll_name_strings, function_name_strings

# Imports that let a binary resolve APIs at run time, hiding them from the import table.
DYNAMIC_LOADERS = frozenset(
    {
        "LoadLibraryA",
        "LoadLibraryW",
        "LoadLibraryExA",
        "LoadLibraryExW",
        "LoadPackagedLibrary",
        "GetProcAddress",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetModuleHandleExA",
        "GetModuleHandleExW",
        "LdrLoadDll",
        "LdrGetProcedureAddress",
        "LdrGetProcedureAddressEx",
        "LdrGetDllHandle",
    }
)


@dataclass
class PEInfo:
    path: str
    machine: str
    subsystem: str
    is_dll: bool
    imports: dict[str, list[str]] = field(default_factory=dict)
    delay_imports: dict[str, list[str]] = field(default_factory=dict)
    by_ordinal: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    dynamic_loaders: list[str] = field(default_factory=list)
    dll_strings: list[str] = field(default_factory=list)
    function_strings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": "pe",
            "machine": self.machine,
            "subsystem": self.subsystem,
            "is_dll": self.is_dll,
            "imports": self.imports,
            "delay_imports": self.delay_imports,
            "by_ordinal": self.by_ordinal,
            "exports": self.exports,
            "dynamic_loaders": self.dynamic_loaders,
            "dll_strings": self.dll_strings,
            "function_strings": self.function_strings,
            "errors": self.errors,
        }


def is_pe(head: bytes) -> bool:
    return head[:2] == b"MZ"


def _name(entry) -> str:
    if entry.name is not None:
        return entry.name.decode("ascii", errors="replace")
    return f"#{entry.ordinal}"


def _collect(directory, by_ordinal: list[str]) -> dict[str, list[str]]:
    """Map DLL name to imported function names.

    Ordinal imports are named "#N" unless pefile knows the name for that
    ordinal. Each one is also listed in by_ordinal as "dll!#N" or "dll!#N=Name",
    because the emulated DLL must export the same ordinal.
    """
    out: dict[str, set[str]] = {}
    for dll in directory or []:
        dll_name = dll.dll.decode("ascii", errors="replace").lower()
        names = out.setdefault(dll_name, set())
        for imp in dll.imports:
            name = _name(imp)
            names.add(name)
            if getattr(imp, "import_by_ordinal", False):
                suffix = "" if name.startswith("#") else f"={name}"
                by_ordinal.append(f"{dll_name}!#{imp.ordinal}{suffix}")
    return {k: sorted(v) for k, v in sorted(out.items())}


def analyze(path: Path, rel: str) -> PEInfo | None:
    """Parse a PE file. Returns None if the file is not a valid PE image."""
    data = path.read_bytes()
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return None
    pe.parse_data_directories(
        directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
        ]
    )
    machine = pefile.MACHINE_TYPE.get(pe.FILE_HEADER.Machine, hex(pe.FILE_HEADER.Machine))
    subsystem = pefile.SUBSYSTEM_TYPE.get(
        pe.OPTIONAL_HEADER.Subsystem, str(pe.OPTIONAL_HEADER.Subsystem)
    )
    info = PEInfo(
        path=rel,
        machine=str(machine).removeprefix("IMAGE_FILE_MACHINE_"),
        subsystem=str(subsystem).removeprefix("IMAGE_SUBSYSTEM_"),
        is_dll=pe.is_dll(),
    )
    info.imports = _collect(getattr(pe, "DIRECTORY_ENTRY_IMPORT", None), info.by_ordinal)
    info.delay_imports = _collect(
        getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", None), info.by_ordinal
    )
    info.by_ordinal.sort()
    exp = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if exp is not None:
        info.exports = sorted({_name(s) for s in exp.symbols})
    for w in pe.get_warnings():
        if "Error" in w or "error" in w:
            info.errors.append(w)

    imported = {f for funcs in info.imports.values() for f in funcs}
    imported |= {f for funcs in info.delay_imports.values() for f in funcs}
    info.dynamic_loaders = sorted(imported & DYNAMIC_LOADERS)

    info.dll_strings = sorted(dll_name_strings(data))
    info.function_strings = sorted(function_name_strings(data) - imported - set(info.exports))
    pe.close()
    return info
