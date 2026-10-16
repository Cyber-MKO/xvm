"""String heuristics for names that a binary may resolve at run time."""

from __future__ import annotations

import re

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")

_DLL = re.compile(r"(?i)\b([a-z0-9_.\-]{1,64}\.(?:dll|drv|sys|ocx|cpl))\b")
_DYLIB = re.compile(r"(/[\w@.+\-/]+\.(?:dylib|framework/[\w.\-]+)|\blib[\w.+\-]+\.so(?:\.\d+)*)")

# Win32-style identifiers: CamelCase with at least two humps, optional A/W suffix,
# or Nt/Zw/Rtl/Ldr prefixed native calls.
_FUNC = re.compile(r"^(?:[A-Z][a-z0-9]+){2,}(?:Ex)?[AW]?$|^(?:Nt|Zw|Rtl|Ldr)[A-Z]\w+$")


def strings(data: bytes) -> set[str]:
    out = {m.decode("ascii") for m in _ASCII.findall(data)}
    out |= {m.decode("utf-16-le") for m in _UTF16.findall(data)}
    return out


def dll_name_strings(data: bytes) -> set[str]:
    found: set[str] = set()
    for s in strings(data):
        for m in _DLL.findall(s):
            found.add(m.lower())
    return found


def dylib_name_strings(data: bytes) -> set[str]:
    found: set[str] = set()
    for s in strings(data):
        found.update(_DYLIB.findall(s))
    return found


def function_name_strings(data: bytes) -> set[str]:
    """Whole strings that look like a Windows API function name.

    This is a candidate list, not proof of use. The runtime gap log is what
    confirms a dynamic lookup.
    """
    return {s for s in strings(data) if 6 <= len(s) <= 64 and _FUNC.match(s)}
