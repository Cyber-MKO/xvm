"""Parse `reg export` files into host profile registry keys.

Written from Microsoft's public description of the .reg text format
("How to add, modify, or delete registry subkeys and values by using a .reg
file", Microsoft Learn). Supported value forms:

| Form | Type |
| --- | --- |
| `"text"` | REG_SZ |
| `dword:0000000a` | REG_DWORD |
| `hex:..` | REG_BINARY |
| `hex(2):..` | REG_EXPAND_SZ (UTF-16LE) |
| `hex(7):..` | REG_MULTI_SZ (UTF-16LE) |
| `hex(4):..` | REG_DWORD (little-endian bytes) |
| `hex(b):..` | REG_QWORD (little-endian bytes) |

Other hex(N) types are reported as skipped, not dropped silently.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

HIVES = {
    "HKEY_LOCAL_MACHINE": "HKLM",
    "HKEY_USERS": "HKU",
    "HKEY_CLASSES_ROOT": "HKCR",
}
HEADERS = ("Windows Registry Editor Version 5.00", "REGEDIT4")
_HEX_VALUE = re.compile(r'^(?:@|"(?:[^"\\]|\\.)*")=hex(?:\([0-9a-fA-F]+\))?:')


class RegFileError(ValueError):
    pass


@dataclass
class RegExport:
    keys: dict[str, dict[str, dict]] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)


def decode(raw: bytes) -> str:
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le")
    return raw.decode("utf-8-sig")


def _logical_lines(text: str):
    """Yield (line_number, line) with hex continuations joined."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i + 1
        line = lines[i].rstrip()
        if _HEX_VALUE.match(line):
            while line.endswith("\\") and i + 1 < len(lines):
                i += 1
                line = line[:-1] + lines[i].strip()
        yield start, line
        i += 1


def _key_path(raw: str, lineno: int) -> str | None:
    hive, _, rest = raw.partition("\\")
    short = HIVES.get(hive.upper())
    if short is None:
        return None
    if not rest:
        raise RegFileError(f"line {lineno}: hive root without a key: [{raw}]")
    return f"{short}\\{rest}"


def _unquote(s: str, lineno: int) -> tuple[str, str]:
    """Parse a leading quoted string; return (text, remainder)."""
    if not s.startswith('"'):
        raise RegFileError(f"line {lineno}: expected a quoted string")
    out = []
    i = 1
    while i < len(s):
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        elif c == '"':
            return "".join(out), s[i + 1 :]
        else:
            out.append(c)
            i += 1
    raise RegFileError(f"line {lineno}: unterminated string")


def _hex_bytes(s: str, lineno: int) -> bytes:
    s = s.strip()
    if not s:
        return b""
    try:
        return bytes(int(b, 16) for b in s.split(","))
    except ValueError as exc:
        raise RegFileError(f"line {lineno}: bad hex data") from exc


def _utf16_strings(data: bytes) -> list[str]:
    if len(data) % 2:
        data = data[:-1]
    return data.decode("utf-16-le").split("\0")


def _value(data: str, lineno: int) -> dict | str:
    """Return a typed value, or a string naming the type that was skipped."""
    if data.startswith('"'):
        text, rest = _unquote(data, lineno)
        if rest.strip():
            raise RegFileError(f"line {lineno}: text after string value")
        return {"type": "REG_SZ", "data": text}
    if data.lower().startswith("dword:"):
        return {"type": "REG_DWORD", "data": int(data[6:], 16)}
    m = re.match(r"(?i)hex(?:\(([0-9a-f]+)\))?:(.*)$", data)
    if not m:
        raise RegFileError(f"line {lineno}: unknown value form: {data[:40]}")
    kind = int(m.group(1), 16) if m.group(1) else 3
    raw = _hex_bytes(m.group(2), lineno)
    if kind == 3:
        return {"type": "REG_BINARY", "data": raw.hex()}
    if kind == 2:
        return {"type": "REG_EXPAND_SZ", "data": _utf16_strings(raw)[0]}
    if kind == 7:
        parts = _utf16_strings(raw)
        while parts and parts[-1] == "":
            parts.pop()
        return {"type": "REG_MULTI_SZ", "data": parts}
    if kind == 4 and len(raw) == 4:
        return {"type": "REG_DWORD", "data": int.from_bytes(raw, "little")}
    if kind == 0xB and len(raw) == 8:
        return {"type": "REG_QWORD", "data": int.from_bytes(raw, "little")}
    return f"hex({kind:x})"


def parse(text: str) -> RegExport:
    out = RegExport()
    lines = _logical_lines(text)
    first = next((line for _, line in lines if line.strip()), "")
    if first.strip() not in HEADERS:
        raise RegFileError(f"not a .reg export: header is {first[:60]!r}")
    current: str | None = None
    skipping = False
    for lineno, line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith(";"):
            continue
        if stripped.startswith("["):
            if not stripped.endswith("]"):
                raise RegFileError(f"line {lineno}: unterminated key")
            raw = stripped[1:-1]
            if raw.startswith("-"):
                raise RegFileError(f"line {lineno}: key deletions are not an export")
            current = _key_path(raw, lineno)
            skipping = current is None
            if skipping:
                out.skipped.append(f"line {lineno}: unsupported hive [{raw}]")
            else:
                out.keys.setdefault(current, {})
            continue
        if skipping:
            continue
        if current is None:
            raise RegFileError(f"line {lineno}: value outside a key")
        if stripped.startswith("@="):
            name, rest = "", stripped[1:]
        else:
            name, rest = _unquote(stripped, lineno)
        if not rest.startswith("="):
            raise RegFileError(f"line {lineno}: expected '=' after value name")
        rest = rest[1:]
        if rest == "-":
            raise RegFileError(f"line {lineno}: value deletions are not an export")
        value = _value(rest, lineno)
        if isinstance(value, str):
            out.skipped.append(f"{current}: value {name!r} of type {value}")
            continue
        out.keys[current][name] = value
    return out
