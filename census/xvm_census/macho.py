"""Minimal Mach-O reader: slices and linked dylibs.

Symbol-level imports (bind opcodes, chained fixups) are not parsed yet. They
come with the macOS personality (roadmap Phase 6).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .strings import dylib_name_strings

_FAT = (0xCAFEBABE, 0xCAFEBABF)
_THIN = {
    0xFEEDFACE: ("<", 32),
    0xFEEDFACF: ("<", 64),
    0xCEFAEDFE: (">", 32),
    0xCFFAEDFE: (">", 64),
}
_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64"}
_LC_LOAD_DYLIB = {
    0xC: "load",
    0x18 | 0x80000000: "weak",
    0x1F | 0x80000000: "reexport",
    0x23 | 0x80000000: "upward",
    0x20: "lazy",
}


@dataclass
class MachOInfo:
    path: str
    slices: list[dict] = field(default_factory=list)
    dylib_strings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": "macho",
            "slices": self.slices,
            "dylib_strings": self.dylib_strings,
            "errors": self.errors,
        }


def is_macho(head: bytes) -> bool:
    if len(head) < 8:
        return False
    magic_be = struct.unpack(">I", head[:4])[0]
    if magic_be in _FAT:
        # Java class files share 0xCAFEBABE; a fat header has a small arch count.
        return 0 < struct.unpack(">I", head[4:8])[0] < 32
    return struct.unpack("<I", head[:4])[0] in _THIN


def _thin(data: bytes, off: int) -> dict:
    magic = struct.unpack_from("<I", data, off)[0]
    endian, bits = _THIN[magic]
    cputype, _sub, _ftype, ncmds, _size = struct.unpack_from(endian + "iiiII", data, off + 4)
    pos = off + (32 if bits == 64 else 28)
    dylibs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from(endian + "II", data, pos)
        kind = _LC_LOAD_DYLIB.get(cmd)
        if kind is not None:
            name_off = struct.unpack_from(endian + "I", data, pos + 8)[0]
            raw = data[pos + name_off : pos + cmdsize]
            dylibs.append({"name": raw.split(b"\0", 1)[0].decode(errors="replace"), "kind": kind})
        if cmdsize == 0:
            break
        pos += cmdsize
    return {"arch": _CPU.get(cputype & 0xFFFFFFFF, hex(cputype & 0xFFFFFFFF)), "dylibs": dylibs}


def analyze(path: Path, rel: str) -> MachOInfo:
    data = path.read_bytes()
    info = MachOInfo(path=rel)
    try:
        magic = struct.unpack(">I", data[:4])[0]
        if magic in _FAT:
            nfat = struct.unpack_from(">I", data, 4)[0]
            entry = 32 if magic == 0xCAFEBABF else 20
            for i in range(nfat):
                if entry == 20:
                    _cpu, _sub, offset, _size, _align = struct.unpack_from(
                        ">iiIII", data, 8 + i * 20
                    )
                else:
                    _cpu, _sub, offset, _size, _align, _r = struct.unpack_from(
                        ">iiQQII", data, 8 + i * 32
                    )
                info.slices.append(_thin(data, offset))
        else:
            info.slices.append(_thin(data, 0))
    except (struct.error, KeyError) as exc:
        info.errors.append(f"malformed Mach-O: {exc}")
    info.dylib_strings = sorted(dylib_name_strings(data))
    return info
