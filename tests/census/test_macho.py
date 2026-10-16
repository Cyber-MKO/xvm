import struct

from xvm_census import macho


def _thin(cputype: int, dylib: str) -> bytes:
    """A minimal 64-bit Mach-O with one LC_LOAD_DYLIB command."""
    name = dylib.encode() + b"\0"
    cmdsize = (24 + len(name) + 7) & ~7
    cmd = struct.pack("<IIIIII", 0xC, cmdsize, 24, 0, 0, 0) + name
    cmd = cmd.ljust(cmdsize, b"\0")
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 3, 2, 1, cmdsize, 0, 0)
    return header + cmd


def test_thin(tmp_path):
    f = tmp_path / "agent"
    f.write_bytes(_thin(0x01000007, "/usr/lib/libSystem.B.dylib"))
    assert macho.is_macho(f.read_bytes()[:8])
    info = macho.analyze(f, "agent")
    assert info.errors == []
    assert info.slices == [
        {"arch": "x86_64", "dylibs": [{"name": "/usr/lib/libSystem.B.dylib", "kind": "load"}]}
    ]


def test_fat(tmp_path):
    a = _thin(0x01000007, "/usr/lib/libSystem.B.dylib")
    b = _thin(0x0100000C, "/usr/lib/libc++.1.dylib")
    off_a, off_b = 0x1000, 0x2000
    head = struct.pack(">II", 0xCAFEBABE, 2)
    head += struct.pack(">iiIII", 0x01000007, 3, off_a, len(a), 12)
    head += struct.pack(">iiIII", 0x0100000C, 0, off_b, len(b), 12)
    data = head.ljust(off_a, b"\0") + a.ljust(off_b - off_a, b"\0") + b
    f = tmp_path / "fat"
    f.write_bytes(data)
    info = macho.analyze(f, "fat")
    assert [s["arch"] for s in info.slices] == ["x86_64", "arm64"]
    assert info.slices[1]["dylibs"][0]["name"] == "/usr/lib/libc++.1.dylib"


def test_java_class_is_not_macho():
    assert not macho.is_macho(struct.pack(">II", 0xCAFEBABE, 0x34))
