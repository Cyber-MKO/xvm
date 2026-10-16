"""Unpack agent packages (MSI, PKG, DEB, RPM) into a directory tree.

Nested archives found inside a package (for example a PKG Payload, a DEB
data.tar, or a CAB inside an MSI) are unpacked in place, up to a fixed depth.
All work uses external tools: msitools, bsdtar (libarchive), rpm2cpio, cpio.
"""

from __future__ import annotations

import gzip
import shutil
import subprocess
from pathlib import Path

MAX_DEPTH = 4

# Magic bytes for formats we unpack.
_OLE_CFB = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # MSI is an OLE compound file
_XAR = b"xar!"  # macOS flat PKG
_AR = b"!<arch>\n"  # DEB
_RPM = b"\xed\xab\xee\xdb"
_CAB = b"MSCF"
_GZIP = b"\x1f\x8b"
_PBZX = b"pbzx"
_CPIO = (b"070701", b"070702", b"070707")


class UnpackError(RuntimeError):
    pass


def detect(path: Path) -> str | None:
    """Return the archive kind of a file, or None if it is not one we unpack."""
    try:
        with path.open("rb") as f:
            head = f.read(512)
    except OSError:
        return None
    if head.startswith(_OLE_CFB) and path.suffix.lower() in (".msi", ".msp", ""):
        return "msi"
    if head.startswith(_XAR):
        return "pkg"
    if head.startswith(_AR):
        return "deb"
    if head.startswith(_RPM):
        return "rpm"
    if head.startswith(_CAB):
        return "cab"
    if head.startswith(_PBZX):
        return "pbzx"
    if head.startswith(_CPIO):
        return "cpio"
    if head.startswith(_GZIP):
        return "gzip"
    if len(head) > 262 and head[257:262] == b"ustar":
        return "tar"
    if (
        head[:3] in (b"BZh",)
        or head.startswith(b"\xfd7zXZ\x00")
        or head.startswith(b"\x28\xb5\x2f\xfd")
    ):
        return "compressed"
    return None


def _run(cmd: list[str], cwd: Path | None = None, stdin: bytes | None = None) -> bytes:
    exe = shutil.which(cmd[0])
    if exe is None:
        raise UnpackError(f"required tool not found: {cmd[0]}")
    proc = subprocess.run(cmd, cwd=cwd, input=stdin, capture_output=True, check=False)
    if proc.returncode != 0:
        raise UnpackError(
            f"{' '.join(cmd)} failed ({proc.returncode}): {proc.stderr.decode(errors='replace')}"
        )
    return proc.stdout


def _bsdtar(src: Path, dest: Path) -> None:
    _run(["bsdtar", "-xf", str(src.resolve()), "-C", str(dest)])


def _unpack_one(kind: str, src: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    if kind == "msi":
        _run(["msiextract", "-C", str(dest), str(src.resolve())])
    elif kind == "rpm":
        cpio_data = _run(["rpm2cpio", str(src.resolve())])
        _run(["cpio", "-idm", "--no-absolute-filenames", "--quiet"], cwd=dest, stdin=cpio_data)
    elif kind == "gzip" and not _is_tar_gz(src):
        with gzip.open(src, "rb") as fin, (dest / src.stem).open("wb") as fout:
            shutil.copyfileobj(fin, fout)
    elif kind == "pbzx":
        raise UnpackError("pbzx payloads (macOS) are not supported yet")
    else:
        # pkg (xar), deb (ar), cab, cpio, tar and compressed tarballs.
        _bsdtar(src, dest)


def _is_tar_gz(path: Path) -> bool:
    try:
        with gzip.open(path, "rb") as f:
            head = f.read(512)
    except OSError:
        return False
    return (len(head) > 262 and head[257:262] == b"ustar") or head.startswith(_CPIO)


def unpack(package: Path, dest: Path) -> list[str]:
    """Unpack a package and its nested archives into dest.

    Returns a list of notes (for example nested archives that could not be
    unpacked). Raises UnpackError if the top-level package fails.
    """
    notes: list[str] = []
    kind = detect(package)
    if kind is None:
        raise UnpackError(f"unrecognised package format: {package}")
    _unpack_one(kind, package, dest)
    _expand_nested(dest, depth=1, notes=notes)
    return notes


def _expand_nested(root: Path, depth: int, notes: list[str]) -> None:
    if depth > MAX_DEPTH:
        return
    for path in sorted(p for p in root.rglob("*") if p.is_file() and not p.is_symlink()):
        kind = detect(path)
        if kind is None:
            continue
        target = path.with_name(path.name + ".d")
        try:
            _unpack_one(kind, path, target)
        except UnpackError as exc:
            notes.append(f"{path.relative_to(root)}: {exc}")
            shutil.rmtree(target, ignore_errors=True)
            continue
        _expand_nested(target, depth + 1, notes)
