"""Command line: xvm-msi-install.

Installs an agent MSI for one host onto its drive folders. The host
profile gives the OS facts that component conditions read and the install
properties (its `agent` section). Gaps go to stderr, one per line.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from xvm_control import profile

from .install import InstallError, install


def _drive(text: str) -> tuple[str, Path]:
    letter, sep, folder = text.partition("=")
    if not sep or len(letter) != 1 or not letter.isalpha():
        raise argparse.ArgumentTypeError(f"expected LETTER=FOLDER, got {text!r}")
    return letter.upper(), Path(folder)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="xvm-msi-install", description=__doc__)
    parser.add_argument("--msi", type=Path, required=True)
    parser.add_argument("--host-profile", type=Path, required=True)
    parser.add_argument("--bases", type=Path, action="append", default=[])
    parser.add_argument("--drive", type=_drive, action="append", required=True)
    parser.add_argument(
        "--program-files",
        required=True,
        help=r"the host's ProgramFilesFolder for this package, such as C:\Program Files (x86)",
    )
    args = parser.parse_args(argv)
    try:
        bases = args.bases or [Path("control/profiles/bases")]
        host = profile.resolve_file(args.host_profile, bases)
        result = install(args.msi, dict(args.drive), host, args.program_files)
    except (InstallError, profile.ProfileError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for gap in result.gaps:
        print(f"gap msi {gap}", file=sys.stderr)
    print(f"installed {result.files} files, created {result.folders} folders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
