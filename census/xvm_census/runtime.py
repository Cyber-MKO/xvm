"""Run-time lookups: functions an agent finds with GetProcAddress.

Static analysis cannot see names an agent looks up at run time. The
personality logs every lookup it cannot answer (CLAUDE.md rule 4) as

    gap GetProcAddress DLL!FUNCTION from IMAGE

Kasim decided (2026-11-13) that such a lookup counts as a census entry
once it is recorded here, with the image that asked. It is then
implemented like an import, with a test and a doc line (rule 3).
"""

from __future__ import annotations

import re
from pathlib import Path

_LINE = re.compile(r"^gap GetProcAddress (?P<dll>[^!\s]+)!(?P<function>\S+) from (?P<image>.+)$")


def parse_log(text: str) -> set[tuple[str, str, str]]:
    """(dll, function, image) for each lookup gap in a personality log."""
    found = set()
    for line in text.splitlines():
        m = _LINE.match(line.strip())
        if m:
            found.add((m["dll"].lower(), m["function"], m["image"]))
    return found


def _image_path(census: dict, image: str) -> str:
    """The package path of a binary named `image`, or the name itself."""
    for b in census.get("binaries", []):
        for path in [b["path"], *b.get("also_at", [])]:
            if Path(path).name.lower() == image.lower():
                return path
    return image


def merge(census: dict, lookups: set[tuple[str, str, str]]) -> int:
    """Add lookups to `census["runtime_lookups"]` ({dll: {function: [images]}}).

    Returns how many (dll, function, image) entries are new.
    """
    section: dict = census.setdefault("runtime_lookups", {})
    added = 0
    for dll, function, image in sorted(lookups):
        callers = section.setdefault(dll, {}).setdefault(function, [])
        path = _image_path(census, image)
        if path not in callers:
            callers.append(path)
            callers.sort()
            added += 1
    census["runtime_lookups"] = {
        dll: dict(sorted(funcs.items())) for dll, funcs in sorted(section.items())
    }
    return added
