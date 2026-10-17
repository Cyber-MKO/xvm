"""Shared test vectors for the Rust host-state engine (engine/tests/vectors).

Each case holds base.yaml and host.yaml. This test compiles them to the JSON
the engine loads and records resolve() as resolved.json. The engine's tests
check that its layered view gives the same answer.

Run with XVM_UPDATE_VECTORS=1 to rewrite the JSON after changing a case.
"""

import json
import os
from pathlib import Path

import pytest

from xvm_control import profile

VECTORS = Path(__file__).parents[2] / "engine/tests/vectors"
CASES = sorted(p.name for p in VECTORS.iterdir() if (p / "host.yaml").is_file())


def _expected(case: Path) -> dict[str, str]:
    base = profile.load(case / "base.yaml")
    host = profile.load(case / "host.yaml")
    resolved = profile.resolve(host, base)
    return {
        name: json.dumps(doc, indent=1) + "\n"
        for name, doc in (("base.json", base), ("host.json", host), ("resolved.json", resolved))
    }


@pytest.mark.parametrize("case", CASES)
def test_vectors_are_current(case):
    d = VECTORS / case
    for name, text in _expected(d).items():
        if os.environ.get("XVM_UPDATE_VECTORS") == "1":
            (d / name).write_text(text)
        assert (d / name).read_text() == text, f"{case}/{name} is stale: XVM_UPDATE_VECTORS=1"


def test_compile_tree(tmp_path):
    index = profile.compile_tree(
        [VECTORS / "edge/base.yaml", VECTORS / "example/base.yaml"],
        [VECTORS / "edge/host.yaml", VECTORS / "example/host.yaml"],
        tmp_path,
    )
    assert index == {
        "schema": 1,
        "bases": ["edge-base", "windows-example"],
        "hosts": ["edge-host", "win-web-01"],
    }
    assert json.loads((tmp_path / "hosts/edge-host.json").read_text())["kind"] == "host-profile"


def test_compile_rejects_unknown_base(tmp_path):
    with pytest.raises(profile.ProfileError, match="not among the bases"):
        profile.compile_tree(
            [VECTORS / "edge/base.yaml"], [VECTORS / "example/host.yaml"], tmp_path
        )
