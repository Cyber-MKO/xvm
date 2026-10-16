import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURE_SRC = Path(__file__).parent / "fixtures" / "src"
BUILD_TOOLS = ("clang", "lld-link", "llvm-dlltool")


def require(*tools: str) -> None:
    missing = [t for t in tools if shutil.which(t) is None]
    if missing:
        pytest.skip(f"missing tools: {', '.join(missing)}")


@pytest.fixture(scope="session")
def pe_fixtures(tmp_path_factory) -> Path:
    """Build agent.exe and helper.dll from fixtures/src. Returns the output directory."""
    require(*BUILD_TOOLS)
    build = tmp_path_factory.mktemp("build")
    subprocess.run(["sh", str(FIXTURE_SRC / "build.sh"), str(build)], check=True)
    out = tmp_path_factory.mktemp("agent")
    for name in ("agent.exe", "helper.dll"):
        shutil.copy(build / name, out / name)
    return out
