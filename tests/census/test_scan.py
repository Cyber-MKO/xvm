import json
import shutil

from xvm_census import cli, scan


def test_census_classifies_dlls(pe_fixtures):
    c = scan.build_census(pe_fixtures, agent="fake", source="dir")
    assert c["counts"]["pe"] == 2
    dlls = c["dlls"]
    assert dlls["helper.dll"]["kind"] == "bundled"
    assert dlls["kernel32.dll"]["kind"] == "system"
    assert dlls["wevtapi.dll"]["delay_loaded"] is True
    assert dlls["advapi32.dll"]["functions"] == {"RegOpenKeyExW": ["agent.exe"]}
    # GetTickCount is called by the bundled DLL; callers are tracked per function.
    assert dlls["kernel32.dll"]["functions"]["GetTickCount"] == ["helper.dll"]


def test_dynamic_loading_summary(pe_fixtures):
    c = scan.build_census(pe_fixtures, agent="fake", source="dir")
    (dyn,) = c["dynamic_loading"]
    assert dyn["path"] == "agent.exe"
    names = {u["name"]: u["kind"] for u in dyn["unlinked_dll_strings"]}
    assert names == {"iphlpapi.dll": "system", "ntdll.dll": "system"}
    assert "GetAdaptersAddresses" in dyn["function_candidates"]


def test_duplicates_are_skipped(pe_fixtures, tmp_path):
    root = tmp_path / "tree"
    shutil.copytree(pe_fixtures, root)
    (root / "sub").mkdir()
    shutil.copy(root / "helper.dll", root / "sub" / "helper.dll")
    c = scan.build_census(root, agent="fake", source="dir")
    assert c["counts"]["duplicates"] == 1
    helper = next(b for b in c["binaries"] if b["path"] == "helper.dll")
    assert helper["also_at"] == ["sub/helper.dll"]


def test_cli_writes_reports(pe_fixtures, tmp_path):
    out = tmp_path / "reports"
    rc = cli.main(["scan", str(pe_fixtures), "--agent", "fake-agent", "--out", str(out)])
    assert rc == 0
    data = json.loads((out / "fake-agent.json").read_text())
    assert data["schema"] == 1
    md = (out / "fake-agent.md").read_text()
    assert "# API census: fake-agent" in md
    assert "### `wevtapi.dll` (1)" in md
    assert "`helper.dll` | bundled" in md
    assert "`ws2_32.dll!#115=WSAStartup`" in md
    assert "\u2014" not in md  # house style: no em-dashes


def test_report_sections(pe_fixtures, tmp_path):
    out = tmp_path / "reports"
    cli.main(["scan", str(pe_fixtures), "--agent", "fake", "--out", str(out)])
    md = (out / "fake.md").read_text()
    assert "| `agent.exe` | AMD64 | WINDOWS_CUI | 4 | 7 | yes |" in md
    assert "<summary>Function-like strings</summary>" in md


def test_runtime_loaded_modules(pe_fixtures, tmp_path):
    root = tmp_path / "tree"
    shutil.copytree(pe_fixtures, root)
    shutil.copy(root / "helper.dll", root / "plugin.dll")
    (root / "plugin.dll").write_bytes((root / "plugin.dll").read_bytes() + b"\0")
    c = scan.build_census(root, agent="fake", source="dir")
    assert c["runtime_loaded_modules"] == ["plugin.dll"]
