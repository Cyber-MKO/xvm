import json

from xvm_census import cli, runtime, scan

LOG = """\
service WazuhSvc: SERVICE_RUNNING
gap GetProcAddress ws2_32.dll!inet_ntop from wazuh-agent.exe
gap GetProcAddress WS2_32.dll!inet_ntop from wazuh-agent.exe
gap GetProcAddress kernel32.dll!GetSystemFirmwareTable from other.exe
gap call KERNEL32.dll!CreatePipe from wazuh-agent.exe at 0x0045690f
gap feature kernel32.dll!GetVersionExA: wSuiteMask from wazuh-agent.exe
"""


def test_lookups_are_parsed_from_the_gap_log():
    assert runtime.parse_log(LOG) == {
        ("ws2_32.dll", "inet_ntop", "wazuh-agent.exe"),
        ("kernel32.dll", "GetSystemFirmwareTable", "other.exe"),
    }


def test_runtime_command_merges_into_the_report(pe_fixtures, tmp_path):
    report = tmp_path / "agent.json"
    census = scan.build_census(pe_fixtures, agent="fake", source="dir")
    report.write_text(json.dumps(census))
    log = tmp_path / "run.log"
    log.write_text(LOG.replace("from wazuh-agent.exe", "from AGENT.EXE"))
    assert cli.main(["runtime", str(report), str(log)]) == 0
    out = json.loads(report.read_text())
    assert out["runtime_lookups"] == {
        "kernel32.dll": {"GetSystemFirmwareTable": ["other.exe"]},
        "ws2_32.dll": {"inet_ntop": ["agent.exe"]},
    }
    md = (tmp_path / "agent.md").read_text()
    assert "## Run-time lookups" in md
    assert "| `ws2_32.dll` | `inet_ntop` | `agent.exe` |" in md
    # Running again adds nothing.
    assert runtime.merge(out, runtime.parse_log(log.read_text())) == 0
