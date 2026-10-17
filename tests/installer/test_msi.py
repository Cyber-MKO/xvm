import shutil
import subprocess

import pytest

from xvm_msi.condition import ConditionError, evaluate
from xvm_msi.install import apply_properties, install, raw_value, resolve_directories

CONF = (
    "<ossec_config>\r\n  <client>\r\n    <server>\r\n      <address>0.0.0.0</address>\r\n"
    "      <port>1514</port>\r\n    </server>\r\n    <notify_time>20</notify_time>\r\n"
    "  </client>\r\n</ossec_config>\r\n"
)

WXS = """<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Fake Agent" Language="1033" Version="1.0.0"
           Manufacturer="xvm" UpgradeCode="11111111-2222-3333-4444-555555555555">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine"/>
    <Media Id="1" Cabinet="simple.cab" EmbedCab="yes"/>
    <Property Id="MAJORVERSION">
      <RegistrySearch Id="Major" Root="HKLM" Type="raw"
                      Key="SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"
                      Name="CurrentMajorVersionNumber"/>
    </Property>
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="APPLICATIONFOLDER" Name="fake-agent">
          <Component Id="Conf" Guid="AAAAAAAA-0000-0000-0000-000000000001">
            <File Id="OSSEC_CONF" Name="ossec.conf" Source="ossec.conf"/>
          </Component>
          <Component Id="Modern" Guid="AAAAAAAA-0000-0000-0000-000000000002">
            <File Id="SERVER_TXT" Name="server.txt" Source="server.txt"/>
          </Component>
          <Component Id="Client" Guid="AAAAAAAA-0000-0000-0000-000000000003">
            <File Id="CLIENT_TXT" Name="client.txt" Source="client.txt"/>
          </Component>
          <Directory Id="QUEUE" Name="queue">
            <Directory Id="LOGCOLLECTOR" Name="logcollector">
              <Component Id="LogFolder" Guid="AAAAAAAA-0000-0000-0000-000000000004">
                <CreateFolder/>
              </Component>
            </Directory>
          </Directory>
        </Directory>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1">
      <ComponentRef Id="Conf"/>
      <ComponentRef Id="Modern"/>
      <ComponentRef Id="Client"/>
      <ComponentRef Id="LogFolder"/>
    </Feature>
  </Product>
</Wix>
"""


CONDITIONS = {
    "Modern": 'MAJORVERSION = "#10" AND MsiNTProductType > 1',
    "Client": "MsiNTProductType = 1",
}


def test_conditions():
    props = {"VersionNT": "603", "MsiNTProductType": "3", "MAJORVERSION": "#10"}
    assert evaluate("VersionNT >= 600", props) == (True, {"VersionNT"})
    assert evaluate('MAJORVERSION = "#10" AND MsiNTProductType = 1', props)[0] is False
    assert evaluate("( VersionNT = 501 OR VersionNT64 = 501 )", props)[0] is False
    assert evaluate('NOT BUILDVERSION AND ProductName ~= "x"', {"ProductName": "X"})[0]
    assert evaluate("", props) == (True, set())
    with pytest.raises(ConditionError):
        evaluate("VersionNT >=", props)


def test_directories_and_raw_values():
    rows = [
        {"Directory": "TARGETDIR", "Directory_Parent": "", "DefaultDir": "SourceDir"},
        {"Directory": "APP", "Directory_Parent": "ProgramFilesFolder", "DefaultDir": "a|app"},
        {"Directory": "Q", "Directory_Parent": "APP", "DefaultDir": "c-7jk|logs:src"},
        {"Directory": "SAME", "Directory_Parent": "APP", "DefaultDir": "."},
    ]
    roots = {"TARGETDIR": "C:\\", "ProgramFilesFolder": "C:\\Program Files (x86)"}
    dirs = resolve_directories(rows, roots)
    assert dirs["Q"] == "C:\\Program Files (x86)\\app\\logs"
    assert dirs["SAME"] == dirs["APP"]
    assert raw_value({"type": "REG_DWORD", "data": 10}) == "#10"
    assert raw_value({"type": "REG_SZ", "data": "#x"}) == "##x"
    assert raw_value({"type": "REG_SZ", "data": "20348"}) == "20348"


def test_properties_set_the_documented_ossec_conf_settings():
    conf, gaps = apply_properties(
        CONF, {"WAZUH_MANAGER": "10.0.0.5", "WAZUH_AGENT_GROUP": "web", "WAZUH_PROTOCOL": "udp"}
    )
    assert "<address>10.0.0.5</address>" in conf
    assert (
        "    <enrollment>\r\n      <groups>web</groups>\r\n    </enrollment>\r\n  </client>" in conf
    )
    assert "<port>1514</port>" in conf
    assert gaps == ["install property WAZUH_PROTOCOL"]


def _host(product_type: str) -> dict:
    current = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    return {
        "os_info": {"version": "10.0", "architecture": "x86_64"},
        "registry": {
            "keys": {
                current: {
                    "CurrentMajorVersionNumber": {"type": "REG_DWORD", "data": 10},
                    "InstallationType": {"type": "REG_SZ", "data": product_type},
                }
            }
        },
        "agent": {"product": "wazuh", "version": "1.0.0", "manager": "manager.example"},
    }


@pytest.mark.parametrize(
    ("kind", "installed"), [("Server", "server.txt"), ("Client", "client.txt")]
)
def test_install_a_package(tmp_path, kind, installed):
    for tool in ("wixl", "msibuild", "msiinfo", "bsdtar"):
        if shutil.which(tool) is None:
            pytest.skip(f"missing tool: {tool}")
    src = tmp_path / "src"
    src.mkdir()
    (src / "ossec.conf").write_bytes(CONF.encode())
    (src / "server.txt").write_text("server")
    (src / "client.txt").write_text("client")
    (src / "fake.wxs").write_text(WXS)
    subprocess.run(["wixl", "-o", "fake.msi", "fake.wxs"], cwd=src, check=True)
    # wixl has no component conditions: set them in the Component table.
    msi = str(src / "fake.msi")
    for component, condition in CONDITIONS.items():
        query = (
            f"UPDATE `Component` SET `Condition` = '{condition}' WHERE `Component` = '{component}'"
        )
        subprocess.run(["msibuild", msi, "-q", query], check=True)
    c = tmp_path / "c"
    c.mkdir()
    result = install(src / "fake.msi", {"C": c}, _host(kind), "C:\\Program Files (x86)")
    app = c / "Program Files (x86)" / "fake-agent"
    assert (app / "queue" / "logcollector").is_dir()
    assert sorted(p.name for p in app.iterdir() if p.is_file()) == sorted(["ossec.conf", installed])
    assert "<address>manager.example</address>" in (app / "ossec.conf").read_text()
    assert result.files == 2
    assert result.folders == 1
    assert "AppSearch MAJORVERSION: read the 64-bit view of " in " ".join(result.gaps)
