import copy
from pathlib import Path

import pytest
import yaml

from xvm_control import cli, profile

EXAMPLES = Path(__file__).parents[2] / "control/profiles/examples"
BASES = EXAMPLES / "bases"
WEB = EXAMPLES / "hosts/win-web-01.yaml"
KEY_CV = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"


@pytest.fixture
def base():
    return profile.load(BASES / "windows-example.yaml")


@pytest.fixture
def host():
    return profile.load(WEB)


def test_examples_resolve():
    r = profile.resolve_file(WEB, [BASES])
    assert r["kind"] == "resolved-host"
    assert r["base"] == "windows-example"
    assert r["identity"]["hostname"] == "WIN-WEB-01"
    assert r["os_info"]["build"] == "20348"  # inherited
    assert r["hardware"]["memory_mb"] == 8192  # overridden
    assert r["hardware"]["cpu"]["cores"] == 2  # nested object kept


def test_keyed_lists(host, base):
    r = profile.resolve(host, base)
    assert [u["name"] for u in r["users"]] == ["Administrator", "webadmin"]
    w32 = next(s for s in r["services"] if s["name"] == "W32Time")
    assert w32 == {
        "name": "W32Time",
        "display_name": "Windows Time",
        "state": "stopped",
        "start_mode": "manual",
    }
    nic = r["network"]["interfaces"][0]
    assert nic["description"] == "Example virtual NIC" and nic["ipv4"] == ["192.0.2.11/24"]


def test_names_match_case_insensitively(host, base):
    host["users"] = [{"name": "guest", "remove": True}, {"name": "ADMINISTRATOR", "enabled": False}]
    r = profile.resolve(host, base)
    assert r["users"] == [{**base["users"][0], "enabled": False}]  # base spelling kept


def test_remove_missing_entry_fails(host, base):
    host["users"] = [{"name": "nobody", "remove": True}]
    with pytest.raises(profile.ProfileError, match="cannot remove 'nobody'"):
        profile.resolve(host, base)


def test_registry_merge(host, base):
    host["registry"] = {
        "keys": {
            KEY_CV.lower(): {"ubr": {"type": "REG_DWORD", "data": 2}, "DisplayVersion": None},
            r"HKLM\SOFTWARE\Example": {"Path": {"type": "REG_SZ", "data": r"C:\Example"}},
        }
    }
    r = profile.resolve(host, base)
    cv = r["registry"]["keys"][KEY_CV]
    assert cv["UBR"] == {"type": "REG_DWORD", "data": 2}  # original key and value case kept
    assert "DisplayVersion" not in cv
    assert r["registry"]["keys"][r"HKLM\SOFTWARE\Example"]["Path"]["data"] == r"C:\Example"


def test_registry_delete_keys(host, base):
    base["registry"]["keys"][KEY_CV + r"\Sub"] = {"X": {"type": "REG_SZ", "data": "1"}}
    host["registry"] = {"delete_keys": [KEY_CV]}
    r = profile.resolve(host, base)
    # The key goes with everything below it (Sub, Time Zones); other keys stay.
    left = r["registry"]["keys"]
    assert left and not any(k.lower().startswith(KEY_CV.lower()) for k in left)
    host["registry"] = {"delete_keys": [r"HKLM\SOFTWARE\Missing"]}
    with pytest.raises(profile.ProfileError, match="cannot delete"):
        profile.resolve(host, base)


@pytest.mark.parametrize(
    "value",
    [
        {"type": "REG_DWORD", "data": -1},
        {"type": "REG_DWORD", "data": "10"},
        {"type": "REG_SZ", "data": 5},
        {"type": "REG_MULTI_SZ", "data": "a"},
        {"type": "REG_BINARY", "data": "zz"},
        {"type": "REG_NONE", "data": ""},
    ],
)
def test_bad_registry_values(base, value):
    base["registry"]["keys"][KEY_CV]["Bad"] = value
    with pytest.raises(profile.ProfileError):
        profile.validate(base)


def test_bad_registry_key_path(base):
    base["registry"]["keys"][r"HKEY_LOCAL_MACHINE\SOFTWARE"] = {}
    with pytest.raises(profile.ProfileError, match="registry/keys"):
        profile.validate(base)


def test_base_cannot_remove_or_delete(base):
    b = copy.deepcopy(base)
    b["users"].append({"name": "x", "remove": True})
    with pytest.raises(profile.ProfileError, match="cannot remove"):
        profile.validate(b)
    b = copy.deepcopy(base)
    b["registry"]["keys"][KEY_CV]["UBR"] = None
    with pytest.raises(profile.ProfileError, match="cannot delete values"):
        profile.validate(b)


def test_duplicate_names(base):
    base["users"].append({"name": "administrator"})
    with pytest.raises(profile.ProfileError, match="duplicate name"):
        profile.validate(base)


def test_profile_requires_base_and_identity(host):
    del host["identity"]
    with pytest.raises(profile.ProfileError, match="identity"):
        profile.validate(host)


def test_registry_only_on_windows(base):
    base["os"] = "linux"
    with pytest.raises(profile.ProfileError):
        profile.validate(base)


def test_os_mismatch(host, base):
    base["os"] = "linux"
    del base["registry"]
    with pytest.raises(profile.ProfileError, match="does not match"):
        profile.resolve(host, base)


def test_unknown_field_rejected(host):
    host["identity"]["hostnmae"] = "typo"
    with pytest.raises(profile.ProfileError, match="hostnmae"):
        profile.validate(host)


def test_unquoted_yaml_timestamp(tmp_path):
    doc = yaml.safe_load((BASES / "windows-example.yaml").read_text())
    doc["os_info"]["install_date"] = "PLACEHOLDER"
    text = yaml.safe_dump(doc).replace("PLACEHOLDER", "2026-01-01 08:30:00")
    p = tmp_path / "windows-example.yaml"
    p.write_text(text)
    with pytest.raises(profile.ProfileError, match="os_info/install_date: quote timestamps"):
        profile.load(p)


def test_cli(capsys):
    assert cli.main(["resolve", str(WEB), "--bases", str(BASES), "--format", "json"]) == 0
    assert '"hostname": "WIN-WEB-01"' in capsys.readouterr().out
    assert cli.main(["validate", str(WEB), "--bases", str(BASES / "missing")]) == 1
    assert "not found" in capsys.readouterr().err


def test_loader_settings(host, base):
    r = profile.resolve(host, base)
    assert r["agent"]["pid"] == 4812
    assert r["agent"]["environment"]["COMPUTERNAME"] == "WIN-WEB-01"
    assert len(r["windows"]["trusted_files"]) == 17
    host["agent"]["pid"] = 4810
    with pytest.raises(profile.ProfileError, match="multiple of 4"):
        profile.validate(host)
    host["agent"]["pid"] = 4812
    host["windows"]["trusted_files"] = {"relative\\x.exe": "0" * 64}
    with pytest.raises(profile.ProfileError, match="not an absolute path"):
        profile.validate(host)
    host["windows"] = {"cert_stores": {"ROOT": [{"der": "AAA"}]}}
    with pytest.raises(profile.ProfileError, match="bad base64"):
        profile.validate(host)
    host["windows"] = {"system_module_directory": "C:\\Windows\\SysWOW64"}
    host["os"] = "linux"
    host.pop("registry")
    with pytest.raises(profile.ProfileError, match="only for os windows"):
        profile.validate(host)
