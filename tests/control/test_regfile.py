import pytest

from xvm_control import regfile

from .golden_capture import files

CV = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"


def _parse(name):
    return regfile.parse(regfile.decode(files()[f"registry/{name}.reg"]))


def test_value_types():
    exp = _parse("os-currentversion")
    v = exp.keys[CV]
    assert v["ProductName"] == {"type": "REG_SZ", "data": "Windows Server 2022 Standard Evaluation"}
    assert v["UBR"] == {"type": "REG_DWORD", "data": 0xA2B}
    assert v["SystemRoot"]["data"] == "C:\\Windows"  # \\ unescaped
    assert v['Quote "x"'] == {"type": "REG_SZ", "data": "y"}
    assert v["PathName"] == {"type": "REG_EXPAND_SZ", "data": "%SystemRoot%\\x"}  # continuation
    assert v["Multi"] == {"type": "REG_MULTI_SZ", "data": ["a", "b"]}
    assert v["Q"] == {"type": "REG_QWORD", "data": 1}
    assert v["Blob"] == {"type": "REG_BINARY", "data": "deadbeef"}
    assert v[""] == {"type": "REG_SZ", "data": "default"}
    assert "Odd" not in v
    assert exp.skipped == [f"{CV}: value 'Odd' of type hex(0)"]
    assert exp.keys[CV + r"\Empty"] == {}


def test_utf8_and_regedit4():
    exp = regfile.parse('REGEDIT4\n\n[HKEY_USERS\\.DEFAULT\\X]\n"A"="b"\n')
    assert exp.keys == {r"HKU\.DEFAULT\X": {"A": {"type": "REG_SZ", "data": "b"}}}


def test_unsupported_hive_is_reported():
    exp = regfile.parse('REGEDIT4\n[HKEY_CURRENT_USER\\X]\n"A"="b"\n[HKEY_USERS\\Y]\n')
    assert exp.keys == {r"HKU\Y": {}}
    assert exp.skipped == [r"line 2: unsupported hive [HKEY_CURRENT_USER\X]"]


@pytest.mark.parametrize(
    "text, message",
    [
        ("hello", "not a .reg export"),
        ('REGEDIT4\n"A"="b"\n', "outside a key"),
        ("REGEDIT4\n[-HKEY_USERS\\X]\n", "deletions"),
        ('REGEDIT4\n[HKEY_USERS\\X]\n"A"=-\n', "deletions"),
        ('REGEDIT4\n[HKEY_USERS\\X]\n"A"="b\n', "unterminated string"),
        ('REGEDIT4\n[HKEY_USERS\\X]\n"A"=hex:zz\n', "bad hex"),
        ('REGEDIT4\n[HKEY_USERS\\X]\n"A"=float:1\n', "unknown value form"),
        ("REGEDIT4\n[HKEY_USERS]\n", "hive root"),
    ],
)
def test_errors(text, message):
    with pytest.raises(regfile.RegFileError, match=message):
        regfile.parse(text)
