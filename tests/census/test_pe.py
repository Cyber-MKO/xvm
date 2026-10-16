from xvm_census import pe


def test_static_imports(pe_fixtures):
    info = pe.analyze(pe_fixtures / "agent.exe", "agent.exe")
    assert info is not None
    assert info.machine == "AMD64"
    assert info.subsystem == "WINDOWS_CUI"
    assert not info.is_dll
    assert info.imports["advapi32.dll"] == ["RegOpenKeyExW"]
    assert "GetProcAddress" in info.imports["kernel32.dll"]
    assert info.imports["helper.dll"] == ["helper_add"]


def test_delay_imports(pe_fixtures):
    info = pe.analyze(pe_fixtures / "agent.exe", "agent.exe")
    assert info.delay_imports == {"wevtapi.dll": ["EvtSubscribe"]}
    assert "wevtapi.dll" not in info.imports


def test_ordinal_import_is_recorded(pe_fixtures):
    info = pe.analyze(pe_fixtures / "agent.exe", "agent.exe")
    assert info.by_ordinal == ["ws2_32.dll!#115=WSAStartup"]
    assert info.imports["ws2_32.dll"] == ["WSAStartup"]


def test_dynamic_loading_flags(pe_fixtures):
    info = pe.analyze(pe_fixtures / "agent.exe", "agent.exe")
    assert info.dynamic_loaders == ["GetModuleHandleW", "GetProcAddress", "LoadLibraryA"]
    assert "iphlpapi.dll" in info.dll_strings
    assert "ntdll.dll" in info.dll_strings  # UTF-16 string
    assert "GetAdaptersAddresses" in info.function_strings
    assert "RtlGetVersion" in info.function_strings
    # Names already in the import table are not candidates.
    assert "RegOpenKeyExW" not in info.function_strings


def test_exports(pe_fixtures):
    info = pe.analyze(pe_fixtures / "helper.dll", "helper.dll")
    assert info.is_dll
    assert info.exports == ["helper_add"]
    assert info.dynamic_loaders == []


def test_not_a_pe(tmp_path):
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ" + b"\0" * 10)
    assert pe.analyze(f, "x.exe") is None
