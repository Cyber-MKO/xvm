from xvm_census import strings


def test_dll_names():
    data = b"\0libstdc++-6.dll\0%s.dll\x001libfoo.dll\0KERNEL32.DLL\0"
    assert strings.dll_name_strings(data) == {"libstdc++-6.dll", "kernel32.dll"}


def test_utf16_dll_names():
    assert strings.dll_name_strings("ntdll.dll".encode("utf-16-le")) == {"ntdll.dll"}


def test_function_names():
    data = b"\0GetNativeSystemInfo\0RtlGetVersion\0hello world\0Get\0"
    assert strings.function_name_strings(data) == {"GetNativeSystemInfo", "RtlGetVersion"}
