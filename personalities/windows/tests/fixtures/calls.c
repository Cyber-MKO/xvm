/* Calls into emulated kernel32 for loader tests. Built without a CRT. */
__declspec(dllimport) unsigned long __stdcall GetLastError(void);
__declspec(dllimport) void __stdcall SetLastError(unsigned long);
__declspec(dllimport) int __stdcall Beep(unsigned long frequency, unsigned long duration);

__declspec(dllexport) unsigned long last_error_round_trip(unsigned long code) {
    SetLastError(code);
    return GetLastError();
}

/* Beep is not implemented (no agent calls it), so this must hit its trap. */
__declspec(dllexport) unsigned long call_missing(void) { return (unsigned long)Beep(0, 0); }
