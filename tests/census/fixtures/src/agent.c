/* Fake agent for census tests. Never run; only its import tables and strings matter.
 * Built without a CRT or SDK headers so the fixture is small and deterministic. */
typedef void *HANDLE;
typedef unsigned long DWORD;
#define IMPORT __declspec(dllimport)

IMPORT long __stdcall RegOpenKeyExW(HANDLE, const unsigned short *, DWORD, DWORD, HANDLE *);
IMPORT HANDLE __stdcall LoadLibraryA(const char *);
IMPORT void *__stdcall GetProcAddress(HANDLE, const char *);
IMPORT HANDLE __stdcall GetModuleHandleW(const unsigned short *);
IMPORT void __stdcall ExitProcess(unsigned);
IMPORT HANDLE __stdcall EvtSubscribe(HANDLE, HANDLE, const unsigned short *,
                                     const unsigned short *, HANDLE, void *, void *, DWORD);
IMPORT int __stdcall WSAStartup(unsigned short, void *);
IMPORT int helper_add(int, int);

/* lld-link needs a delay-load helper; real binaries get it from delayimp.lib. */
void *__delayLoadHelper2(const void *desc, void **slot) { (void)desc; return *slot; }

void start(void) {
    HANDLE k;
    char wsa[512];
    RegOpenKeyExW((HANDLE)0x80000002, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0,
                  0x20019, &k);
    HANDLE m = LoadLibraryA("iphlpapi.dll");
    void *f = GetProcAddress(m, "GetAdaptersAddresses");
    void *g = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    EvtSubscribe(0, 0, L"Security", L"*", 0, 0, 0, 1);
    WSAStartup(0x202, wsa);
    ExitProcess(helper_add(f != 0, g != 0));
}
