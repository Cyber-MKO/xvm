/* Agent stand-in for loader tests. Never run; only its imports matter. */
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);
__declspec(dllimport) unsigned long __stdcall GetLastError(void);
__declspec(dllimport) unsigned long __stdcall ByOrdinal(void);
__declspec(dllimport) int add(int, int);

int start(void) { return add((int)GetTickCount(), (int)(GetLastError() + ByOrdinal())); }
