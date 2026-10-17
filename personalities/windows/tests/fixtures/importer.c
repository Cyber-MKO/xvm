/* Agent stand-in for loader tests. Never run; only its imports matter. */
__declspec(dllimport) int __stdcall Beep(unsigned long frequency, unsigned long duration);
__declspec(dllimport) unsigned long __stdcall GetLastError(void);
__declspec(dllimport) unsigned long __stdcall ByOrdinal(void);
__declspec(dllimport) int add(int, int);

int start(void) { return add((int)Beep(0, 0), (int)(GetLastError() + ByOrdinal())); }
