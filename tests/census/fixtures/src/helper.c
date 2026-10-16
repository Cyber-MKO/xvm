/* Bundled DLL shipped beside the fake agent. */
__declspec(dllimport) unsigned long __stdcall GetTickCount(void);
__declspec(dllexport) int helper_add(int a, int b) { return a + b + (int)GetTickCount(); }
int _DllMainCRTStartup(void *h, unsigned long r, void *p) { (void)h; (void)r; (void)p; return 1; }
