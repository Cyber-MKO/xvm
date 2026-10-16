/* Executable that imports psapi.dll and a bundled DLL. Never run. */
__declspec(dllimport) int __stdcall EnumProcessModules(void *, void **, unsigned long,
                                                       unsigned long *);
__declspec(dllimport) int add(int, int);

int start(void) { return EnumProcessModules(0, 0, 0, 0) + add(1, 2); }
