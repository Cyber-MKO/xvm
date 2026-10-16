/* Executable that imports a DLL whose DllMain fails. */
__declspec(dllimport) int never_called(void);

int start(void) { return never_called(); }
