/* Executable for start-up tests: its exit code shows what DllMain saw. */
__declspec(dllimport) int dll_attach_count(void);
__declspec(dllimport) unsigned long dll_reason(void);

int start(void) { return (int)dll_reason() * 10 + dll_attach_count(); }
