/* DLL whose DllMain refuses to load. */
int __stdcall DllMain(void *instance, unsigned long reason, void *reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return 0;
}

__declspec(dllexport) int never_called(void) { return 1; }
