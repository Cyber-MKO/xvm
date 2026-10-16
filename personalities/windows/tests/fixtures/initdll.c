/* DLL with a DllMain for start-up tests. Built without a CRT. */
static int attach_count;
static unsigned long last_reason;

int __stdcall DllMain(void *instance, unsigned long reason, void *reserved) {
    (void)instance;
    (void)reserved;
    last_reason = reason;
    attach_count++;
    return 1;
}

__declspec(dllexport) int dll_attach_count(void) { return attach_count; }
__declspec(dllexport) unsigned long dll_reason(void) { return last_reason; }
