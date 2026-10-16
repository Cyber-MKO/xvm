/* DLL with a DllMain for start-up tests. Built without a CRT. */
static int attach_count;
static unsigned long last_reason;
static int reason_counts[4];

int __stdcall DllMain(void *instance, unsigned long reason, void *reserved) {
    (void)instance;
    (void)reserved;
    last_reason = reason;
    if (reason < 4) reason_counts[reason]++;
    if (reason == 1) attach_count++;
    return 1;
}

__declspec(dllexport) int dll_attach_count(void) { return attach_count; }
__declspec(dllexport) unsigned long dll_reason(void) { return last_reason; }
__declspec(dllexport) int dll_reason_count(unsigned long reason) {
    return reason < 4 ? reason_counts[reason] : -1;
}
