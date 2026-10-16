/* TLS fixture for loader tests: implicit TLS, a TLS callback and direct fs
 * reads, the way MinGW and OpenSSL code in the Wazuh agent does them.
 * No imports. Built without a CRT, so it carries its own TLS directory,
 * laid out as "The .tls Section" of the PE format specification describes. */
typedef void(__stdcall *tls_callback)(void *, unsigned long, void *);

typedef struct {
    unsigned long start, end, index, callbacks, zero_fill, characteristics;
} tls_directory;

/* Sections sort by the text after '$', so _tls_start and _tls_end bracket
 * every __declspec(thread) variable, and __xl_a and __xl_z the callbacks. */
#pragma section(".tls", read, write)
#pragma section(".tls$ZZZ", read, write)
#pragma section(".CRT$XLA", read)
#pragma section(".CRT$XLB", read)
#pragma section(".CRT$XLZ", read)
__declspec(allocate(".tls")) char _tls_start = 0;
__declspec(allocate(".tls$ZZZ")) char _tls_end = 0;
__declspec(allocate(".CRT$XLA")) tls_callback __xl_a = 0;
__declspec(allocate(".CRT$XLZ")) tls_callback __xl_z = 0;
unsigned long _tls_index = 0xffffffff;
/* The compiler reaches the TLS array as fs:__tls_array, an absolute symbol
 * at the TEB offset of ThreadLocalStoragePointer. */
__asm__(".globl __tls_array\n.set __tls_array, 0x2c");

__declspec(thread) int tls_counter = 5;

static unsigned long last_reason;
static int callback_calls;
static void *callback_handle;

static void __stdcall on_tls(void *handle, unsigned long reason, void *reserved) {
    (void)reserved;
    callback_handle = handle;
    last_reason = reason;
    callback_calls++;
}
__declspec(allocate(".CRT$XLB")) tls_callback __xl_b = on_tls;

const tls_directory _tls_used = {
    (unsigned long)&_tls_start, (unsigned long)&_tls_end, (unsigned long)&_tls_index,
    (unsigned long)(&__xl_a + 1), 0, 0,
};

static unsigned long fs_dword(unsigned long offset) {
    unsigned long value;
    __asm__ volatile("movl %%fs:(%1), %0" : "=r"(value) : "r"(offset));
    return value;
}

/* NtCurrentTeb() and NT_TIB.StackBase, as MinGW's start-up code reads them. */
__declspec(dllexport) unsigned long teb_self(void) { return fs_dword(0x18); }
__declspec(dllexport) unsigned long teb_stack_base(void) {
    return ((unsigned long *)teb_self())[1];
}
/* NT_TIB.ExceptionList, pushed and popped by SEH frames. */
__declspec(dllexport) unsigned long seh_head(void) { return fs_dword(0); }
/* NT_TIB.FiberData, as GetCurrentFiber() reads it. */
__declspec(dllexport) unsigned long fiber_data(void) { return fs_dword(0x10); }

__declspec(dllexport) int bump_tls(void) { return ++tls_counter; }
__declspec(dllexport) unsigned long tls_index(void) { return _tls_index; }
__declspec(dllexport) unsigned long tls_last_reason(void) { return last_reason; }
__declspec(dllexport) int tls_callback_calls(void) { return callback_calls; }
__declspec(dllexport) void *tls_callback_handle(void) { return callback_handle; }
