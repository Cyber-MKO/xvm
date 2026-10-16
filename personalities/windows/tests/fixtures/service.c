/* Service fixture: a dispatcher table, a ServiceMain and a control handler,
 * as an own-process service writes them. Built without a CRT. */
typedef void(__stdcall *service_main_fn)(unsigned long, char **);
typedef void(__stdcall *handler_fn)(unsigned long);
typedef struct {
    const char *name;
    service_main_fn main;
} table_entry;
typedef struct {
    unsigned long type, state, accepted, exit_code, specific, check_point, wait_hint;
} service_status;

__declspec(dllimport) int __stdcall StartServiceCtrlDispatcherA(const table_entry *);
__declspec(dllimport) unsigned long __stdcall RegisterServiceCtrlHandlerA(const char *, handler_fn);
__declspec(dllimport) int __stdcall SetServiceStatus(unsigned long, service_status *);
__declspec(dllimport) unsigned long __stdcall GetLastError(void);

static unsigned long status_handle;
static unsigned long main_argc;
static char name_seen[32];
static unsigned long main_teb, dispatcher_teb, handler_teb;
static int controls_seen;

static unsigned long teb(void) {
    unsigned long value;
    __asm__ volatile("movl %%fs:0x18, %0" : "=r"(value));
    return value;
}

static void report(unsigned long state) {
    service_status s = {0x10, state, 1, 0, 0, 0, 0};
    SetServiceStatus(status_handle, &s);
}

static void __stdcall handler(unsigned long control) {
    controls_seen++;
    handler_teb = teb();
    if (control == 1) report(1);
}

static void __stdcall service_main(unsigned long argc, char **argv) {
    int i;
    main_argc = argc;
    for (i = 0; argv[0][i] && i < 31; i++) name_seen[i] = argv[0][i];
    status_handle = RegisterServiceCtrlHandlerA(argv[0], handler);
    main_teb = teb();
    report(4);
}

/* Returns 1 after the service stops, or GetLastError() if the dispatcher
 * fails. */
int start(void) {
    table_entry table[] = {{"ignored for own-process services", service_main}, {0, 0}};
    dispatcher_teb = teb();
    if (!StartServiceCtrlDispatcherA(table)) return (int)GetLastError();
    return 1;
}

__declspec(dllexport) unsigned long service_argc(void) { return main_argc; }
__declspec(dllexport) const char *service_name(void) { return name_seen; }
__declspec(dllexport) int service_controls(void) { return controls_seen; }
__declspec(dllexport) unsigned long service_main_teb(void) { return main_teb; }
__declspec(dllexport) unsigned long service_dispatcher_teb(void) { return dispatcher_teb; }
__declspec(dllexport) unsigned long service_handler_teb(void) { return handler_teb; }
