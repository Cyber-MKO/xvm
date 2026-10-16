/* Bundled-DLL stand-in for loader tests. No imports, so it can run before
 * any emulated API exists. Built without a CRT or SDK headers. */
static int counter = 40;
/* An exported pointer in data keeps a HIGHLOW relocation the optimizer
 * cannot fold away. */
__declspec(dllexport) int *counter_ptr = &counter;

__declspec(dllexport) int add(int a, int b) { return a + b; }
__declspec(dllexport) int bump(void) { return ++*counter_ptr; }
int hidden(void) { return 7; }
