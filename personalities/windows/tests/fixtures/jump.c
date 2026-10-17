/* setjmp and longjmp through msvcrt's raw exports. The exit code is
   71: the first longjmp delivers 7, the second (with 0) delivers 1. */
__declspec(dllimport) int __cdecl _setjmp3(void *buf, int count);
__declspec(dllimport) void __cdecl longjmp(void *buf, int value);

static int buffer[16];

static void dive(int n) {
    if (n == 0)
        longjmp(buffer, 7);
    dive(n - 1);
}

int start(void) {
    volatile int first = _setjmp3(buffer, 0);
    if (first == 0) {
        dive(3);
        return 1;
    }
    volatile int second = _setjmp3(buffer, 0);
    if (second == 0)
        longjmp(buffer, 0);
    return first * 10 + second;
}
