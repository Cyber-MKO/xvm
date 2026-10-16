# Windows personality: API table

One row per emulated API. Each row needs a census entry naming the calling agent and a test (CLAUDE.md rule 3).

| DLL | Function | Called by (census) | Test | Notes |
| --- | --- | --- | --- | --- |
| `crypt32.dll` | `CertOpenSystemStoreA` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/crypt32/store.rs` tests | Contents from `windows.cert_stores` in the profile. A store the profile does not list opens empty and is logged as a gap |
| `crypt32.dll` | `CertEnumCertificatesInStore` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/crypt32/store.rs` tests | `CERT_CONTEXT` with `CERT_INFO` version, serial, issuer, validity and subject. Algorithm, key, unique IDs and extensions are not filled |
| `crypt32.dll` | `CertGetNameStringA` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/crypt32/store.rs` tests | `CERT_NAME_SIMPLE_DISPLAY_TYPE` only (CN, OU, O, email), subject or issuer. Other types and the alternative-name fallback are logged gaps |
| `crypt32.dll` | `CertCloseStore` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/crypt32/store.rs` tests | Certificates stay valid after closing |
| `kernel32.dll` | `GetCurrentProcess` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/process.rs` tests | The documented pseudo-handle `(HANDLE)-1` |
| `psapi.dll` | `EnumProcessModules` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `tests/process.rs`, `enum_process_modules_lists_the_executable_first` | Current process only: executable first, then load order. Another process is a logged gap |
| `advapi32.dll` | `StartServiceCtrlDispatcherA` | Wazuh 4.14.2: 4 images, including `wazuh-agent.exe` | `tests/process.rs`, `service_dispatcher_*`; `tests/run.rs` | Own-process services only. Runs `ServiceMain` on a new thread, delivers controls on the calling thread, returns after `SERVICE_STOPPED`. Fails with 1063 unless the profile names a service |
| `advapi32.dll` | `RegisterServiceCtrlHandlerA` | Wazuh 4.14.2: 4 images, including `wazuh-agent.exe` | `tests/process.rs`, `service_dispatcher_*`; `tests/run.rs` | Records the handler; held controls go out once it is registered |
| `advapi32.dll` | `SetServiceStatus` | Wazuh 4.14.2: 4 images, including `wazuh-agent.exe` | `tests/process.rs`, `service_dispatcher_*`; `tests/run.rs` | Records the status and logs each state change to stderr |
| `kernel32.dll` | `GetLastError` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `tests/process.rs`, `agent_code_calls_emulated_functions` | Reads `LastErrorValue` from the calling thread's TEB |
| `kernel32.dll` | `SetLastError` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` and `libwazuhext.dll` | `tests/process.rs`, `agent_code_calls_emulated_functions` | Writes `LastErrorValue` in the calling thread's TEB |
| `kernel32.dll` | `InitializeCriticalSection` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/kernel32/critsec.rs` tests | Our lock state in the `CRITICAL_SECTION` fields; see the module doc |
| `kernel32.dll` | `InitializeCriticalSectionAndSpinCount` | Wazuh 4.14.2: 1 image, `libwazuhext.dll` | `src/win/kernel32/critsec.rs` tests | Always succeeds; spin count stored, not used |
| `kernel32.dll` | `EnterCriticalSection` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/kernel32/critsec.rs` tests | Futex mutex; the owner re-enters by counting |
| `kernel32.dll` | `TryEnterCriticalSection` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/critsec.rs` tests | Never blocks |
| `kernel32.dll` | `LeaveCriticalSection` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/kernel32/critsec.rs` tests | Wakes one waiter on the last leave |
| `kernel32.dll` | `DeleteCriticalSection` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/kernel32/critsec.rs` tests | Holds no resources; resets the structure |
| `kernel32.dll` | `AddVectoredExceptionHandler` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/exception.rs` tests | Records the handler in call order. Exceptions are not dispatched yet |
| `kernel32.dll` | `RemoveVectoredExceptionHandler` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/exception.rs` tests | Nonzero if the handle was registered |
| `msvcrt.dll` | `_initterm` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Calls each non-null entry in order |
| `msvcrt.dll` | `__set_app_type` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Kept per process; error output always goes to stderr |
| `msvcrt.dll` | `__p__fmode` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Per-process `_fmode`, default `_O_TEXT` |
| `msvcrt.dll` | `__p__commode` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Per-process `_commode`, default 0 |
| `msvcrt.dll` | `__lconv_init` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Undocumented. Nothing to prepare: `localeconv` will build its data on demand |
| `kernel32.dll` | `SetUnhandledExceptionFilter` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/kernel32/exception.rs` tests | Stores the filter, returns the previous one. Not called yet: no dispatch |
| `kernel32.dll` | `GetModuleHandleA` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `tests/process.rs`, `module_handles_and_proc_addresses_through_kernel32` | NULL gives the main module. Name or full path, ignoring case; `.dll` added when no extension. A miss for a DLL we do not provide is a gap |
| `kernel32.dll` | `GetModuleHandleW` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `tests/process.rs`, `module_handles_and_proc_addresses_through_kernel32` | As `GetModuleHandleA` |
| `kernel32.dll` | `GetProcAddress` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `tests/process.rs`, `module_handles_and_proc_addresses_through_kernel32` | By name or ordinal; follows forwarders. A miss in an emulated DLL is a gap |
| `msvcrt.dll` | `__getmainargs` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | `argv` split by the documented rules; `envp` from the profile. Wildcard expansion is a logged gap |
| `msvcrt.dll` | `__initenv` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Variable (data export) in the emulated image. MinGW stores `envp` in it |
| `msvcrt.dll` | `__p__acmdln` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Address of `_acmdln`, which points at the command line |
| `msvcrt.dll` | `_onexit` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Kept per process for `exit` |
| `msvcrt.dll` | `_chdir` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/dir.rs` tests | Changes the emulated current directory only. ENOENT or ENOTDIR on failure |
| `msvcrt.dll` | `_getcwd` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/dir.rs` tests | NULL buffer: `malloc`s at least `maxlen` bytes. ERANGE if too small |
| `msvcrt.dll` | `_errno` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `src/win/msvcrt/errno.rs` tests | Per-thread `errno` with Microsoft values |
| `msvcrt.dll` | `malloc` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/heap.rs` tests | Host libc heap |
| `msvcrt.dll` | `calloc` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/heap.rs` tests | Host libc heap |
| `msvcrt.dll` | `realloc` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/heap.rs` tests | `realloc(p, 0)` frees and returns NULL, as documented |
| `msvcrt.dll` | `free` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/heap.rs` tests | Host libc heap |
| `msvcrt.dll` | `strlen` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `memcpy` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `memmove` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `memset` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `memcmp` | Wazuh 4.14.2: 7 images, in `dbsync.dll`, `libfimdb.dll`, `libstdc++-6.dll`, `libwazuhext.dll`, `rsync.dll`, `syscollector.dll`, `sysinfo.dll` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `memchr` | Wazuh 4.14.2: 4 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strcmp` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strncmp` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strcpy` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strncpy` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strcat` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strncat` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strchr` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strrchr` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strstr` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strspn` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strcspn` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |
| `msvcrt.dll` | `strpbrk` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/msvcrt/string.rs` tests | Host libc; C-standard behaviour |

Every other census function is a gap. The loader logs it once per module when it binds imports. If agent code calls it, a trap prints `gap call DLL!Function from MODULE at ADDRESS` and the process aborts. To list the gaps for an image, run `cargo run --target i686-unknown-linux-gnu --bin xvm-windows-load -- IMAGE`.

## TEB fields

Agent code reads these through `fs` without calling an API. Evidence comes from disassembling the Wazuh 4.14.2 images (2026-10-16). The census tool does not flag `fs` reads yet. Tests are in `personalities/windows/tests/loader.rs`, `code_reaches_teb_and_tls_through_fs`.

| Offset | Field | Read by | Value we set |
| --- | --- | --- | --- |
| `0x00` | `NT_TIB.ExceptionList` | `libwazuhext.dll` (OpenSSL PadLock SEH frames) | `0xFFFFFFFF`, end of chain |
| `0x04` | `NT_TIB.StackBase` | All 17 images (MinGW start-up lock, via `fs:0x18`) | Top of the thread's stack |
| `0x08` | `NT_TIB.StackLimit` | None seen; set beside `StackBase` | Bottom of the thread's stack |
| `0x10` | `NT_TIB.FiberData` | `libwazuhext.dll` (OpenSSL async, `GetCurrentFiber`) | 0 until `ConvertThreadToFiber` exists |
| `0x18` | `NT_TIB.Self` | All 17 images (MinGW start-up) | The TEB address |
| `0x2C` | `ThreadLocalStoragePointer` | None seen in agent code; required by the PE TLS rules for the 11 images with a TLS directory | Array of per-module TLS blocks |
| `0x34` | `LastErrorValue` | None seen in agent code; our `GetLastError` and `SetLastError` keep it here | Starts at 0 |

Not set: `ClientId` and the PEB pointer at `0x30`. No agent image reads them inline.
