# Windows personality: API table

One row per emulated API. Each row needs a census entry naming the calling agent and a test (CLAUDE.md rule 3).

| DLL | Function | Called by (census) | Test | Notes |
| --- | --- | --- | --- | --- |
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
