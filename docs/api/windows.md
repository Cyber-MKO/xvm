# Windows personality: API table

One row per emulated API. Each row needs a census entry naming the calling agent and a test (CLAUDE.md rule 3).

| DLL | Function | Called by (census) | Test | Notes |
| --- | --- | --- | --- | --- |

No APIs implemented yet.

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

Not set: `ClientId`, `LastErrorValue` and the PEB pointer at `0x30`. No agent image reads them inline.
