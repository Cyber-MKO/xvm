# Phase 1 sizing: Wazuh Windows agent census

- Target: `wazuh-agent-4.14.2-1.msi`, the default version in Habeny (`app/installers/wazuh.py`)
- SHA-256: `e1eb434f1694283b89e07021cce1bded4ef25275d9efe6ca0edf2d514a7ea959`
- Generated report: [census/reports/wazuh-agent-4.14.2-windows.md](../census/reports/wazuh-agent-4.14.2-windows.md)
- Also censused: 4.14.9, the newest 4.x on 2026-10-16 ([report](../census/reports/wazuh-agent-4.14.9-windows.md)). See the version diff below.
- Status: the four questions are answered (2026-10-16). See Decisions.

## Headline numbers

| Measure | Value |
| --- | --- |
| PE images | 17 (all PE32, i386, built with MinGW) |
| OS DLLs imported | 19 |
| OS functions imported, whole package | 617 |
| OS functions imported, agent service only | 596 |
| Delay-load imports | none |
| Ordinal imports | none |
| Bundled DLLs loaded only at run time | `libfimdb.dll`, `libwazuhshared.dll`, `syscollector.dll` |

The service is `wazuh-agent.exe` plus the DLLs it loads. It needs almost the whole surface. The other binaries add very little.

| Binary group | OS functions | Extra over the service |
| --- | --- | --- |
| Service: `wazuh-agent.exe` and all bundled DLLs | 596 | n/a |
| Enrollment and tools: `agent-auth.exe`, `manage_agents.exe` | 269 | 2 (`msvcrt`) |
| Active response: `netsh.exe`, `route-null.exe`, `restart-wazuh.exe` | 217 | 0 |
| GUI: `win32ui.exe` | 280 | 19 (mostly `user32`). Out of scope by rule 6. |

## Service surface per DLL

| DLL | Functions | What it is for |
| --- | --- | --- |
| `kernel32.dll` | 186 | Files, processes, threads, sync, heap, virtual memory, TLS, fibers, toolhelp, `ReadDirectoryChangesW` |
| `msvcrt.dll` | 188 | C runtime. MinGW links the system CRT, so we must provide it. |
| `advapi32.dll` | 101 | Registry, services (SCM), security and ACLs, legacy Event Log, CryptoAPI, LSA, audit policy |
| `wsock32.dll` | 30 | BSD sockets |
| `crypt32.dll` | 20 | Certificate stores and chains |
| `ws2_32.dll` | 18 | Winsock 2 events and `getaddrinfo` |
| `wevtapi.dll` | 8 | Event Log subscribe, render, bookmarks, message formatting |
| `version.dll` | 3 | File version resources |
| `wintrust.dll` | 6 | `WinVerifyTrust`, catalog hashes |
| `iphlpapi.dll` | 5 | Adapters, TCP and UDP tables |
| `netapi32.dll` | 5 | Users and local groups |
| `oleaut32.dll` | 5 | BSTR and VARIANT helpers for COM |
| `ole32.dll` | 4 | `CoCreateInstance`, `CoSetProxyBlanket`: almost certainly WMI from `sysinfo.dll` |
| `psapi.dll` | 4 | Process modules and memory |
| `shlwapi.dll` | 5 | Path helpers |
| `user32.dll` | 4 | `GetSystemMetrics`, `MessageBoxW`, `GetProcessWindowStation`, `GetUserObjectInformationW` |
| `wtsapi32.dll` | 3 | Session enumeration |
| `mpr.dll` | 1 | `WNetGetConnectionA` (mapped network drives) |

## Version diff: 4.14.2 against 4.14.9

The surfaces are almost the same, so the choice of version does not change the plan.

| Only in 4.14.2 | Only in 4.14.9 |
| --- | --- |
| `kernel32!lstrcmpiA`, `mpr!WNetGetConnectionA`, `shlwapi!PathIsUNCA` | `kernel32!CreateSemaphoreW`, `GetModuleFileNameW`, `GetTickCount64`; `ntdll!NtQueryInformationProcess`, `VerSetConditionMask`; `shell32!CommandLineToArgvW`; `version!GetFileVersionInfoA`, `GetFileVersionInfoSizeA`, `VerQueryValueA`; `ws2_32!WSACleanup`, `WSAStartup` |

## Run-time lookups seen in strings

These are candidates for `GetProcAddress`. The runtime gap log will confirm them.

| Name | Where | Likely use |
| --- | --- | --- |
| `GetNativeSystemInfo` | most binaries | Architecture for inventory |
| `Wow64DisableWow64FsRedirection` | `wazuh-agent.exe` | 32-bit agent reading the 64-bit `System32` |
| `LdrRegisterDllNotification` | `wazuh-agent.exe`, `agent-auth.exe` | DLL load hook |
| `GetIfEntry2`, `ConvertLengthToIpv4Mask` | `sysinfo.dll` | Network inventory |
| `GetSystemFirmwareTable` | `sysinfo.dll` | SMBIOS for hardware inventory |
| `GetTickCount64`, `CreateToolhelp32Snapshot`, `AddDllDirectory` | `libwazuhext.dll` | Runtime support (SQLite, OpenSSL, libcurl) |

The string lists also contain many registry value names (`CurrentBuildNumber`, `ReleaseId`, `DisplayVersion`, `InstallLocation`, `ProfileImagePath`). These tell the host-state engine which keys a host profile must fill.

## Findings that change the plan

1. **The agent is 32-bit.** Every image is PE32 for i386. The brief assumed nothing about bitness. The loader must run i386 code. See decision 1.
2. **The CRT is not bundled.** The brief's risk table expected agents to link their own CRT. Wazuh links the system `msvcrt.dll`, so 188 CRT functions are ours to provide.
3. **`user32.dll` is on the service path.** Four functions, most likely from OpenSSL (service detection and fatal-error popups). None need a window system. See decision 3.
4. **COM is on the service path.** `sysinfo.dll` uses COM, very likely WMI. This is Phase 3 (inventory) work, but `ole32` must load in Phase 1.
5. **No delay loads and no ordinals.** The import side of the loader is simple.
6. **The MSI runs script custom actions.** `InstallerScripts` (VBScript) writes `ossec.conf` from installer properties, sets permissions, creates a dump registry key and starts the service. Our installer step must do the same things from the host profile.

## Decisions (Kasim, 2026-10-16)

| # | Question | Decision | Consequence |
| --- | --- | --- | --- |
| 1 | How do we run i386 code? | The Windows personality is a 32-bit Linux process (Rust target `i686-unknown-linux-gnu`). | Agent code runs natively. The host kernel needs `CONFIG_IA32_EMULATION=y` and must not boot with `ia32_emulation=0`. Checked on the dev container. Check on the Habeny host before Phase 4. |
| 2 | How do we provide `msvcrt.dll`? | Our own CRT on top of host libc, with Windows semantics added (paths, text mode, `errno` values, `_stat` layout), one function at a time from the census. | Each function needs a census entry, a test and a row in `docs/api/windows.md` (rule 3). |
| 3 | Is a non-GUI `user32` subset allowed under rule 6? | Yes. Only the census functions, with no window system. `MessageBoxW` logs its text and returns as if dismissed. | No windows, message loops or desktop. Any other `user32` call is a logged gap. |
| 4 | Which agent version is the Phase 1 target? | 4.14.2, Habeny's default. | Census report for 4.14.2 is committed. 4.14.9 stays as a reference. |
