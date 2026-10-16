# Phase 1 sizing: Wazuh Windows agent census

- Package: `wazuh-agent-4.14.9-1.msi` (newest 4.x on packages.wazuh.com on 2026-10-16)
- SHA-256: `e3f18109d36c98c2f861f210fc6661226d99251b79321c5d7ff27821b906ea49`
- Generated report: [census/reports/wazuh-agent-4.14.9-windows.md](../census/reports/wazuh-agent-4.14.9-windows.md)
- Status: waiting for Kasim's review. The PE loader does not start before that.

## Headline numbers

| Measure | Value |
| --- | --- |
| PE images | 17 (all PE32, i386, built with MinGW) |
| OS DLLs imported | 20 |
| OS functions imported, whole package | 625 |
| OS functions imported, agent service only | 602 |
| Delay-load imports | none |
| Ordinal imports | none |
| Bundled DLLs loaded only at run time | `libfimdb.dll`, `libwazuhshared.dll`, `syscollector.dll` |

The service is `wazuh-agent.exe` plus the DLLs it loads. It needs almost the whole surface. The other binaries add very little.

| Binary group | OS functions | Extra over the service |
| --- | --- | --- |
| Service: `wazuh-agent.exe` and all bundled DLLs | 602 | n/a |
| Enrollment and tools: `agent-auth.exe`, `manage_agents.exe` | 272 | 2 (`msvcrt`) |
| Active response: `netsh.exe`, `route-null.exe`, `restart-wazuh.exe` | 220 | 2 (`ws2_32`) |
| GUI: `win32ui.exe` | 282 | 19 (mostly `user32`). Out of scope by rule 6. |

## Service surface per DLL

| DLL | Functions | What it is for |
| --- | --- | --- |
| `kernel32.dll` | 188 | Files, processes, threads, sync, heap, virtual memory, TLS, fibers, toolhelp, `ReadDirectoryChangesW` |
| `msvcrt.dll` | 188 | C runtime. MinGW links the system CRT, so we must provide it. |
| `advapi32.dll` | 101 | Registry, services (SCM), security and ACLs, legacy Event Log, CryptoAPI, LSA, audit policy |
| `wsock32.dll` | 30 | BSD sockets |
| `crypt32.dll` | 20 | Certificate stores and chains |
| `ws2_32.dll` | 18 | Winsock 2 events and `getaddrinfo` |
| `wevtapi.dll` | 8 | Event Log subscribe, render, bookmarks, message formatting |
| `version.dll` | 6 | File version resources |
| `wintrust.dll` | 6 | `WinVerifyTrust`, catalog hashes |
| `iphlpapi.dll` | 5 | Adapters, TCP and UDP tables |
| `netapi32.dll` | 5 | Users and local groups |
| `oleaut32.dll` | 5 | BSTR and VARIANT helpers for COM |
| `ole32.dll` | 4 | `CoCreateInstance`, `CoSetProxyBlanket`: almost certainly WMI from `sysinfo.dll` |
| `psapi.dll` | 4 | Process modules and memory |
| `shlwapi.dll` | 4 | Path helpers |
| `user32.dll` | 4 | `GetSystemMetrics`, `MessageBoxW`, `GetProcessWindowStation`, `GetUserObjectInformationW` |
| `wtsapi32.dll` | 3 | Session enumeration |
| `ntdll.dll` | 2 | `NtQueryInformationProcess`, `VerSetConditionMask` |
| `shell32.dll` | 1 | `CommandLineToArgvW` |

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

1. **The agent is 32-bit.** Every image is PE32 for i386. The brief assumed nothing about bitness. The loader must run i386 code. See question 1.
2. **The CRT is not bundled.** The brief's risk table expected agents to link their own CRT. Wazuh links the system `msvcrt.dll`, so 188 CRT functions are ours to provide.
3. **`user32.dll` is on the service path.** Four functions, most likely from OpenSSL (service detection and fatal-error popups). None need a window system. See question 3.
4. **COM is on the service path.** `sysinfo.dll` uses COM, very likely WMI. This is Phase 3 (inventory) work, but `ole32` must load in Phase 1.
5. **No delay loads and no ordinals.** The import side of the loader is simple.
6. **The MSI runs script custom actions.** `InstallerScripts` (VBScript) writes `ossec.conf` from installer properties, sets permissions, creates a dump registry key and starts the service. Our installer step must do the same things from the host profile.

## Questions for Kasim

| # | Question | Options | Recommendation |
| --- | --- | --- | --- |
| 1 | How do we run i386 code? | A: the Windows personality is a 32-bit Linux process (i686 target, multilib). B: a 64-bit process that switches to a 32-bit code segment, like WoW64. C: CPU emulation. | A. Simplest and native speed. B only if we later need 64-bit agents in the same process. |
| 2 | How do we provide `msvcrt.dll`? | A: our own CRT on top of host libc, with Windows semantics added (paths, text mode, `errno`, `_stat` layout). B: a full CRT written from scratch. | A, function by function from the census, each with a test. |
| 3 | Is a non-GUI `user32` subset allowed under rule 6? | A: yes. Implement only the 4 census functions with no window system, and log `MessageBoxW` text. B: no. Leave the imports unresolved and fail. | A. It adds no GUI subsystem, and B stops the agent from loading. |
| 4 | Which agent version is the Phase 1 target? | A: 4.14.9, as censused. B: the version in Habeny's Wazuh baselines. | Whichever Habeny uses. Rerunning the census takes three seconds. |
