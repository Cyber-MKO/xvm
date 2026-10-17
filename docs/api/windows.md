# Windows personality: API table

One row per emulated API. Each row needs a census entry naming the calling agent and a test (CLAUDE.md rule 3).

| DLL | Function | Called by (census) | Test | Notes |
| --- | --- | --- | --- | --- |
| `kernel32.dll` | `GetEnvironmentVariableA` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/env.rs` tests | From the profile; names ignore case. An empty value returns 0 and clears the last error |
| `kernel32.dll` | `GetEnvironmentVariableW` | Wazuh 4.14.2: 3 images, in `agent-auth.exe`, `libwazuhext.dll`, `manage_agents.exe` | `src/win/kernel32/env.rs` tests | As `GetEnvironmentVariableA` |
| `kernel32.dll` | `ExpandEnvironmentStringsA` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/kernel32/env.rs` tests | `%NAME%` of defined variables, names ignoring case; others stay as written. Returns the size with the NUL; writes nothing when the buffer is too small |
| `msvcrt.dll` | `time` | Wazuh 4.14.2: 12 images, including `wazuh-agent.exe` | `src/win/msvcrt/time.rs` tests | 32-bit `_time32` from the host clock; -1 after January 2038 |
| `kernel32.dll` | `GetVersionExA` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/version.rs` tests | From the engine's `os_info`, capped by the main module's manifest as documented (6.2.9200 without a Windows 8.1 or 10 entry). CSD version and product type from the engine's registry. `wSuiteMask` is a logged gap |
| `kernel32.dll` | `CreateThread` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/kernel32/thread.rs` tests | New host thread with its own TEB and attach and detach notifications. `CREATE_SUSPENDED` waits for `ResumeThread`. Security attributes are a logged gap |
| `kernel32.dll` | `CreateMutexA` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | Owner may re-enter; abandoned when its thread ends (`WAIT_ABANDONED`). Names in a per-process namespace, case-sensitive, `Global\` and `Local\` the same |
| `kernel32.dll` | `ReleaseMutex` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | ERROR_NOT_OWNER unless the caller owns it |
| `kernel32.dll` | `WaitForMultipleObjects` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | Any or all, up to 64 handles; reports abandoned mutexes |
| `msvcrt.dll` | `srand` | Wazuh 4.14.2: 5 images, including `wazuh-agent.exe` | `src/win/msvcrt/random.rs` tests | Per-thread seed, kept only (`rand` is not imported) |
| `advapi32.dll` | `CryptAcquireContextA` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/advapi32/crypt.rs` tests | Verify contexts and the default key container (not stored on disk: logged gap). Named containers, deleting, named providers: logged gaps |
| `advapi32.dll` | `CryptAcquireContextW` | Wazuh 4.14.2: 1 image, `libwazuhext.dll` | `src/win/advapi32/crypt.rs` tests | As `CryptAcquireContextA` |
| `advapi32.dll` | `CryptGenRandom` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/advapi32/crypt.rs` tests | Bytes from the real kernel's random source |
| `advapi32.dll` | `CryptReleaseContext` | Wazuh 4.14.2: 1 image, `libwazuhext.dll` | `src/win/advapi32/crypt.rs` tests | Ends a context; NTE_BAD_UID for an unknown one, NTE_BAD_FLAGS for flags |
| `kernel32.dll` | `Sleep` | Wazuh 4.14.2: 17 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | 0 yields; INFINITE never returns |
| `msvcrt.dll` | `strerror` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/strerror.rs` tests | Text from the first sentence of each description on Learn's errno constants page (decision A), until golden-capture strings replace it. Unlisted numbers: "Unknown error". One buffer per thread |
| `advapi32.dll` | `RegOpenKeyExA` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/advapi32/registry.rs` tests | Keys from the engine. A 32-bit process on 64-bit Windows reads `HKLM\SOFTWARE` through `WOW6432Node` unless `KEY_WOW64_64KEY`; a missing 32-bit key falls back to the 64-bit one as a logged gap. No subkey: a predefined key returns itself, an open key a new handle. `HKEY_CURRENT_USER` and `HKEY_CLASSES_ROOT` are logged gaps |
| `advapi32.dll` | `RegEnumKeyExA` | Wazuh 4.14.2: 2 images, `sysinfo.dll` and `wazuh-agent.exe` | `src/win/advapi32/registry/enumerate.rs` tests | Subkeys from the engine, sorted without case. No class names. A profile key has no last write time: 0, a logged gap |
| `advapi32.dll` | `RegEnumValueA` | Wazuh 4.14.2: 2 images, `sysinfo.dll` and `wazuh-agent.exe` | `src/win/advapi32/registry/enumerate.rs` tests | Values from the engine, data as `RegQueryValueExA` gives it. ERROR_MORE_DATA for short buffers |
| `advapi32.dll` | `RegQueryInfoKeyA` | Wazuh 4.14.2: 2 images, `sysinfo.dll` and `wazuh-agent.exe` | `src/win/advapi32/registry/enumerate.rs` tests | Counts and longest names and data. Security descriptor length is not modelled: 0, a logged gap when asked for |
| `advapi32.dll` | `RegQueryValueExA` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/advapi32/registry.rs` tests | Values from the engine; strings in the profile's ANSI code page with their NUL. ERROR_MORE_DATA with the size needed |
| `advapi32.dll` | `RegCloseKey` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/advapi32/registry.rs` tests | Predefined roots close as success |
| `kernel32.dll` | `GetFileAttributesA` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/attributes.rs` tests | Directory, or archive for files, plus read-only from host permissions. Hidden and system are not modelled for drive files |
| `msvcrt.dll` | `_fullpath` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/fullpath.rs` tests | Against the process's current directory; a NULL buffer is allocated with `malloc` (at least 260 bytes). ERANGE when the buffer is too small |
| `msvcrt.dll` | `_findfirst` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/find.rs` tests | `*` and `?` ignoring case; `.` and `..` except at a drive root; names in case-insensitive order; `*.*` matches all. Short names not modelled |
| `msvcrt.dll` | `_findnext` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/find.rs` tests | ENOENT after the last match |
| `msvcrt.dll` | `_findclose` | Wazuh 4.14.2: 11 images, including `wazuh-agent.exe` | `src/win/msvcrt/find.rs` tests |  |
| `msvcrt.dll` | `fopen` | Wazuh 4.14.2: 2 images | `src/win/msvcrt/stdio.rs` tests | `r`, `w`, `a` and `+` through CreateFile with `_SH_DENYNO`; `a` writes at the end; `t`/`b` or `_fmode`. Win32 errors map to ENOENT, EACCES, EEXIST |
| `msvcrt.dll` | `_endthreadex` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | Ends the thread through the exit point its routine started at; detach notifications and the thread's signal follow. On the main thread: logged gap, process ends |
| `mpr.dll` | `WNetGetConnectionA` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/mpr/mod.rs` tests | Host drives are local disks: ERROR_NOT_CONNECTED; other names ERROR_BAD_DEVICE |
| `kernel32.dll` | `GetSystemInfo` | Wazuh 4.14.2: 2 images | `src/win/kernel32/sysinfo.rs` tests | The 32-bit view: x86, 4 KB pages, 64 KB granularity, 2 GB (or 4 GB when large-address-aware on 64-bit) of addresses; processors from `hardware.cpu`; level and revision from the registry's processor `Identifier` |
| `kernel32.dll` | `GetFileAttributesExW` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/attributes.rs` tests | As `GetFileAttributesA`, with FILETIMEs and size |
| `msvcrt.dll` | `remove` | Wazuh 4.14.2: 3 images | `src/win/msvcrt/remove.rs` tests | ENOENT, or EACCES for a folder, a read-only file, or a file another handle holds without delete sharing |
| `kernel32.dll` | `LockFile` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/lockfile.rs` tests | Exclusive, fails at once (ERROR_LOCK_VIOLATION). Rules in `filelock.rs`: exclusive overlaps nothing, shared overlaps only shared; closing a handle releases its locks |
| `kernel32.dll` | `LockFileEx` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/lockfile.rs` tests | Offset from the OVERLAPPED; shared or exclusive; waits unless LOCKFILE_FAIL_IMMEDIATELY |
| `kernel32.dll` | `UnlockFile` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/lockfile.rs` tests | The exact range only, else ERROR_NOT_LOCKED |
| `kernel32.dll` | `UnlockFileEx` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/lockfile.rs` tests | As `UnlockFile`, offset from the OVERLAPPED |
| `kernel32.dll` | `GetFileSize` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/fileio.rs` tests | Sets the last error to 0 on success |
| `kernel32.dll` | `GetFileSizeEx` | Wazuh 4.14.2: 2 images | `src/win/kernel32/fileio.rs` tests |  |
| `kernel32.dll` | `SetFilePointer` | Wazuh 4.14.2: 2 images | `src/win/kernel32/fileio.rs` tests | 32-bit or 64-bit distance; ERROR_NEGATIVE_SEEK; last error 0 on success |
| `kernel32.dll` | `WriteFile` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/fileio.rs` tests | Synchronous; an OVERLAPPED names the offset |
| `kernel32.dll` | `FlushFileBuffers` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/fileio.rs` tests |  |
| `kernel32.dll` | `SetEndOfFile` | Wazuh 4.14.2: 2 images | `src/win/kernel32/fileio.rs` tests | At the file pointer |
| `kernel32.dll` | `GetFileType` | Wazuh 4.14.2: 2 images | `src/win/kernel32/fileio.rs` tests | FILE_TYPE_DISK for every file handle |
| `kernel32.dll` | `DeleteFileA` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/fileio.rs` tests | ERROR_ACCESS_DENIED for folders and read-only files; ERROR_SHARING_VIOLATION when held without delete sharing |
| `kernel32.dll` | `DeleteFileW` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/fileio.rs` tests | As `DeleteFileA` |
| `kernel32.dll` | `GetSystemTime` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/kernel32/time.rs` tests | The real machine's clock |
| `kernel32.dll` | `GetSystemTimeAsFileTime` | Wazuh 4.14.2: 11 images, including `wazuh-agent.exe` | `src/win/kernel32/time.rs` tests | The real machine's clock |
| `kernel32.dll` | `FileTimeToSystemTime` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/time.rs` tests |  |
| `kernel32.dll` | `SystemTimeToFileTime` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/time.rs` tests | Years 1601 to 30827; wDayOfWeek ignored |
| `kernel32.dll` | `GetTickCount` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/time.rs` tests | Milliseconds since boot: the engine's start time for the System process (PID 4) |
| `kernel32.dll` | `QueryPerformanceCounter` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/time.rs` tests | 100-nanosecond ticks since that boot |
| `kernel32.dll` | `QueryPerformanceFrequency` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/time.rs` tests | 10 MHz, as documented for Windows under a hypervisor |
| `kernel32.dll` | `GetProcessAffinityMask` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sysinfo.rs` tests | Every processor of `GetSystemInfo`'s count; other processes are a logged gap |
| `msvcrt.dll` | `_beginthreadex` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | As `CreateThread`; EINVAL or EAGAIN on failure |
| `kernel32.dll` | `VerSetConditionMask` | Wazuh 4.14.2: 2 images, `libwazuhext.dll` and `sysinfo.dll` | `src/win/kernel32/version.rs` tests | Three bits per type, at the type's bit position times three (`VER_SET_CONDITION`) |
| `kernel32.dll` | `VerifyVersionInfoW` | Wazuh 4.14.2: 2 images, `libwazuhext.dll` and `sysinfo.dll` | `src/win/kernel32/version.rs` tests | Same facts and manifest cap as `GetVersionExA`. Major, minor and service pack compare as one version. The suite mask is a logged gap |
| `kernel32.dll` | `ResumeThread` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/thread.rs` tests | Lowers the suspend count; a thread created suspended starts at 0. Returns the count before |
| `kernel32.dll` | `GetFileAttributesW` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/attributes.rs` tests | As `GetFileAttributesA` |
| `kernel32.dll` | `GetFileInformationByHandle` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/kernel32/attributes.rs` tests | Attributes, times and size as `GetFileAttributesExW`; links and the host inode as the file index. The volume serial number is 0, a logged gap |
| `kernel32.dll` | `GetProcessHeap` | Wazuh 4.14.2: 3 images, including `wazuh-agent.exe` and `sysinfo.dll` | `src/win/kernel32/heap.rs` tests | A unique non-NULL handle for host libc's heap |
| `kernel32.dll` | `HeapAlloc` | Wazuh 4.14.2: 3 images, including `wazuh-agent.exe` and `sysinfo.dll` | `src/win/kernel32/heap.rs` tests | `HEAP_ZERO_MEMORY` zeroes. Other heaps and `HEAP_GENERATE_EXCEPTIONS` are logged gaps |
| `kernel32.dll` | `HeapFree` | Wazuh 4.14.2: 2 images, `libwazuhext.dll` and `sysinfo.dll` | `src/win/kernel32/heap.rs` tests | NULL is nothing to free. Other heaps are a logged gap |
| `kernel32.dll` | `GetModuleHandleExW` | Wazuh 4.14.2: 2 images, `libstdc++-6.dll` and `libwazuhext.dll` | `tests/process.rs` | By name, or by an address inside the image. Counts as a load unless the refcount stays unchanged; pinning changes nothing visible, as modules are never unmapped |
| `iphlpapi.dll` | `GetAdaptersAddresses` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/iphlpapi/tests.rs` | One adapter per `network.interfaces` entry: GUID, index, names, MAC, type, MTU, speed, status, metric, IPv4 with prefix, gateway, DNS, DHCP, DNS suffix. A fact missing from the profile is a logged gap. IPv6, prefixes and WINS are logged gaps |
| `kernel32.dll` | `GlobalMemoryStatusEx` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/kernel32/sysinfo.rs` tests | Total memory from `hardware.memory_mb`; total virtual from the application address range. Memory in use is not modelled: a logged gap |
| `ole32.dll` | `CoInitializeEx` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/ole32/tests.rs` | Per thread: S_OK, then S_FALSE; RPC_E_CHANGED_MODE for another model |
| `ole32.dll` | `CoUninitialize` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/ole32/tests.rs` | Undoes one `CoInitializeEx` |
| `ole32.dll` | `CoCreateInstance` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/ole32/tests.rs` | The WMI locator only (see "COM interfaces" below). Other classes are a logged gap and REGDB_E_CLASSNOTREG |
| `ole32.dll` | `CoSetProxyBlanket` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/ole32/tests.rs` | S_OK: objects are in-process |
| `oleaut32.dll` | `SysAllocString` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/oleaut32/mod.rs` tests | Length-prefixed UTF-16 on host libc's heap |
| `oleaut32.dll` | `SysAllocStringLen` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/oleaut32/mod.rs` tests | As `SysAllocString`, with a length; zeroed for NULL text |
| `oleaut32.dll` | `SysFreeString` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/oleaut32/mod.rs` tests | NULL is nothing to free |
| `oleaut32.dll` | `SysStringLen` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/oleaut32/mod.rs` tests | UTF-16 units; 0 for NULL |
| `oleaut32.dll` | `VariantClear` | Wazuh 4.14.2: 1 image, `sysinfo.dll` | `src/win/oleaut32/mod.rs` tests | Frees a BSTR, releases an interface, leaves VT_EMPTY. Arrays and references are a logged gap |
| `kernel32.dll` | `CreateToolhelp32Snapshot` | Wazuh 4.14.2: 2 images, `sysinfo.dll` and `wazuh-agent.exe` | `src/win/kernel32/toolhelp.rs` tests | Processes only, from the engine's `proc.list` at that moment. Other snapshot kinds are a logged gap |
| `kernel32.dll` | `Process32First` | Wazuh 4.14.2: 2 images, `sysinfo.dll` and `wazuh-agent.exe` | `src/win/kernel32/toolhelp.rs` tests | ANSI `PROCESSENTRY32`: PID, parent PID, image name. Thread counts and base priorities are not in the process list: 0, a logged gap |
| `kernel32.dll` | `Process32Next` | Wazuh 4.14.2: 2 images, `sysinfo.dll` and `wazuh-agent.exe` | `src/win/kernel32/toolhelp.rs` tests | As `Process32First`; ERROR_NO_MORE_FILES at the end |
| `kernel32.dll` | `GetTimeZoneInformation` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/kernel32/timezone.rs` tests | From `windows.time_zone`. Returns DAYLIGHT or STANDARD for the current instant, UNKNOWN for a zone without daylight time |
| `msvcrt.dll` | `clock` | Wazuh 4.14.2: 1 image, `wazuh-agent.exe` | `src/win/msvcrt/time.rs` tests | Wall-clock milliseconds since the CRT started; -1 once that does not fit |
| `msvcrt.dll` | `gmtime` | Wazuh 4.14.2: 4 images, including `wazuh-agent.exe` and `syscollector.dll` | `src/win/msvcrt/time.rs` tests | 32-bit `time_t`, UTC. Shares `localtime`'s buffer per thread. NULL with EINVAL for a negative time |
| `msvcrt.dll` | `localtime` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/time.rs` tests | 32-bit `time_t`. Uses the profile's zone rules; a `TZ` variable is a logged gap. One buffer per thread. NULL with EINVAL for a negative time |
| `msvcrt.dll` | `fputc` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Buffered, 4096 bytes. Text mode writes LF as CR LF; `_O_APPEND` writes at the end |
| `msvcrt.dll` | `putc` | Wazuh 4.14.2: 1 image, in `libstdc++-6.dll` | `src/win/msvcrt/stdio.rs` tests | As `fputc` |
| `msvcrt.dll` | `fputs` | Wazuh 4.14.2: 5 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | As `fputc`; returns 0 |
| `msvcrt.dll` | `fwrite` | Wazuh 4.14.2: 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | As `fputc`; all items or none |
| `msvcrt.dll` | `fflush` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | NULL flushes every stream. On an input stream: logged gap, read-ahead kept |
| `msvcrt.dll` | `exit` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | `_onexit` functions last first, then flushes streams. `DLL_PROCESS_DETACH` is a logged gap |
| `msvcrt.dll` | `_exit` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/startup.rs` tests | Ends the process at once, without `exit`'s steps |
| `msvcrt.dll` | `_iob` | Wazuh 4.14.2: 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Variable: 20 `FILE`s. A service has no standard handles, so `stdin`, `stdout` and `stderr` have descriptor -2 and their I/O fails |
| `msvcrt.dll` | `_stat` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stat.rs` tests | 36-byte `struct _stat` as documented: drive number, mode bits copied to group and other, creation time in `st_ctime`. EOVERFLOW past 2 GB |
| `wsock32.dll` | `WSAStartup` | Wazuh 4.14.2: 4 images, including `wazuh-agent.exe` | `src/win/wsock32/startup.rs` tests | Counts starts; grants up to version 2.2 |
| `wsock32.dll` | `WSACleanup` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/wsock32/startup.rs` tests | WSANOTINITIALISED without a matching start |
| `wevtapi.dll` | `EvtSubscribe` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | Push subscriptions: a Windows thread per subscription waits on the engine (`evt.wait`) and delivers with `evt.query`. Future, oldest or after a bookmark. Remote sessions and pull subscriptions are logged gaps |
| `wevtapi.dll` | `EvtClose` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | Any EVT_HANDLE; a subscription stops delivering |
| `wevtapi.dll` | `EvtRender` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | Values (EVT_VARIANT array), XML, or bookmark XML, in UTF-16 |
| `wevtapi.dll` | `EvtCreateRenderContext` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | System (18 properties), user (`EventData`), or value paths |
| `wevtapi.dll` | `EvtFormatMessage` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | The event's own message from `evt.format_message`. Other message kinds are logged gaps |
| `wevtapi.dll` | `EvtOpenPublisherMetadata` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | A handle naming the provider; local only |
| `wevtapi.dll` | `EvtCreateBookmark` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | Empty, or from bookmark XML (channel and record ID) |
| `wevtapi.dll` | `EvtUpdateBookmark` | Wazuh 4.14.2: 1 image, in `wazuh-agent.exe` | `src/win/wevtapi/tests.rs` | Records the event's channel and record ID |
| `wsock32.dll` | `gethostname` | Wazuh 4.14.2: 3 images, including `wazuh-agent.exe` | `src/win/wsock32/hostname.rs` tests | `identity.hostname` from the engine. Needs `WSAStartup`; WSAEFAULT when the name and NUL do not fit |
| `ws2_32.dll` | `getaddrinfo` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/ws2_32/addrinfo.rs` tests | Numeric addresses, then the host's `hosts` file (`%SystemRoot%\System32\drivers\etc\hosts` on its drives), then the real resolver. Port numbers only; service names and extra flags are logged gaps |
| `ws2_32.dll` | `freeaddrinfo` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/ws2_32/addrinfo.rs` tests | Unknown pointers are a logged gap |
| `kernel32.dll` | `GetCurrentProcessId` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/process.rs` tests | `windows.agent.pid` from the host profile |
| `msvcrt.dll` | `_getpid` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/startup.rs` tests | As `GetCurrentProcessId` |
| `msvcrt.dll` | `fgetc` | Wazuh 4.14.2: 5 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Unsigned byte or EOF |
| `msvcrt.dll` | `getc` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Same function as `fgetc` |
| `msvcrt.dll` | `ungetc` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Clears end of file; pushing back EOF fails |
| `kernel32.dll` | `GetThreadPriority` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/thread.rs` tests | Kept on the thread object |
| `kernel32.dll` | `SetThreadPriority` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/thread.rs` tests | Kept, not applied to the host scheduler. Background mode is a logged gap |
| `kernel32.dll` | `CreateSemaphoreA` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | A name is a logged gap |
| `kernel32.dll` | `ReleaseSemaphore` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | `ERROR_TOO_MANY_POSTS` past the maximum |
| `kernel32.dll` | `VirtualQuery` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `tests/process.rs`, `virtual_query_and_protect_work_on_image_pages` | Pages of mapped images; writable image pages report `PAGE_READWRITE`. Other addresses are a logged gap |
| `kernel32.dll` | `VirtualProtect` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `tests/process.rs`, `virtual_query_and_protect_work_on_image_pages` | Image pages, applied with `mprotect`. Guard and caching flags are a logged gap |
| `msvcrt.dll` | `_wfopen` | Wazuh 4.14.2: 2 images, `libstdc++-6.dll` and `libwazuhext.dll` | `src/win/msvcrt/stdio.rs` tests | As `fopen`, with UTF-16 name and mode |
| `msvcrt.dll` | `_fdopen` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Modes `r`, `w`, `a`, `+`, `t`, `b` and the hints. Text or binary from the mode, the descriptor or `_fmode` |
| `msvcrt.dll` | `fgets` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Text mode: CR LF to LF, CTRL+Z ends the file |
| `msvcrt.dll` | `feof` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests |  |
| `msvcrt.dll` | `ferror` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests |  |
| `msvcrt.dll` | `fclose` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Flushes first. Also closes the descriptor and its OS handle |
| `msvcrt.dll` | `_strdup` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/msstring.rs` tests |  |
| `msvcrt.dll` | `_stricmp` | Wazuh 4.14.2: 5 images, including `wazuh-agent.exe` | `src/win/msvcrt/msstring.rs` tests | ASCII folding to lower case, as the "C" locale does |
| `msvcrt.dll` | `_strnicmp` | Wazuh 4.14.2: 6 images, including `wazuh-agent.exe` | `src/win/msvcrt/msstring.rs` tests | As `_stricmp` |
| `msvcrt.dll` | `strtol` | Wazuh 4.14.2: 11 images, including `wazuh-agent.exe` | `src/win/msvcrt/convert.rs` tests | Written here so overflow sets the CRT `errno` (ERANGE) |
| `msvcrt.dll` | `strtoul` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/convert.rs` tests | As `strtol`; a minus sign negates |
| `msvcrt.dll` | `atoi` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/convert.rs` tests | `strtol` in base 10 |
| `msvcrt.dll` | `atol` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/convert.rs` tests | `strtol` in base 10 |
| `msvcrt.dll` | `_lock` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/locks.rs` tests | Undocumented. 64 re-entrant locks; other numbers are a logged gap |
| `msvcrt.dll` | `_unlock` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/msvcrt/locks.rs` tests | As `_lock` |
| `kernel32.dll` | `LoadLibraryA` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `src/win/kernel32/library.rs` and `tests/process.rs` | Loaded modules, emulated system DLLs, application directory, current directory, or a path. Runs DLL notifications, then TLS callbacks and `DllMain`, outside the process lock |
| `kernel32.dll` | `LoadLibraryW` | Wazuh 4.14.2: 2 images, in `libstdc++-6.dll`, `libwazuhext.dll` | `src/win/kernel32/library.rs` and `tests/process.rs` | As `LoadLibraryA` |
| `kernel32.dll` | `LoadLibraryExA` | Wazuh 4.14.2: 1 image, including `wazuh-agent.exe` | `src/win/kernel32/library.rs` and `tests/process.rs` | Flags other than 0 are a logged gap |
| `kernel32.dll` | `FreeLibrary` | Wazuh 4.14.2: 16 images, including `wazuh-agent.exe` | `src/win/kernel32/library.rs` and `tests/process.rs` | Counts only; modules are never unmapped |
| `kernel32.dll` | `TlsAlloc` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/tls.rs` tests | 64 `TlsSlots`; zeroes the slot in every thread. Expansion slots are a logged gap |
| `kernel32.dll` | `TlsGetValue` | Wazuh 4.14.2: all 17 images, including `wazuh-agent.exe` | `src/win/kernel32/tls.rs` tests | Clears the last error on success |
| `kernel32.dll` | `TlsSetValue` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/tls.rs` tests |  |
| `kernel32.dll` | `TlsFree` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/tls.rs` tests | Zeroes the slot in every thread |
| `kernel32.dll` | `GetCurrentThreadId` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/process.rs` tests | Linux thread ID times 4 |
| `kernel32.dll` | `GetCurrentThread` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/process.rs` tests | The documented pseudo-handle `(HANDLE)-2` |
| `kernel32.dll` | `DuplicateHandle` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/handle.rs` tests | Current process only; the thread pseudo-handle becomes a real thread handle. Other processes are a logged gap |
| `kernel32.dll` | `CreateEventA` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | Manual and auto reset. A name is a logged gap |
| `kernel32.dll` | `SetEvent` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests |  |
| `kernel32.dll` | `ResetEvent` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests |  |
| `kernel32.dll` | `WaitForSingleObject` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | Events and threads |
| `kernel32.dll` | `WaitForSingleObjectEx` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/kernel32/sync.rs` tests | Alertable waits are a logged gap |
| `msvcrt.dll` | `isalnum` | Wazuh 4.14.2: 5 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `isalpha` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `iscntrl` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `isgraph` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `islower` | Wazuh 4.14.2: 14 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `isprint` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `ispunct` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `isspace` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `isupper` | Wazuh 4.14.2: 14 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `isxdigit` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `tolower` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `msvcrt.dll` | `toupper` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/ctype.rs` tests | "C" locale: ASCII rules |
| `kernel32.dll` | `CreateFileW` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/kernel32/file.rs` tests | All five dispositions, access and share rights, directories with `FILE_FLAG_BACKUP_SEMANTICS`, documented errors. Share modes checked within the process only. Overlapped, delete-on-close, security descriptors, inheritance and templates are logged gaps |
| `kernel32.dll` | `CreateFileA` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/kernel32/file.rs` tests | As `CreateFileW` |
| `kernel32.dll` | `ReadFile` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/kernel32/file.rs` tests | Synchronous; reads to the requested size or the end of the file. With an OVERLAPPED on a synchronous handle, reads at its offset and moves the file pointer; ERROR_HANDLE_EOF at or past the end. Handles opened with FILE_FLAG_OVERLAPPED: logged gap |
| `kernel32.dll` | `CloseHandle` | Wazuh 4.14.2: 12 images, including `wazuh-agent.exe` | `src/win/kernel32/file.rs` tests | Any handle in the process table; the process and thread pseudo-handles always succeed |
| `msvcrt.dll` | `_open_osfhandle` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/msvcrt/lowio.rs` tests | Lowest free descriptor, as `msvcrt` does. A service has no standard handles, so 0 can be returned |
| `msvcrt.dll` | `_filelengthi64` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/lowio.rs` tests | The file's length, or -1 with EBADF |
| `msvcrt.dll` | `_get_osfhandle` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/lowio.rs` tests | The descriptor's OS handle, or -1 with EBADF |
| `msvcrt.dll` | `_read` | Wazuh 4.14.2: 2 images, `libstdc++-6.dll` and `libwazuhext.dll` | `src/win/msvcrt/lowio.rs` tests | Text mode joins CR LF into LF and stops at CTRL+Z, as on Learn |
| `psapi.dll` | `GetModuleFileNameExW` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `tests/process.rs`, `module_file_names_come_from_drives_and_the_system_directory` | Current process only. Agent files map back through the drive table; emulated DLLs report `system_module_directory`. Truncates and NUL-terminates, as documented |
| `wintrust.dll` | `WinVerifyTrust` | Wazuh 4.14.2: 7 images, including `wazuh-agent.exe` | `src/win/wintrust/trust.rs` tests | Verdicts from the profile: emulated system DLLs valid; `trusted_files` valid while the SHA-256 matches, else `TRUST_E_BAD_DIGEST`; others `TRUST_E_NOSIGNATURE`. Generic verify action and file paths only; catalog checks never run for system DLLs |
| `kernel32.dll` | `GetFullPathNameA` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/kernel32/path.rs` tests | Against the emulated current directory; keeps a trailing separator; does not trim trailing dots and spaces. UNC is a logged gap |
| `kernel32.dll` | `GetFullPathNameW` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/kernel32/path.rs` tests | As `GetFullPathNameA` |
| `kernel32.dll` | `MultiByteToWideChar` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/kernel32/codepage.rs` tests | `CP_UTF8` complete. `CP_ACP`, `CP_THREAD_ACP` and `CP_OEMCP` use the profile's code pages (tables: 1252, 437). Composition and glyph flags, and other code pages, are logged gaps |
| `kernel32.dll` | `WideCharToMultiByte` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/kernel32/codepage.rs` tests | As `MultiByteToWideChar`. Best fit from Microsoft's 1252 file unless `WC_NO_BEST_FIT_CHARS`; 437 has exact mappings only. Sets the used-default flag |
| `msvcrt.dll` | `_fileno` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | The stream's descriptor; -2 for a standard stream without one |
| `msvcrt.dll` | `_setjmp3` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `tests/process.rs` (`jump.exe`) | Assembly, reached without the realigning trampoline. Saves the `_JUMP_BUFFER` registers and the SEH chain head |
| `msvcrt.dll` | `longjmp` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `tests/process.rs` (`jump.exe`) | Restores the buffer; `setjmp` returns the value, or 1 for 0. Runs no unwind handlers |
| `msvcrt.dll` | `fread` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Whole items read; drains read-ahead, then reads more. Text mode as `fgets` |
| `msvcrt.dll` | `fseek` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Origins 0, 1 and 2. Writes waiting output, drops read-ahead and pushed-back bytes, clears end of file |
| `msvcrt.dll` | `ftell` | Wazuh 4.14.2: 9 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | File offset: read-ahead counted in file bytes (CR LF is 2), waiting output added. -1 with EINVAL past 31 bits |
| `msvcrt.dll` | `fgetpos` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | 64-bit `fpos_t`, the same offset as `ftell` |
| `msvcrt.dll` | `fsetpos` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Moves to an `fgetpos` offset, as `fseek` from the start |
| `msvcrt.dll` | `clearerr` | Wazuh 4.14.2: 2 images, including `wazuh-agent.exe` | `src/win/msvcrt/stdio.rs` tests | Clears end of file and the error indicator |
| `msvcrt.dll` | `getenv` | Wazuh 4.14.2: 5 images, including `wazuh-agent.exe` | `src/win/msvcrt/env.rs` tests | From the CRT environment (the `envp` of `__getmainargs`, from the profile). Names match without case; the result points into that environment |
| `msvcrt.dll` | `strcoll` | Wazuh 4.14.2: 1 image, `libstdc++-6.dll` | `src/win/msvcrt/locale.rs` tests | The "C" locale: code-unit order, as `strcmp` |
| `msvcrt.dll` | `wcscoll` | Wazuh 4.14.2: 1 image, `libstdc++-6.dll` | `src/win/msvcrt/locale.rs` tests | The "C" locale: code-unit order, as `wcscmp` |
| `msvcrt.dll` | `strxfrm` | Wazuh 4.14.2: 1 image, `libstdc++-6.dll` | `src/win/msvcrt/locale.rs` tests | The "C" locale: the string itself. Returns its length; stores it only when it and its NUL fit |
| `msvcrt.dll` | `wcsxfrm` | Wazuh 4.14.2: 1 image, `libstdc++-6.dll` | `src/win/msvcrt/locale.rs` tests | As `strxfrm`, for UTF-16 |
| `msvcrt.dll` | `qsort` | Wazuh 4.14.2: 9 images, including `libwazuhext.dll` | `src/win/msvcrt/sort.rs` tests | In-place heapsort with the caller's comparison. Not stable, as documented; ends even if the comparison is no order |
| `msvcrt.dll` | `localeconv` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` and `syscollector.dll` | `src/win/msvcrt/locale.rs` tests | The "C" locale's `lconv`: "." as the decimal point, empty strings, CHAR_MAX fields |
| `msvcrt.dll` | `setlocale` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/locale.rs` tests | Only the "C" locale. Any other, including "", fails with NULL and is a logged gap |
| `shlwapi.dll` | `PathIsUNCA` | Wazuh 4.14.2: 8 images, including `wazuh-agent.exe` | `src/win/shlwapi/path.rs` tests | The documented examples, including `\\?\UNC\` |
| `msvcrt.dll` | `wcslen` | Wazuh 4.14.2: 15 images, including `wazuh-agent.exe` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcscpy` | Wazuh 4.14.2: 2 images, in `libstdc++-6.dll`, `libwazuhext.dll` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcsncpy` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcscat` | Wazuh 4.14.2: 1 image, in `libstdc++-6.dll` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcscmp` | Wazuh 4.14.2: 10 images, including `wazuh-agent.exe` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcsncmp` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcsrchr` | Wazuh 4.14.2: 1 image, including `wazuh-agent.exe` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `msvcrt.dll` | `wcsstr` | Wazuh 4.14.2: 1 image, in `libwazuhext.dll` | `src/win/msvcrt/wide.rs` tests | 16-bit `wchar_t`, written here; host libc uses 32 bits |
| `ntdll.dll` | `LdrRegisterDllNotification` | Wazuh 4.14.2: not imported; `ntdll.dll` and this name are in the string census of `wazuh-agent.exe` and others, and the run-time gap log confirmed the lookup | `src/win/ntdll/loader.rs` tests | Records the callback. Nothing calls it until `LoadLibrary` exists |
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

## COM interfaces

Agent code reaches these through vtables, not imports (`src/com.rs`). Methods not listed are gap traps. Tests in `src/win/ole32/tests.rs`.

| Interface | Methods | Notes |
| --- | --- | --- |
| `IWbemLocator` | `ConnectServer` | Local `ROOT\CIMV2` only. Credentials on a local connection: WBEM_E_LOCAL_CREDENTIALS. Other namespaces and servers are logged gaps |
| `IWbemServices` | `ExecQuery` | WQL `SELECT * FROM Win32_QuickFixEngineering`, from the profile's `hotfixes`. Other queries are logged gaps |
| `IEnumWbemClassObject` | `Next`, `Skip`, `Reset` | Over the rows taken when the query ran |
| `IWbemClassObject` | `Get` | `HotFixID`, `Description`, `InstalledOn` (M/D/YYYY), `InstalledBy`, `CSName`, `__CLASS`. Properties without a profile source are VT_NULL and a logged gap |
| All of them | `QueryInterface`, `AddRef`, `Release` | `IUnknown` and the object's own interface; others are a logged gap |

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
