# API census: wazuh-agent-4.14.2-windows

- Source: `wazuh-agent-4.14.2-1.msi`
- SHA-256: `e1eb434f1694283b89e07021cce1bded4ef25275d9efe6ca0edf2d514a7ea959`
- Generated: 2026-10-16T21:12:16Z by xvm-census 0.0.1
- JSON with per-binary detail sits next to this file.

## Summary

| Measure | Value |
| --- | --- |
| Files unpacked | 59 |
| PE images (unique) | 17 |
| Mach-O images (unique) | 0 |
| ELF files | 0 |
| Duplicate binaries skipped | 0 |
| OS DLLs imported (system and API set) | 19 |
| OS functions imported | 617 |
| Bundled DLLs imported | 7 |
| Binaries with dynamic loading | 16 |

## Binaries

| Binary | Machine | Subsystem | OS DLLs | OS functions | Dynamic loading |
| --- | --- | --- | --- | --- | --- |
| `Program Files/ossec-agent/active-response/bin/netsh.exe` | I386 | WINDOWS_CUI | 9 | 215 | yes |
| `Program Files/ossec-agent/active-response/bin/restart-wazuh.exe` | I386 | WINDOWS_CUI | 9 | 216 | yes |
| `Program Files/ossec-agent/active-response/bin/route-null.exe` | I386 | WINDOWS_CUI | 9 | 217 | yes |
| `Program Files/ossec-agent/agent-auth.exe` | I386 | WINDOWS_CUI | 11 | 266 | yes |
| `Program Files/ossec-agent/dbsync.dll` | I386 | WINDOWS_CUI | 2 | 52 | yes |
| `Program Files/ossec-agent/libfimdb.dll` | I386 | WINDOWS_CUI | 2 | 51 | yes |
| `Program Files/ossec-agent/libgcc_s_dw2-1.dll` | I386 | WINDOWS_CUI | 2 | 29 | yes |
| `Program Files/ossec-agent/libstdc++-6.dll` | I386 | WINDOWS_CUI | 2 | 125 | yes |
| `Program Files/ossec-agent/libwazuhext.dll` | I386 | WINDOWS_CUI | 7 | 350 | yes |
| `Program Files/ossec-agent/libwazuhshared.dll` | I386 | WINDOWS_CUI | 8 | 224 | yes |
| `Program Files/ossec-agent/libwinpthread-1.dll` | I386 | WINDOWS_CUI | 2 | 76 | no |
| `Program Files/ossec-agent/manage_agents.exe` | I386 | WINDOWS_CUI | 11 | 266 | yes |
| `Program Files/ossec-agent/rsync.dll` | I386 | WINDOWS_CUI | 2 | 51 | yes |
| `Program Files/ossec-agent/syscollector.dll` | I386 | WINDOWS_CUI | 2 | 52 | yes |
| `Program Files/ossec-agent/sysinfo.dll` | I386 | WINDOWS_CUI | 12 | 146 | yes |
| `Program Files/ossec-agent/wazuh-agent.exe` | I386 | WINDOWS_CUI | 12 | 360 | yes |
| `Program Files/ossec-agent/win32ui.exe` | I386 | WINDOWS_GUI | 12 | 280 | yes |

## Bundled DLLs loaded only at run time

No binary imports these statically. They are loaded with `LoadLibrary*`.

- `Program Files/ossec-agent/libfimdb.dll`
- `Program Files/ossec-agent/libwazuhshared.dll`
- `Program Files/ossec-agent/syscollector.dll`

## DLLs by function count

Bundled DLLs ship with the agent. We load them, we do not emulate them.

| DLL | Kind | Delay-loaded | Functions | Callers |
| --- | --- | --- | --- | --- |
| `msvcrt.dll` | system | no | 191 | 17 |
| `kernel32.dll` | system | no | 188 | 17 |
| `advapi32.dll` | system | no | 101 | 10 |
| `wsock32.dll` | system | no | 30 | 6 |
| `crypt32.dll` | system | no | 20 | 8 |
| `user32.dll` | system | no | 19 | 10 |
| `ws2_32.dll` | system | no | 18 | 7 |
| `wevtapi.dll` | system | no | 8 | 1 |
| `wintrust.dll` | system | no | 6 | 7 |
| `iphlpapi.dll` | system | no | 5 | 1 |
| `netapi32.dll` | system | no | 5 | 1 |
| `oleaut32.dll` | system | no | 5 | 1 |
| `shlwapi.dll` | system | no | 5 | 8 |
| `ole32.dll` | system | no | 4 | 1 |
| `psapi.dll` | system | no | 4 | 8 |
| `version.dll` | system | no | 3 | 1 |
| `wtsapi32.dll` | system | no | 3 | 1 |
| `comctl32.dll` | system | no | 1 | 1 |
| `mpr.dll` | system | no | 1 | 8 |
| `libstdc++-6.dll` | bundled | no | 212 | 5 |
| `libwazuhext.dll` | bundled | no | 38 | 1 |
| `libwinpthread-1.dll` | bundled | no | 22 | 2 |
| `dbsync.dll` | bundled | no | 21 | 3 |
| `libgcc_s_dw2-1.dll` | bundled | no | 20 | 6 |
| `rsync.dll` | bundled | no | 12 | 2 |
| `sysinfo.dll` | bundled | no | 1 | 1 |

## OS functions per DLL

### `msvcrt.dll` (191)

`__getmainargs`, `__initenv`, `__lconv_init`, `__mb_cur_max`, `__p___argv`, `__p__acmdln`, `__p__commode`, `__p__fmode`, `__set_app_type`, `__setusermatherr`, `_access`, `_aligned_free`, `_aligned_malloc`, `_amsg_exit`, `_assert`, `_beginthreadex`, `_cexit`, `_chdir`, `_chmod`, `_close`, `_endthreadex`, `_errno`, `_exit`, `_fdopen`, `_filelengthi64`, `_fileno`, `_findclose`, `_findfirst`, `_findnext`, `_fstat`, `_fstat64`, `_fstati64`, `_fullpath`, `_get_osfhandle`, `_getcwd`, `_getpid`, `_initterm`, `_iob`, `_lock`, `_lseek`, `_lseeki64`, `_mkdir`, `_mktemp`, `_onexit`, `_open`, `_open_osfhandle`, `_pclose`, `_popen`, `_putenv`, `_read`, `_rmdir`, `_setjmp3`, `_setmode`, `_spawnlp`, `_stat`, `_stati64`, `_strdup`, `_stricmp`, `_strnicmp`, `_sys_errlist`, `_sys_nerr`, `_telli64`, `_ultoa`, `_umask`, `_unlink`, `_unlock`, `_vscprintf`, `_vsnprintf`, `_vsnwprintf`, `_wchdir`, `_wchmod`, `_wfindfirst`, `_wfindnext`, `_wfopen`, `_wfullpath`, `_wgetcwd`, `_wmkdir`, `_wopen`, `_write`, `_wstat64`, `_wutime`, `abort`, `atoi`, `atol`, `calloc`, `clearerr`, `clock`, `difftime`, `exit`, `fclose`, `feof`, `ferror`, `fflush`, `fgetc`, `fgetpos`, `fgets`, `fgetws`, `fopen`, `fprintf`, `fputc`, `fputs`, `fputwc`, `fread`, `free`, `fseek`, `fsetpos`, `ftell`, `fwprintf`, `fwrite`, `getc`, `getenv`, `getwc`, `gmtime`, `isalnum`, `isalpha`, `iscntrl`, `isgraph`, `islower`, `isprint`, `ispunct`, `isspace`, `isupper`, `iswctype`, `isxdigit`, `localeconv`, `localtime`, `longjmp`, `malloc`, `mbstowcs`, `memchr`, `memcmp`, `memcpy`, `memmove`, `memset`, `mktime`, `perror`, `printf`, `putc`, `putwc`, `qsort`, `raise`, `realloc`, `remove`, `rename`, `setbuf`, `setlocale`, `setvbuf`, `signal`, `sprintf`, `srand`, `strcat`, `strchr`, `strcmp`, `strcoll`, `strcpy`, `strcspn`, `strerror`, `strftime`, `strlen`, `strncat`, `strncmp`, `strncpy`, `strpbrk`, `strrchr`, `strspn`, `strstr`, `strtok`, `strtol`, `strtoul`, `strxfrm`, `system`, `time`, `tolower`, `toupper`, `towlower`, `towupper`, `ungetc`, `ungetwc`, `vfprintf`, `wcscat`, `wcscmp`, `wcscoll`, `wcscpy`, `wcsftime`, `wcslen`, `wcsncmp`, `wcsncpy`, `wcsrchr`, `wcsstr`, `wcstombs`, `wcsxfrm`

### `kernel32.dll` (188)

`AddVectoredExceptionHandler`, `AreFileApisANSI`, `BackupRead`, `BackupSeek`, `CloseHandle`, `ConvertFiberToThread`, `ConvertThreadToFiber`, `CreateEventA`, `CreateFiber`, `CreateFileA`, `CreateFileMappingA`, `CreateFileMappingW`, `CreateFileW`, `CreateHardLinkW`, `CreateMutexA`, `CreateMutexW`, `CreatePipe`, `CreateProcessA`, `CreateProcessW`, `CreateSemaphoreA`, `CreateThread`, `CreateToolhelp32Snapshot`, `DeleteCriticalSection`, `DeleteFiber`, `DeleteFileA`, `DeleteFileW`, `DuplicateHandle`, `EnterCriticalSection`, `ExpandEnvironmentStringsA`, `ExpandEnvironmentStringsW`, `FileTimeToSystemTime`, `FindClose`, `FindFirstFileW`, `FindFirstVolumeW`, `FindNextFileW`, `FindNextVolumeW`, `FindVolumeClose`, `FlushFileBuffers`, `FlushViewOfFile`, `FormatMessageA`, `FormatMessageW`, `FreeLibrary`, `GetACP`, `GetConsoleMode`, `GetCurrentDirectoryA`, `GetCurrentProcess`, `GetCurrentProcessId`, `GetCurrentThread`, `GetCurrentThreadId`, `GetDiskFreeSpaceA`, `GetDiskFreeSpaceExW`, `GetDiskFreeSpaceW`, `GetEnvironmentVariableA`, `GetEnvironmentVariableW`, `GetExitCodeProcess`, `GetExitCodeThread`, `GetFileAttributesA`, `GetFileAttributesExW`, `GetFileAttributesW`, `GetFileInformationByHandle`, `GetFileSize`, `GetFileSizeEx`, `GetFileTime`, `GetFileType`, `GetFullPathNameA`, `GetFullPathNameW`, `GetHandleInformation`, `GetLastError`, `GetLogicalDriveStringsA`, `GetModuleFileNameA`, `GetModuleHandleA`, `GetModuleHandleExW`, `GetModuleHandleW`, `GetNativeSystemInfo`, `GetProcAddress`, `GetProcessAffinityMask`, `GetProcessHeap`, `GetProcessTimes`, `GetShortPathNameW`, `GetStartupInfoA`, `GetStdHandle`, `GetSystemDirectoryA`, `GetSystemInfo`, `GetSystemTime`, `GetSystemTimeAdjustment`, `GetSystemTimeAsFileTime`, `GetTempPathA`, `GetTempPathW`, `GetThreadContext`, `GetThreadPriority`, `GetThreadTimes`, `GetTickCount`, `GetTimeZoneInformation`, `GetVersion`, `GetVersionExA`, `GetVersionExW`, `GetVolumeInformationW`, `GetVolumePathNamesForVolumeNameW`, `GlobalAlloc`, `GlobalFree`, `GlobalMemoryStatusEx`, `HeapAlloc`, `HeapCompact`, `HeapCreate`, `HeapDestroy`, `HeapFree`, `HeapReAlloc`, `HeapSize`, `HeapValidate`, `InitializeCriticalSection`, `InitializeCriticalSectionAndSpinCount`, `IsDBCSLeadByteEx`, `IsDebuggerPresent`, `LeaveCriticalSection`, `LoadLibraryA`, `LoadLibraryExA`, `LoadLibraryW`, `LocalAlloc`, `LocalFree`, `LockFile`, `LockFileEx`, `MapViewOfFile`, `Module32First`, `MoveFileExA`, `MoveFileExW`, `MultiByteToWideChar`, `OpenProcess`, `OutputDebugStringA`, `OutputDebugStringW`, `PeekNamedPipe`, `Process32First`, `Process32Next`, `ProcessIdToSessionId`, `QueryDosDeviceA`, `QueryDosDeviceW`, `QueryPerformanceCounter`, `QueryPerformanceFrequency`, `RaiseException`, `ReadConsoleA`, `ReadConsoleW`, `ReadDirectoryChangesW`, `ReadFile`, `ReleaseMutex`, `ReleaseSemaphore`, `RemoveDirectoryW`, `RemoveVectoredExceptionHandler`, `ReplaceFileW`, `ResetEvent`, `ResumeThread`, `SetConsoleMode`, `SetEndOfFile`, `SetEvent`, `SetFilePointer`, `SetHandleInformation`, `SetLastError`, `SetProcessAffinityMask`, `SetSystemTime`, `SetThreadContext`, `SetThreadPriority`, `SetUnhandledExceptionFilter`, `Sleep`, `SleepEx`, `SuspendThread`, `SwitchToFiber`, `SystemTimeToFileTime`, `TerminateProcess`, `TerminateThread`, `TlsAlloc`, `TlsFree`, `TlsGetValue`, `TlsSetValue`, `TryEnterCriticalSection`, `UnlockFile`, `UnlockFileEx`, `UnmapViewOfFile`, `VerSetConditionMask`, `VerifyVersionInfoW`, `VirtualAlloc`, `VirtualFree`, `VirtualLock`, `VirtualProtect`, `VirtualQuery`, `WaitForMultipleObjects`, `WaitForSingleObject`, `WaitForSingleObjectEx`, `WideCharToMultiByte`, `WriteFile`, `lstrcmpiA`

### `advapi32.dll` (101)

`AddAce`, `AdjustTokenPrivileges`, `AllocateAndInitializeSid`, `AuditEnumerateSubCategories`, `AuditLookupCategoryGuidFromCategoryId`, `AuditQuerySystemPolicy`, `ChangeServiceConfig2A`, `CloseEventLog`, `CloseServiceHandle`, `ControlService`, `ConvertSidToStringSidA`, `ConvertSidToStringSidW`, `ConvertStringSidToSidA`, `CopySid`, `CreateServiceA`, `CryptAcquireContextA`, `CryptAcquireContextW`, `CryptCreateHash`, `CryptDecrypt`, `CryptDestroyHash`, `CryptDestroyKey`, `CryptEncrypt`, `CryptEnumProvidersW`, `CryptExportKey`, `CryptGenRandom`, `CryptGetHashParam`, `CryptGetProvParam`, `CryptGetUserKey`, `CryptHashData`, `CryptImportKey`, `CryptReleaseContext`, `CryptSetHashParam`, `CryptSignHashW`, `DeleteAce`, `DeleteService`, `DeregisterEventSource`, `EnumServicesStatusExW`, `EqualSid`, `FreeSid`, `GetAce`, `GetAclInformation`, `GetFileSecurityW`, `GetLengthSid`, `GetNamedSecurityInfoW`, `GetNumberOfEventLogRecords`, `GetOldestEventLogRecord`, `GetSecurityDescriptorDacl`, `GetSecurityInfo`, `GetSidSubAuthority`, `GetSidSubAuthorityCount`, `ImpersonateSelf`, `InitializeAcl`, `InitializeSecurityDescriptor`, `IsValidSid`, `LookupAccountNameA`, `LookupAccountNameW`, `LookupAccountSidA`, `LookupAccountSidW`, `LookupPrivilegeValueA`, `LsaClose`, `LsaFreeMemory`, `LsaNtStatusToWinError`, `LsaOpenPolicy`, `LsaQueryInformationPolicy`, `OpenEventLogA`, `OpenProcessToken`, `OpenSCManagerA`, `OpenSCManagerW`, `OpenServiceA`, `OpenServiceW`, `OpenThreadToken`, `QueryServiceConfig2W`, `QueryServiceConfigW`, `QueryServiceStatus`, `ReadEventLogA`, `RegCloseKey`, `RegEnumKeyExA`, `RegEnumKeyExW`, `RegEnumKeyW`, `RegEnumValueA`, `RegEnumValueW`, `RegGetKeySecurity`, `RegOpenKeyExA`, `RegOpenKeyExW`, `RegQueryInfoKeyA`, `RegQueryInfoKeyW`, `RegQueryValueExA`, `RegQueryValueExW`, `RegisterEventSourceA`, `RegisterEventSourceW`, `RegisterServiceCtrlHandlerA`, `ReportEventA`, `ReportEventW`, `SetEntriesInAclA`, `SetNamedSecurityInfoW`, `SetSecurityDescriptorDacl`, `SetSecurityDescriptorGroup`, `SetSecurityDescriptorOwner`, `SetServiceStatus`, `StartServiceA`, `StartServiceCtrlDispatcherA`

### `wsock32.dll` (30)

`WSACleanup`, `WSAGetLastError`, `WSASetLastError`, `WSAStartup`, `__WSAFDIsSet`, `accept`, `bind`, `closesocket`, `connect`, `gethostbyname`, `gethostname`, `getpeername`, `getsockname`, `getsockopt`, `htonl`, `htons`, `inet_addr`, `inet_ntoa`, `ioctlsocket`, `listen`, `ntohl`, `ntohs`, `recv`, `recvfrom`, `select`, `send`, `sendto`, `setsockopt`, `shutdown`, `socket`

### `crypt32.dll` (20)

`CertAddCertificateContextToStore`, `CertCloseStore`, `CertCreateCertificateChainEngine`, `CertDuplicateCertificateContext`, `CertEnumCertificatesInStore`, `CertFindCertificateInStore`, `CertFindExtension`, `CertFreeCertificateChain`, `CertFreeCertificateChainEngine`, `CertFreeCertificateContext`, `CertGetCertificateChain`, `CertGetCertificateContextProperty`, `CertGetNameStringA`, `CertOpenStore`, `CertOpenSystemStoreA`, `CertOpenSystemStoreW`, `CryptDecodeObjectEx`, `CryptQueryObject`, `CryptStringToBinaryA`, `PFXImportCertStore`

### `user32.dll` (19)

`AppendMenuA`, `CreateMenu`, `CreatePopupMenu`, `CreateWindowExA`, `DialogBoxParamA`, `EndDialog`, `GetDlgItem`, `GetDlgItemTextA`, `GetProcessWindowStation`, `GetSystemMetrics`, `GetUserObjectInformationW`, `GetWindowTextLengthA`, `LoadIconA`, `MessageBoxA`, `MessageBoxW`, `PostMessageA`, `SendMessageA`, `SetDlgItemTextA`, `SetMenu`

### `ws2_32.dll` (18)

`WSAAddressToStringA`, `WSACloseEvent`, `WSACreateEvent`, `WSAEnumNetworkEvents`, `WSAEventSelect`, `WSAIoctl`, `WSAResetEvent`, `WSASetEvent`, `WSASocketA`, `WSAWaitForMultipleEvents`, `freeaddrinfo`, `getaddrinfo`, `gethostbyaddr`, `getservbyname`, `getservbyport`, `inet_addr`, `inet_ntoa`, `ntohs`

### `wevtapi.dll` (8)

`EvtClose`, `EvtCreateBookmark`, `EvtCreateRenderContext`, `EvtFormatMessage`, `EvtOpenPublisherMetadata`, `EvtRender`, `EvtSubscribe`, `EvtUpdateBookmark`

### `wintrust.dll` (6)

`CryptCATAdminAcquireContext`, `CryptCATAdminCalcHashFromFileHandle`, `CryptCATAdminEnumCatalogFromHash`, `CryptCATAdminReleaseCatalogContext`, `CryptCATAdminReleaseContext`, `WinVerifyTrust`

### `iphlpapi.dll` (5)

`GetAdaptersAddresses`, `GetAdaptersInfo`, `GetExtendedTcpTable`, `GetExtendedUdpTable`, `GetIfEntry`

### `netapi32.dll` (5)

`NetApiBufferFree`, `NetLocalGroupEnum`, `NetUserEnum`, `NetUserGetInfo`, `NetUserGetLocalGroups`

### `oleaut32.dll` (5)

`SysAllocString`, `SysAllocStringLen`, `SysFreeString`, `SysStringLen`, `VariantClear`

### `shlwapi.dll` (5)

`PathFileExistsA`, `PathFindFileNameA`, `PathIsUNCA`, `PathMatchSpecA`, `PathRemoveFileSpecA`

### `ole32.dll` (4)

`CoCreateInstance`, `CoInitializeEx`, `CoSetProxyBlanket`, `CoUninitialize`

### `psapi.dll` (4)

`EnumProcessModules`, `GetModuleFileNameExW`, `GetProcessImageFileNameA`, `GetProcessMemoryInfo`

### `version.dll` (3)

`GetFileVersionInfoSizeW`, `GetFileVersionInfoW`, `VerQueryValueW`

### `wtsapi32.dll` (3)

`WTSEnumerateSessionsW`, `WTSFreeMemory`, `WTSQuerySessionInformationW`

### `comctl32.dll` (1)

`InitCommonControls`

### `mpr.dll` (1)

`WNetGetConnectionA`

## Dynamic loading

These binaries resolve APIs at run time. The names below come from string heuristics and are candidates only. The runtime gap log confirms real lookups.

### `Program Files/ossec-agent/active-response/bin/netsh.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `libwazuhshared.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `winnsi.dll (system)`, `ws2_32.dll (system)`, `ws2help.dll (system)`, `wsock32.dll (system)`
- Function-like strings: 28; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`CompanyName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `DomainProfile`, `EnableFirewall`, `FileDescription`, `FileSizeWin`, `FileVersion`, `FirewallPolicy`, `GetNativeSystemInfo`, `GetProductInfo`, `H8L8P8T8X8`, `LdrRegisterDllNotification`, `LegalCopyright`, `MergeAppendFile`, `ProductName`, `ProductType`, `ProductVersion`, `PublicProfile`, `StandardProfile`, `StringFileInfo`, `TestUnmergeFiles`, `UnmergeFiles`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/active-response/bin/restart-wazuh.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `libwazuhshared.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `winnsi.dll (system)`, `ws2_32.dll (system)`, `ws2help.dll (system)`, `wsock32.dll (system)`
- Function-like strings: 22; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`CompanyName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `FileDescription`, `FileSizeWin`, `FileVersion`, `GetNativeSystemInfo`, `GetProductInfo`, `LdrRegisterDllNotification`, `LegalCopyright`, `MergeAppendFile`, `ProductName`, `ProductType`, `ProductVersion`, `StringFileInfo`, `TestUnmergeFiles`, `UnmergeFiles`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/active-response/bin/route-null.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `libwazuhshared.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `winnsi.dll (system)`, `ws2_32.dll (system)`, `ws2help.dll (system)`, `wsock32.dll (system)`
- Function-like strings: 22; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`CompanyName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `FileDescription`, `FileSizeWin`, `FileVersion`, `GetNativeSystemInfo`, `GetProductInfo`, `LdrRegisterDllNotification`, `LegalCopyright`, `MergeAppendFile`, `ProductName`, `ProductType`, `ProductVersion`, `StringFileInfo`, `TestUnmergeFiles`, `UnmergeFiles`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/agent-auth.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `webio.dll (system)`, `winhttp.dll (system)`, `winnlsres.dll (system)`, `winnsi.dll (system)`, `ws2help.dll (system)`
- Function-like strings: 32; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`CompanyName`, `ComputerName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `FileDescription`, `FileSizeWin`, `FileVersion`, `GetNativeSystemInfo`, `GetProductInfo`, `InstallService`, `LdrRegisterDllNotification`, `LegalCopyright`, `MergeAppendFile`, `OssecServiceCtrlHandler`, `OssecServiceStart`, `ProductName`, `ProductType`, `ProductVersion`, `Q0Y0h0`, `ReleaseId`, `ReloadCounter`, `StoreCounter`, `StringFileInfo`, `TestUnmergeFiles`, `UninstallService`, `UnmergeFiles`, `VarFileInfo`, `WazuhSvc`

</details>

### `Program Files/ossec-agent/dbsync.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `libwazuhext.dll (bundled)`
- Function-like strings: 8; of these, imported elsewhere in the package: none

<details><summary>Function-like strings</summary>

`CompanyName`, `FileDescription`, `FileVersion`, `LegalCopyright`, `ProductName`, `ProductVersion`, `StringFileInfo`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/libfimdb.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `libwazuhext.dll (bundled)`
- Function-like strings: 10; of these, imported elsewhere in the package: none

<details><summary>Function-like strings</summary>

`Bf10RemoteSync`, `CompanyName`, `FileDescription`, `FileVersion`, `LegalCopyright`, `M0V0d0k0r0y0`, `ProductName`, `ProductVersion`, `StringFileInfo`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/libgcc_s_dw2-1.dll`

- Loaders imported: `GetModuleHandleA`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: none
- Function-like strings: 0; of these, imported elsewhere in the package: none

### `Program Files/ossec-agent/libstdc++-6.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleExW`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`, `LoadLibraryW`
- DLL names in strings but not linked: `advapi32.dll (system)`
- Function-like strings: 5; of these, imported elsewhere in the package: none

<details><summary>Function-like strings</summary>

`B0S0u0`, `I0X0u0`, `I0X0x0`, `I4U4a4`, `SystemFunction036`

</details>

### `Program Files/ossec-agent/libwazuhext.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleExW`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`, `LoadLibraryW`
- DLL names in strings but not linked: `iphlpapi.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `secur32.dll (system)`, `security.dll (system)`
- Function-like strings: 283; of these, imported elsewhere in the package: `CreateToolhelp32Snapshot`, `GetNativeSystemInfo`, `LoadLibraryExA`, `Module32First`

<details><summary>Function-like strings</summary>

`A0Q0z0`, `AcquireCredentialsHandle`, `AddDllDirectory`, `AddImm`, `AggFinal`, `AggInverse`, `AggStep`, `AggStep1`, `AggValue`, `AntiReplay`, `ApplicationData`, `AunpAun`, `AutoCommit`, `B2f9C2u`, `BeginSubrtn`, `BitAnd`, `BitNot`, `Bn0bLn`, `CancelIo`, `CertBlob`, `CertificateList`, `CertificateRequest`, `CertificateStatus`, `CertificateUrl`, `CertificateVerify`, `ChaCha20`, `CharLowerW`, `CharUpperW`, `CipherString`, `ClientHello`, `ClientKeyExchange`, `ClientRenegotiation`, `ClientSignatureAlgorithms`, `ClrSubtype`, `Cnp2Cn`, `CollSeq`, `ColumnsUsed`, `CompanyName`, `CompressedCertificate`, `CreateBtree`, `CreateEvent`, `CreateEventExW`, `CreateFile2`, `CreateFileMappingFromApp`, `CreateToolhelp32Snapshot`, `CurrentService`, `CurrentUser`, `CurrentUserGroupPolicy`, `CursorHint`, `CursorLock`, `CursorUnlock`, `D0L0T0`, `D0Y0a0`, `D2S2c2`, `DecrJumpZero`, `DecryptMessage`, `DeferredSeek`, `DirName`, `DropIndex`, `DropTable`, `DropTrigger`, `E0L0Q0m0t0y0`, `EdiPartyName`, `ElseEq`, `EmptyFragments`, `EncryptMessage`, `EncryptThenMac`, `EncryptedExtensions`, `EncryptedPreMasterSecret`, `EncryptedPrivateKeyInfo`, `EndCoroutine`, `EndOfEarlyData`, `ErnissuerDomainPolicy`, `ExtendedMasterSecret`, `FileDescription`, `FileTimeToLocalFileTime`, `FileVersion`, `FilterAdd`, `FinishSeek`, `FkCheck`, `FkCounter`, `FkIfZero`, `GeneralNames`, `GeneralString`, `GetFileInformationByHandleEx`, `GetNativeSystemInfo`, `GetProcAddressA`, `GetSubtype`, `GetTickCount64`, `GostKeyTransportBlob`, `HaltIfNull`, `HelloVerifyRequest`, `HnInitial`, `Hun8Hun`, `HunpHun`, `IdxDelete`, `IdxInsert`, `IdxRowid`, `IfNoHope`, `IfNotOpen`, `IfNotZero`, `IfNullRow`, `IfSizeBetween`, `IncrVacuum`, `InitCoroutine`, `InitSecurityInterfaceA`, `InitializeSecurityContext`, `IntCopy`, `IntegrityCk`, `InterlockedCompareExchange`, `IsNull`, `IsTrue`, `IsType`, `IssuerBlob`, `Jan8Janpadding`, `JournalMode`, `KeyUpdate`, `Kn0tKnp`, `Kn0uKn`, `L0X1y1`, `LegalCopyright`, `LmndLmn`, `LoadAnalysis`, `LoadLibraryExA`, `LoadPackagedLibrary`, `LocalKeySet`, `LocalMachine`, `LocalMachineEnterprise`, `LocalMachineGroupPolicy`, `MakeRecord`, `MapViewOfFileFromApp`, `MaxPgcnt`, `MaxProtocol`, `MemMax`, `MessageHash`, `MiddleboxCompat`, `MinProtocol`, `MinghuaQu`, `MinghuaQuw`, `Module32First`, `Module32Next`, `MtnhMtn`, `MustBeInt`, `NewRowid`, `NewSessionTicket`, `NextProto`, `NoConflict`, `NoRenegotiation`, `NoResumptionOnRenegotiation`, `NotExists`, `NotFound`, `NotNull`, `NtnhMtnhMtnhMtn`, `NullRow`, `NumTickets`, `O1A2P2`, `OffsetLimit`, `OnalgId`, `OnauthEncryptedContentInfo`, `OnauthInfo`, `OncertId`, `OncompressionAlgorithm`, `OncontentEncryptionAlgorithm`, `OndigestedObjectType`, `OnencryptedContentInfo`, `OnfieldType`, `OnkeyDerivationAlgorithm`, `OnkeyIdentifier`, `OnnameAssigner`, `OnnamingAuthorityId`, `OnnewSigCert`, `OnprivateKey`, `OnreceiptsFrom`, `OnresponseStatus`, `OnrevocationTime`, `OnstartDayTime`, `OnstartTime`, `OnstatusString`, `OntbsRequest`, `OntbsResponseData`, `OpenAutoindex`, `OpenDup`, `OpenEphemeral`, `OpenPseudo`, `OpenRead`, `OpenWrite`, `OtnhMtn`, `ParseSchema`, `PrioritizeChaCha`, `PrivateKey`, `PrivateKeyInfo`, `ProductName`, `ProductVersion`, `PureFunc`, `QueryContextAttributes`, `QueryCredentialAttributes`, `ReadCookie`, `RealAffinity`, `RecordPadding`, `ReleaseReg`, `ReopenIdx`, `RequestPostHandshake`, `RequirePostHandshake`, `ResetCount`, `ResetSorter`, `ResultRow`, `RowCell`, `RowData`, `RowSetAdd`, `RowSetRead`, `RowSetTest`, `RtlVerifyVersionInfo`, `RxCertificateCompression`, `SecP256r1Kyber768Draft00`, `SeekEnd`, `SeekHit`, `SeekRowid`, `SeekScan`, `SequenceTest`, `ServerHello`, `ServerHelloDone`, `ServerInfoFile`, `ServerKeyExchange`, `ServerPreference`, `SessionTicket`, `SetCookie`, `SetFilePointerEx`, `SetSubtype`, `ShiftLeft`, `ShiftRight`, `SignatureAlgorithms`, `SipHash`, `SoftNull`, `SorterCompare`, `SorterData`, `SorterInsert`, `SorterNext`, `SorterOpen`, `SorterSort`, `SqlExec`, `StrictCertCheck`, `StringFileInfo`, `SubjectPublicKeyInfo`, `SupplementalData`, `SvnpSvn`, `TableLock`, `TargetingInformation`, `TndigestAlgorithms`, `TnintendedAlg`, `TnkeyAttrId`, `TnoriginatorInfo`, `TnotherCertFormat`, `TnotherRevInfoFormat`, `TnsubjectKeyIdentifier`, `TxCertificateCompression`, `TypeCheck`, `U0J1l1`, `UnixSockets`, `UnsafeLegacyRenegotiation`, `UnsafeLegacyServerConnect`, `UuidCreate`, `UuidCreateSequential`, `ValueList`, `VarFileInfo`, `VerifyMode`, `VersionNeg`, `VnPhVn`, `VncertReq`, `VncertReqId`, `VnnewWithNew`, `VnpoposkInput`, `VnpubMethod`, `WnpwWn`, `X25519Kyber768Draft00`, `X400Name`, `X500UniqueIdentifier`, `XmppAddr`, `Y1z1F2`, `Yn0hYn`, `YnPiYn`, `Z09Y0r`, `ZeroOrNull`, `ZwKiZwKi`

</details>

### `Program Files/ossec-agent/libwazuhshared.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `smsvcrt.dll (system)`
- Function-like strings: 19; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`BoInfinity`, `CoMicr`, `CompanyName`, `ComputerName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `FileDescription`, `FileVersion`, `GetNativeSystemInfo`, `GetProductInfo`, `LegalCopyright`, `ProductName`, `ProductType`, `ProductVersion`, `ReleaseId`, `StringFileInfo`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/manage_agents.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `dpapi.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `winnsi.dll (system)`, `ws2help.dll (system)`
- Function-like strings: 32; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`CompanyName`, `ComputerName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `FileDescription`, `FileSizeWin`, `FileVersion`, `G5S5b5`, `GetNativeSystemInfo`, `GetProductInfo`, `InstallService`, `LdrRegisterDllNotification`, `LegalCopyright`, `MergeAppendFile`, `OssecServiceCtrlHandler`, `OssecServiceStart`, `ProductName`, `ProductType`, `ProductVersion`, `ReleaseId`, `ReloadCounter`, `StoreCounter`, `StringFileInfo`, `TestUnmergeFiles`, `UninstallService`, `UnmergeFiles`, `VarFileInfo`, `WazuhSvc`

</details>

### `Program Files/ossec-agent/rsync.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `libwazuhext.dll (bundled)`
- Function-like strings: 9; of these, imported elsewhere in the package: none

<details><summary>Function-like strings</summary>

`CompanyName`, `FileDescription`, `FileVersion`, `LegalCopyright`, `ProductName`, `ProductVersion`, `StringFileInfo`, `VarFileInfo`, `X0F5x5`

</details>

### `Program Files/ossec-agent/syscollector.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `libwazuhext.dll (bundled)`
- Function-like strings: 9; of these, imported elsewhere in the package: none

<details><summary>Function-like strings</summary>

`B0I0m4`, `CompanyName`, `FileDescription`, `FileVersion`, `LegalCopyright`, `ProductName`, `ProductVersion`, `StringFileInfo`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/sysinfo.dll`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `libwazuhext.dll (bundled)`
- Function-like strings: 33; of these, imported elsewhere in the package: none

<details><summary>Function-like strings</summary>

`B0L0V0y0`, `CompanyName`, `ConvertLengthToIpv4Mask`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `DisplayName`, `DisplayVersion`, `FileDescription`, `FileVersion`, `GetIfEntry2`, `GetSystemFirmwareTable`, `InProcHandler`, `InProcHandler32`, `InProcHandler64`, `InProcServer`, `InProcServer32`, `InProcServer64`, `InstallDate`, `InstallLocation`, `InstallPath`, `InstallProperties`, `LegalCopyright`, `LocalServer`, `LocalServer32`, `LocalServer64`, `O0U0o0`, `ProductName`, `ProductVersion`, `ProfileImagePath`, `RollupFix`, `ServiceDll`, `StringFileInfo`, `VarFileInfo`

</details>

### `Program Files/ossec-agent/wazuh-agent.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`, `LoadLibraryExA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libfimdb.dll (bundled)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `winnsi.dll (system)`, `ws2help.dll (system)`
- Function-like strings: 57; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`ClientBuffer`, `ClientConf`, `CompanyName`, `ComputerName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `EventChannel`, `EventMessageFile`, `ExecdConfig`, `ExecdRun`, `ExecdShutdown`, `ExecdTimeoutRun`, `FileDescription`, `FileSizeWin`, `FileVersion`, `FreeTimeoutList`, `GetAlertData`, `GetCommandbyName`, `GetNativeSystemInfo`, `GetProductInfo`, `I0U0d0`, `InstallService`, `LdrRegisterDllNotification`, `LegalCopyright`, `LogCollectorConfig`, `LogCollectorStart`, `M0U0m0`, `MergeAppendFile`, `OssecServiceCtrlHandler`, `OssecServiceStart`, `PrintErrorAcordingToModules`, `ProductName`, `ProductType`, `ProductVersion`, `ReadActiveCommands`, `ReadActiveResponses`, `ReadConfig`, `ReadExecConfig`, `ReleaseId`, `ReloadCounter`, `SeDebugPrivilege`, `SeSecurityPrivilege`, `StoreCounter`, `StringFileInfo`, `TestUnmergeFiles`, `UninstallService`, `UnmergeFiles`, `VarFileInfo`, `WazuhSvc`, `WinEvtLog`, `WinExecdStart`, `Wow64DisableWow64FsRedirection`, `WriteMemoryCallback`

</details>

### `Program Files/ossec-agent/win32ui.exe`

- Loaders imported: `GetModuleHandleA`, `GetModuleHandleW`, `GetProcAddress`, `LoadLibraryA`
- DLL names in strings but not linked: `bcrypt.dll (system)`, `bcryptprimitives.dll (system)`, `cryptbase.dll (system)`, `cryptnet.dll (system)`, `cryptsp.dll (system)`, `idle.dll (system)`, `iphlpapi.dll (system)`, `kernek32.dll (system)`, `libgcc_s_dw2-1.dll (bundled)`, `libwazuhext.dll (bundled)`, `msasn1.dll (system)`, `ncrypt.dll (system)`, `ntdll.dll (system)`, `ntmarta.dll (system)`, `ntsasn1.dll (system)`, `profapi.dll (system)`, `rsaenh.dll (system)`, `samlib.dll (system)`, `smsvcrt.dll (system)`, `sspicli.dll (system)`, `swdrm.dll (system)`, `system.dll (system)`, `textshaping.dll (system)`, `userenv.dll (system)`, `uxtheme.dll (system)`, `webio.dll (system)`, `winhttp.dll (system)`, `winnsi.dll (system)`, `ws2help.dll (system)`
- Function-like strings: 29; of these, imported elsewhere in the package: `GetNativeSystemInfo`

<details><summary>Function-like strings</summary>

`CompanyName`, `ComputerName`, `CurrentBuildNumber`, `CurrentMajorVersionNumber`, `CurrentMinorVersionNumber`, `CurrentVersion`, `DeleteState`, `DirSize`, `FileDescription`, `FileSizeWin`, `FileVersion`, `GetNativeSystemInfo`, `GetProductInfo`, `InstallService`, `LdrRegisterDllNotification`, `LegalCopyright`, `MergeAppendFile`, `OssecServiceCtrlHandler`, `OssecServiceStart`, `ProductName`, `ProductType`, `ProductVersion`, `ReleaseId`, `StringFileInfo`, `TestUnmergeFiles`, `UninstallService`, `UnmergeFiles`, `VarFileInfo`, `WazuhSvc`

</details>
