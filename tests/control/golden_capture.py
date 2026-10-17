"""Build a small capture folder shaped like capture.ps1 output (Windows PowerShell 5.1)."""

import hashlib
import json

from xvm_golden import baseline

CV = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
UNINSTALL = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
UNINSTALL_WOW = (
    r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
)


def _reg(*blocks: str) -> bytes:
    text = "Windows Registry Editor Version 5.00\r\n\r\n" + "\r\n".join(blocks) + "\r\n"
    return b"\xff\xfe" + text.encode("utf-16-le")


def _json(obj) -> bytes:
    return b"\xef\xbb\xbf" + json.dumps(obj).encode()


BOOT_MS = 1792137600000  # 2026-10-16T08:00:00Z


def _proc(pid, ppid, name, after_s=None, **extra):
    p = {
        "ProcessId": pid,
        "ParentProcessId": ppid,
        "Name": name,
        "ExecutablePath": None,
        "CommandLine": None,
        "SessionId": 0,
        "Owner": None,
        "CreationDate": None if after_s is None else f"/Date({BOOT_MS + int(after_s * 1000)})/",
    }
    p.update(extra)
    return p


def _processes() -> list[dict]:
    return [
        _proc(0, 0, "System Idle Process"),
        _proc(4, 0, "System", 0, Owner="NT AUTHORITY\\SYSTEM"),
        _proc(300, 4, "smss.exe", 1, ExecutablePath="C:\\Windows\\System32\\smss.exe"),
        _proc(
            500,
            300,
            "svchost.exe",
            5,
            CommandLine="svchost.exe -k DcomLaunch",
            Owner="NT AUTHORITY\\SYSTEM",
        ),
        _proc(520, 300, "svchost.exe", 6.25),
        _proc(700, 300, "wazuh-agent.exe", 60),
        _proc(710, 700, "cmd.exe", 61),
        _proc(950, 999, "explorer.exe", 120, SessionId=1, Owner="GOLDEN-VM\\Administrator"),
        _proc(900, 950, "powershell.exe", 3000, SessionId=1),
        _proc(905, 900, "conhost.exe", 3000.5, SessionId=1),
    ]


def _files() -> list[dict]:
    return [
        {
            "path": "C:\\Windows",
            "dir": True,
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-10-16T08:00:00Z",
            "accessed": "2026-10-16T09:00:00Z",
            "attributes": "Directory",
        },
        {
            "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "dir": False,
            "size": 824,
            "sha256": "ab" * 32,
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "accessed": "2026-10-16T09:00:00Z",
            "attributes": "Archive",
        },
        {
            "path": "C:\\Windows\\regedit.exe",
            "dir": False,
            "size": 1000,
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
            "accessed": "2026-01-01T00:00:00Z",
            "attributes": "ReadOnly, System, Archive",
        },
        {"path": "\\\\?\\C:\\long\\path.txt", "dir": False, "size": 1},
    ]


def _rendered(*logons) -> bytes:
    """wevtutil qe /f:RenderedXml /e:Events output, as PowerShell writes it (UTF-8 with BOM)."""
    ns = "http://schemas.microsoft.com/win/2004/08/events/event"
    events = []
    for user, logon_type in logons:
        msg = (
            f"An account was successfully logged on.\r\n\tAccount Name:\t\t{user}\r\n"
            f"\tLogon Type:\t\t{logon_type}"
        )
        events.append(
            f"<Event xmlns='{ns}'><System><Provider Name='Microsoft-Windows-Security-Auditing'/>"
            f"<EventID>4624</EventID><Version>2</Version></System><EventData>"
            f"<Data Name='TargetUserName'>{user}</Data><Data Name='LogonType'>{logon_type}</Data>"
            f"</EventData><RenderingInfo Culture='en-US'><Message>{msg}</Message>"
            f"</RenderingInfo></Event>"
        )
    return ("\ufeff<Events>" + "".join(events) + "</Events>").encode("utf-8")


def files() -> dict[str, bytes]:
    expand = "%SystemRoot%\\x".encode("utf-16-le") + b"\0\0"
    multi = "a".encode("utf-16-le") + b"\0\0" + "b".encode("utf-16-le") + b"\0\0\0\0"
    return {
        "registry/os-currentversion.reg": _reg(
            f"[{CV}]",
            '"ProductName"="Windows Server 2022 Standard Evaluation"',
            '"EditionID"="ServerStandardEval"',
            '"CurrentBuildNumber"="20348"',
            '"DisplayVersion"="21H2"',
            '"UBR"=dword:00000a2b',
            '"SystemRoot"="C:\\\\Windows"',
            '"Quote \\"x\\""="y"',
            '"PathName"=hex(2):' + ",".join(f"{b:02x}" for b in expand[:10]) + ",\\",
            "  " + ",".join(f"{b:02x}" for b in expand[10:]),
            '"Multi"=hex(7):' + ",".join(f"{b:02x}" for b in multi),
            '"Q"=hex(b):01,00,00,00,00,00,00,00',
            '"Blob"=hex:de,ad,be,ef',
            '"Odd"=hex(0):',
            '@="default"',
            "",
            f"[{CV}\\Empty]",
        ),
        "registry/computername.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName]",
            '"ComputerName"="GOLDEN-VM"',
            '"Other"="kept"',
        ),
        "registry/tcpip-parameters.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters]",
            '"Hostname"="GOLDEN-VM"',
            '"NV Hostname"="GOLDEN-VM"',
            '"SearchList"=""',
            "",
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{1}]",
            '"DhcpIPAddress"="198.51.100.7"',
        ),
        "registry/profilelist.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList]",
            '"ProfilesDirectory"=hex(2):43,00,3a,00,00,00',
        ),
        "registry/timezone.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation]",
            '"TimeZoneKeyName"="UTC"',
        ),
        "registry/os-currentversion-wow64.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion]",
            '"ProductName"="Windows Server 2022 Standard Evaluation"',
            '"CurrentBuildNumber"="20348"',
        ),
        "registry/codepage.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Nls\CodePage]",
            '"ACP"="1252"',
            '"OEMCP"="437"',
        ),
        "registry/eventlog-security.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Security]",
            '"MaxSize"=dword:01400000',
        ),
        "registry/eventlog-system.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\System]",
        ),
        "registry/eventlog-application.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\EventLog\Application]",
        ),
        "registry/uninstall.reg": _reg(
            f"[{UNINSTALL}\\{{A}}]",
            '"DisplayName"="Example Tool"',
            '"DisplayVersion"="1.2.3"',
            '"Publisher"="Example Corp"',
            '"InstallDate"="20260102"',
            "",
            f"[{UNINSTALL}\\{{B}}]",
            '"DisplayName"="Hidden Runtime"',
            '"SystemComponent"=dword:00000001',
            "",
            f"[{UNINSTALL}\\NoName]",
            '"Comment"="no DisplayName"',
        ),
        "registry/uninstall-wow64.reg": _reg(
            f"[{UNINSTALL_WOW}\\{{W}}]",
            '"DisplayName"="Wazuh Agent"',
            '"DisplayVersion"="4.14.2"',
            "",
            f"[{UNINSTALL_WOW}\\{{X}}]",
            '"DisplayName"="Legacy 32-bit App"',
        ),
        "registry/wazuh-service.reg": _reg(
            r"[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WazuhSvc]",
            '"Start"=dword:00000002',
        ),
        # A single object, not a list: ConvertTo-Json output for one CIM instance.
        "host/os.json": _json(
            {
                "Caption": "Microsoft Windows Server 2022 Standard Evaluation",
                "Version": "10.0.20348",
                "BuildNumber": "20348",
                "OSArchitecture": "64-bit",
                "InstallDate": "/Date(1767225600000)/",
                "LastBootUpTime": "/Date(1792137600000)/",
            }
        ),
        "host/processes.json": _json(_processes()),
        "host/files.json": _json(_files()),
        "host/locale.json": _json({"culture": "en-US", "timezone": "UTC"}),
        "host/cpu.json": _json(
            [
                {
                    "Name": "Example CPU  ",
                    "Manufacturer": "GenuineIntel",
                    "NumberOfCores": 2,
                    "NumberOfLogicalProcessors": 4,
                    "MaxClockSpeed": 2400,
                },
                {
                    "Name": "Example CPU",
                    "Manufacturer": "GenuineIntel",
                    "NumberOfCores": 2,
                    "NumberOfLogicalProcessors": 4,
                    "MaxClockSpeed": 2400,
                },
            ]
        ),
        "host/computer.json": _json(
            {
                "Name": "GOLDEN-VM",
                "Manufacturer": "Example Systems",
                "Model": "Virtual Machine",
                "TotalPhysicalMemory": 4294967296,
            }
        ),
        "host/bios.json": _json(
            {
                "Manufacturer": "Example BIOS",
                "SMBIOSBIOSVersion": "1.0",
                "SerialNumber": "SERIAL-123",
                "ReleaseDate": "/Date(1704067200000)/",
            }
        ),
        "host/netadapters.json": _json(
            [
                {
                    "Name": "Ethernet0",
                    "InterfaceDescription": "Example NIC",
                    "Status": "Up",
                    "MacAddress": "02-00-00-00-00-01",
                }
            ]
        ),
        "host/network.json": _json(
            {
                "Description": "Example NIC",
                "MACAddress": "02:00:00:00:00:01",
                "IPAddress": ["198.51.100.7"],
                "DHCPEnabled": True,
            }
        ),
        "host/users.json": _json(
            [
                {
                    "Name": "Administrator",
                    "Enabled": True,
                    "SID": "S-1-5-21-1-2-3-500",
                    "LastLogon": None,
                },
                {"Name": "Guest", "Enabled": False, "SID": "S-1-5-21-1-2-3-501"},
                {"Name": "xvmgolden", "Enabled": True, "SID": "S-1-5-21-1-2-3-1001"},
            ]
        ),
        "host/groups.json": _json(
            [
                {"Name": "Administrators", "SID": "S-1-5-32-544"},
                {"Name": "Guests", "SID": "S-1-5-32-546"},
            ]
        ),
        "host/group-members.json": _json(
            [
                {
                    "group": "Administrators",
                    "member": "GOLDEN-VM\\Administrator",
                    "sid": "S-1-5-21-1-2-3-500",
                    "class": "User",
                    "source": "Local",
                },
                {
                    "group": "Administrators",
                    "member": "EXAMPLE\\Domain Admins",
                    "sid": "S-1-5-21-9-9-9-512",
                    "class": "Group",
                    "source": "ActiveDirectory",
                },
                {
                    "group": "Guests",
                    "member": "GOLDEN-VM\\Guest",
                    "sid": "S-1-5-21-1-2-3-501",
                    "class": "User",
                    "source": "Local",
                },
            ]
        ),
        "host/services.json": _json(
            [
                {
                    "Name": "W32Time",
                    "DisplayName": "Windows Time",
                    "State": "Stopped",
                    "StartMode": "Manual",
                    "PathName": "C:\\Windows\\system32\\svchost.exe -k x",
                    "StartName": "NT AUTHORITY\\LocalService",
                },
                {
                    "Name": "EventLog",
                    "DisplayName": "Windows Event Log",
                    "State": "Running",
                    "StartMode": "Auto",
                },
                {
                    "Name": "WazuhSvc",
                    "DisplayName": "Wazuh",
                    "State": "Running",
                    "StartMode": "Auto",
                },
            ]
        ),
        "wazuh/ossec.conf": b"<ossec_config/>",
        "evtx/rendered/Security.xml": _rendered(
            ("bob", "3"),
            ("alice", "2"),
            ("svc-x", "5"),
        ),
        "evtx/scenario/Security.rendered.xml": _rendered(("xvmgolden", "3")),
        **{
            f"evtx/{part}/{log}.evtx": b"ElfFile\0"
            for part in ("full", "scenario")
            for log in baseline.LOGS
        },
    }


def write(root, overrides: dict[str, bytes] | None = None):
    content = {**files(), **(overrides or {})}
    entries = []
    for rel, data in sorted(content.items()):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        entries.append({"path": rel, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    steps = [
        {
            "name": n,
            "start": "2026-10-16T10:00:00.000Z",
            "end": "2026-10-16T10:00:01.000Z",
            "expect": "x",
        }
        for n in baseline.REQUIRED_STEPS
    ]
    manifest = {
        "schema": 1,
        "kind": "windows-golden-baseline",
        "host": {"name": "GOLDEN-VM", "build": "20348"},
        "capture_pid": 900,
        "scenario": {
            "start": "2026-10-16T10:00:00.000Z",
            "end": "2026-10-16T10:01:00.000Z",
            "steps": steps,
        },
        "warnings": [],
        "files": entries,
    }
    (root / "manifest.json").write_bytes(_json(manifest))
    return root
