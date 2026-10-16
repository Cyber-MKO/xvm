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
            }
        ),
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
