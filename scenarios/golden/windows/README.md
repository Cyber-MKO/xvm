# Windows golden baseline

A one-time capture from a real Windows evaluation VM running the Wazuh agent. Emulated hosts are diffed against it (brief section 11). Capturing it is the last Phase 0 exit item.

## What you need

| Item | Detail |
| --- | --- |
| Windows VM | Windows Server or Windows 11 evaluation image, 64-bit |
| Wazuh agent | 4.14.2 (the Phase 1 target), installed and enrolled |
| Wazuh manager | Same version, reachable from the VM, with shell access |
| Agent name | A dedicated name, for example `xvm-golden-win` |

## Steps

| # | Where | Action |
| --- | --- | --- |
| 1 | Manager | Set `<logall_json>yes</logall_json>` in the `<global>` section of `/var/ossec/etc/ossec.conf`, then restart the manager. |
| 2 | VM | Add `<directories realtime="yes">C:\xvm-golden-fim</directories>` to the `<syscheck>` section of the agent's `ossec.conf`. Restart `WazuhSvc`. |
| 3 | VM | Wait until the agent shows Active on the manager and its first FIM scan has finished. |
| 4 | VM | In an Administrator PowerShell window: `.\capture.ps1 -OutDir C:\xvm-golden-out` |
| 5 | Manager | Within the same day: `./manager-capture.sh xvm-golden-win /tmp/xvm-golden-manager` |
| 6 | Workstation | Copy both folders to the repo checkout, then run `xvm-golden import-manager <capture-dir> --archives <manager-dir>/archives.json --alerts <manager-dir>/alerts.json` |
| 7 | Workstation | `xvm-golden verify <capture-dir>` must print `ok`. |
| 8 | Workstation | Move the folder to `scenarios/golden/windows/captures/<host>-<yyyymmdd>/` and commit it. Git LFS stores the `.evtx` and manager files (see `.gitattributes`). Run `git lfs install` once first. |
| 9 | Workstation | Build the base image: `xvm-profile base-from-golden scenarios/golden/windows/captures/<id> --name <base-name>`. Commit `control/profiles/bases/<base-name>.yaml`. |

If `capture.ps1` is blocked, run it with `powershell -ExecutionPolicy Bypass -File .\capture.ps1 -OutDir C:\xvm-golden-out`.

## The scenario

Each step waits 10 seconds so the agent can ship its events. The manifest records the start and end of each step in UTC.

| Step | Action | Expected events |
| --- | --- | --- |
| `marker_start` | `eventcreate` ID 900, source `xvm-golden` | Application 900 |
| `user_create` | Create local user `xvmgolden` | Security 4720, 4722, 4724, 4738 |
| `group_add` | Add it to Administrators | Security 4732 |
| `failed_logon` | Three `net use` logons with a wrong password | Security 4625, three times |
| `group_remove` | Remove it from Administrators | Security 4733 |
| `user_delete` | Delete the user | Security 4726 |
| `service_restart` | Restart W32Time | System 7036 |
| `fim_change` | Create, change and delete `golden.txt` in the FIM folder | Wazuh FIM added, modified and deleted |
| `marker_end` | `eventcreate` ID 901 | Application 901 |

The test user is removed even if a step fails. No event log is cleared.

## File metadata

`host/files.json` lists paths, sizes, times, attributes and SHA-256 hashes, never file bytes. It covers the folders in the agent's `<syscheck>` `<directories>` (to depth 3), `System32\drivers\etc` and the top level of the Windows folder. It skips the agent, output and FIM folders, and stops at 50,000 entries. Files larger than 64 MB, and files in use, are listed without a hash; the manifest warnings count them.

## Output

| Path | Contents |
| --- | --- |
| `manifest.json` | Host, agent version, step times, file hashes, warnings |
| `registry/*.reg` | Identity keys: OS version, computer name, TCP/IP, uninstall, profiles, time zone, Wazuh service, Event Log |
| `host/*` | `systeminfo`, `ipconfig /all`, and JSON for OS, locale, computer, CPU, BIOS, network, network adapters, hotfixes, users, groups, group members, services, processes (with command lines, owners and start times), and file metadata |
| `wazuh/*` | Agent `ossec.conf`, version files, `ossec.log`. Never `client.keys`. |
| `evtx/full/*.evtx` | Security, System and Application, whole log |
| `evtx/scenario/*.evtx` | The same logs, scenario window only |
| `manager/*.json` | Manager archives and alerts for the window, added by `xvm-golden import-manager` |

`xvm-golden verify` checks the hashes, the required files and steps, the step times, and that no `client.keys` is present.
