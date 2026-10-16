<#
.SYNOPSIS
    Capture the Windows golden baseline for xvm (roadmap Phase 0).

.DESCRIPTION
    Run once, as Administrator, on a Windows evaluation VM with the Wazuh agent
    installed and enrolled. The script:

      1. Exports host identity: registry keys, system, network, software, users,
         services and hotfixes.
      2. Runs a short, reversible scenario that produces known events: a local
         user is created, added to and removed from Administrators, used for
         three failed logons and deleted; W32Time is restarted; a file in the
         FIM folder is created, changed and deleted.
      3. Exports the Security, System and Application logs, both in full and
         for the scenario window only.
      4. Writes manifest.json with step timestamps (UTC) and SHA-256 hashes.

    It never clears an event log and never copies the agent key (client.keys).
    Compatible with Windows PowerShell 5.1.

.PARAMETER OutDir
    Output directory. Created if missing. Must be empty.

.PARAMETER FimDir
    Folder used for the FIM step. Add it to the agent's ossec.conf first, for
    example <directories realtime="yes">C:\xvm-golden-fim</directories>.

.PARAMETER AgentDir
    Wazuh agent install folder.

.PARAMETER SettleSeconds
    Wait after each scenario step so the agent can ship its events.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutDir,
    [string]$FimDir = 'C:\xvm-golden-fim',
    [string]$AgentDir = "${env:ProgramFiles(x86)}\ossec-agent",
    [int]$SettleSeconds = 10
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$SchemaVersion = 1
$Logs = @('Security', 'System', 'Application')
$TestUser = 'xvmgolden'
$MarkerSource = 'xvm-golden'

# Registry keys that hold host identity. Value names in the census strings
# (CurrentBuildNumber, ReleaseId, DisplayVersion, ProfileImagePath) live here.
$RegistryKeys = [ordered]@{
    'os-currentversion'   = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    'computername'        = 'HKLM\SYSTEM\CurrentControlSet\Control\ComputerName'
    'tcpip-parameters'    = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'
    'uninstall'           = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    'uninstall-wow64'     = 'HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    'profilelist'         = 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    'timezone'            = 'HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation'
    'wazuh-service'       = 'HKLM\SYSTEM\CurrentControlSet\Services\WazuhSvc'
    'eventlog-security'   = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security'
    'eventlog-system'     = 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System'
    'eventlog-application'= 'HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application'
}

function Get-UtcNow {
    return (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script as Administrator.'
    }
}

function Invoke-Native {
    # Run a native command and fail on a non-zero exit code.
    param([string]$File, [string[]]$Arguments, [switch]$AllowFailure)
    & $File @Arguments 2>&1 | Out-Null
    if (-not $AllowFailure -and $LASTEXITCODE -ne 0) {
        throw "$File $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
    }
    return $LASTEXITCODE
}

function Save-Json {
    param($Object, [string]$Path)
    # -InputObject keeps a one-element array an array in the JSON.
    ConvertTo-Json -InputObject $Object -Depth 6 | Set-Content -Path $Path -Encoding UTF8
}

function New-RandomPassword {
    $bytes = New-Object byte[] 18
    [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return 'Xg1!' + [Convert]::ToBase64String($bytes)
}

$Steps = New-Object System.Collections.ArrayList
$Warnings = New-Object System.Collections.ArrayList

function Invoke-Step {
    param([string]$Name, [string]$Expect, [scriptblock]$Action)
    Write-Host "step: $Name"
    $start = Get-UtcNow
    & $Action
    Start-Sleep -Seconds $SettleSeconds
    [void]$Steps.Add([ordered]@{ name = $Name; start = $start; end = (Get-UtcNow); expect = $Expect })
}

# ---------------------------------------------------------------- preflight

Assert-Admin
if (Test-Path $OutDir) {
    if (@(Get-ChildItem -Force $OutDir).Count -gt 0) { throw "OutDir is not empty: $OutDir" }
} else {
    New-Item -ItemType Directory -Path $OutDir | Out-Null
}
$OutDir = (Resolve-Path $OutDir).Path
foreach ($d in 'registry', 'host', 'wazuh', 'evtx\full', 'evtx\scenario') {
    New-Item -ItemType Directory -Path (Join-Path $OutDir $d) | Out-Null
}

$ossecConf = Join-Path $AgentDir 'ossec.conf'
if (-not (Test-Path $ossecConf)) { throw "Wazuh agent not found at $AgentDir" }
if (-not (Select-String -Path $ossecConf -SimpleMatch $FimDir -Quiet)) {
    [void]$Warnings.Add("FIM folder $FimDir is not in ossec.conf; the FIM step will raise no alert.")
}
if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
    throw "Local user $TestUser already exists. Remove it and run again."
}
$svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
if ($null -eq $svc -or $svc.Status -ne 'Running') { throw 'WazuhSvc is not running.' }

$captureStart = Get-UtcNow

# ---------------------------------------------------------------- host identity

foreach ($name in $RegistryKeys.Keys) {
    $file = Join-Path $OutDir "registry\$name.reg"
    $rc = Invoke-Native reg.exe @('export', $RegistryKeys[$name], $file, '/y') -AllowFailure
    if ($rc -ne 0) { [void]$Warnings.Add("reg export failed for $($RegistryKeys[$name])") }
}

$hostDir = Join-Path $OutDir 'host'
systeminfo.exe /fo csv | Set-Content -Path (Join-Path $hostDir 'systeminfo.csv') -Encoding UTF8
ipconfig.exe /all | Set-Content -Path (Join-Path $hostDir 'ipconfig.txt') -Encoding UTF8
Save-Json (Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime,
        CSName, Locale, OSLanguage, ProductType, SerialNumber) (Join-Path $hostDir 'os.json')
Save-Json (Get-CimInstance Win32_ComputerSystem |
    Select-Object Name, Domain, Manufacturer, Model, NumberOfProcessors,
        NumberOfLogicalProcessors, TotalPhysicalMemory) (Join-Path $hostDir 'computer.json')
Save-Json (Get-CimInstance Win32_Processor |
    Select-Object Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors,
        MaxClockSpeed) (Join-Path $hostDir 'cpu.json')
Save-Json (Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer, SMBIOSBIOSVersion, SerialNumber,
        ReleaseDate) (Join-Path $hostDir 'bios.json')
Save-Json (Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' |
    Select-Object Description, MACAddress, IPAddress, IPSubnet, DefaultIPGateway,
        DNSServerSearchOrder, DHCPEnabled) (Join-Path $hostDir 'network.json')
Save-Json (Get-CimInstance Win32_QuickFixEngineering |
    Select-Object HotFixID, Description, InstalledOn) (Join-Path $hostDir 'hotfixes.json')
# SIDs are written as text; ConvertTo-Json would otherwise expand the object.
$sidText = @{ Name = 'SID'; Expression = { $_.SID.Value } }
Save-Json @(Get-LocalUser | Select-Object Name, Enabled, $sidText, LastLogon,
    PasswordLastSet) (Join-Path $hostDir 'users.json')
Save-Json @(Get-LocalGroup | Select-Object Name, $sidText) (Join-Path $hostDir 'groups.json')
$members = New-Object System.Collections.ArrayList
foreach ($g in Get-LocalGroup) {
    # Get-LocalGroupMember fails on groups holding orphaned domain SIDs; skip those.
    try {
        foreach ($m in Get-LocalGroupMember -Group $g.Name -ErrorAction Stop) {
            [void]$members.Add([ordered]@{
                group = $g.Name; member = $m.Name; sid = $m.SID.Value
                class = [string]$m.ObjectClass; source = [string]$m.PrincipalSource
            })
        }
    } catch {
        [void]$Warnings.Add("Members of group $($g.Name) not read: $($_.Exception.Message)")
    }
}
Save-Json @($members) (Join-Path $hostDir 'group-members.json')
Save-Json @(Get-NetAdapter | Select-Object Name, InterfaceDescription, Status,
    MacAddress) (Join-Path $hostDir 'netadapters.json')
Save-Json ([ordered]@{
    culture  = (Get-Culture).Name
    timezone = (Get-TimeZone).Id
}) (Join-Path $hostDir 'locale.json')
Save-Json (Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, PathName,
        StartName) (Join-Path $hostDir 'services.json')
Save-Json (Get-CimInstance Win32_Process |
    Select-Object ProcessId, ParentProcessId, Name, ExecutablePath) (Join-Path $hostDir 'processes.json')

$wazuhDir = Join-Path $OutDir 'wazuh'
Copy-Item $ossecConf (Join-Path $wazuhDir 'ossec.conf')
foreach ($f in 'VERSION.json', 'VERSION', 'ossec.log') {
    $src = Join-Path $AgentDir $f
    if (Test-Path $src) { Copy-Item $src (Join-Path $wazuhDir $f) }
}

# ---------------------------------------------------------------- scenario

$password = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
$scenarioStart = Get-UtcNow

try {
    Invoke-Step 'marker_start' 'Application event 900 from xvm-golden' {
        Invoke-Native eventcreate.exe @('/T', 'INFORMATION', '/ID', '900', '/L', 'APPLICATION',
            '/SO', $MarkerSource, '/D', 'xvm golden scenario start') | Out-Null
    }
    Invoke-Step 'user_create' 'Security 4720, 4722, 4724, 4738' {
        New-LocalUser -Name $TestUser -Password $password -Description 'xvm golden baseline' | Out-Null
    }
    Invoke-Step 'group_add' 'Security 4732' {
        Add-LocalGroupMember -SID 'S-1-5-32-544' -Member $TestUser
    }
    Invoke-Step 'failed_logon' 'Security 4625 three times' {
        for ($i = 0; $i -lt 3; $i++) {
            Invoke-Native net.exe @('use', '\\127.0.0.1\IPC$', '/user:' + $TestUser, 'wrong-password') -AllowFailure | Out-Null
        }
    }
    Invoke-Step 'group_remove' 'Security 4733' {
        Remove-LocalGroupMember -SID 'S-1-5-32-544' -Member $TestUser
    }
    Invoke-Step 'user_delete' 'Security 4726' {
        Remove-LocalUser -Name $TestUser
    }
    Invoke-Step 'service_restart' 'System 7036 for W32Time' {
        Restart-Service -Name W32Time -Force
    }
    Invoke-Step 'fim_change' 'Wazuh FIM added, modified and deleted alerts' {
        if (-not (Test-Path $FimDir)) { New-Item -ItemType Directory -Path $FimDir | Out-Null }
        $f = Join-Path $FimDir 'golden.txt'
        Set-Content -Path $f -Value 'xvm golden v1'
        Start-Sleep -Seconds 3
        Add-Content -Path $f -Value 'xvm golden v2'
        Start-Sleep -Seconds 3
        Remove-Item -Path $f
    }
    Invoke-Step 'marker_end' 'Application event 901 from xvm-golden' {
        Invoke-Native eventcreate.exe @('/T', 'INFORMATION', '/ID', '901', '/L', 'APPLICATION',
            '/SO', $MarkerSource, '/D', 'xvm golden scenario end') | Out-Null
    }
} finally {
    # Never leave the test account behind, even if a step failed.
    if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
        Remove-LocalUser -Name $TestUser
        [void]$Warnings.Add("Scenario stopped early; $TestUser was removed during cleanup.")
    }
}
$scenarioEnd = Get-UtcNow

# ---------------------------------------------------------------- event logs

$window = "*[System[TimeCreated[@SystemTime>='$scenarioStart' and @SystemTime<='$scenarioEnd']]]"
foreach ($log in $Logs) {
    Invoke-Native wevtutil.exe @('epl', $log, (Join-Path $OutDir "evtx\full\$log.evtx")) | Out-Null
    Invoke-Native wevtutil.exe @('epl', $log, (Join-Path $OutDir "evtx\scenario\$log.evtx"),
        "/q:$window") | Out-Null
}

# ---------------------------------------------------------------- manifest

$files = New-Object System.Collections.ArrayList
Get-ChildItem -Path $OutDir -Recurse -File | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($OutDir.Length + 1).Replace('\', '/')
    [void]$files.Add([ordered]@{
        path   = $rel
        size   = $_.Length
        sha256 = (Get-FileHash -Algorithm SHA256 -Path $_.FullName).Hash.ToLowerInvariant()
    })
}

$os = Get-CimInstance Win32_OperatingSystem
$agentVersion = $null
$versionJson = Join-Path $AgentDir 'VERSION.json'
if (Test-Path $versionJson) {
    $agentVersion = (Get-Content $versionJson -Raw | ConvertFrom-Json).version
}

$manifest = [ordered]@{
    schema        = $SchemaVersion
    kind          = 'windows-golden-baseline'
    host          = [ordered]@{
        name    = $env:COMPUTERNAME
        os      = $os.Caption
        version = $os.Version
        build   = $os.BuildNumber
    }
    agent         = [ordered]@{ product = 'wazuh'; version = $agentVersion }
    capture_start = $captureStart
    capture_end   = (Get-UtcNow)
    scenario      = [ordered]@{ start = $scenarioStart; end = $scenarioEnd; steps = $Steps }
    warnings      = $Warnings
    files         = $files
}
Save-Json $manifest (Join-Path $OutDir 'manifest.json')

Write-Host "Done: $OutDir"
foreach ($w in $Warnings) { Write-Warning $w }
Write-Host "Next: on the manager, run manager-capture.sh for this agent, then xvm-golden import-manager."
