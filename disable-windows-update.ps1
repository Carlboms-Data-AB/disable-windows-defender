<#
.SYNOPSIS
    Disable (or restore) Windows Update on an isolated machine.

.DESCRIPTION
    Turns off Windows Update to remove its intermittent CPU spikes (scans, downloads, and the
    self-healing WaaSMedicSvc) as a variable in a performance test on a dedicated, isolated host.

    It does four things, each reversible with -Revert:
      1. Group Policy   : HKLM\...\WindowsUpdate\AU  NoAutoUpdate = 1
      2. Services       : wuauserv, UsoSvc, BITS, DoSvc  -> Disabled + stopped
      3. WaaSMedicSvc   : the "medic" that re-enables Windows Update -> Start = 4 (Disabled).
                          Its service key is owned by TrustedInstaller, so the script takes
                          ownership first. If that fails it reports [FAIL] and continues.
      4. Scheduled tasks: \Microsoft\Windows\UpdateOrchestrator\* and \...\WindowsUpdate\*  -> Disabled

    Nothing here touches Microsoft Defender - use defender-perf-test.ps1 for that.

.PARAMETER Revert
    Re-enable Windows Update: policy removed, services back to Manual, WaaSMedicSvc Start = 3,
    scheduled tasks re-enabled.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\disable-windows-update.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\disable-windows-update.ps1 -Revert
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Revert
)

$ErrorActionPreference = "Continue"

function Write-Head($text) {
    Write-Host ""
    Write-Host "============================================"
    Write-Host $text
    Write-Host "============================================"
}

function Report {
    param([bool]$Ok, [string]$What, [string]$Err = "")
    if ($Ok) { Write-Host ("  [ok]   {0}" -f $What) -ForegroundColor Green }
    else     { Write-Host ("  [FAIL] {0} -> {1}" -f $What, $Err) -ForegroundColor Yellow }
}

# Enable a process privilege (needed to take ownership of the WaaSMedicSvc service key).
function Enable-Privilege {
    param([string]$Privilege)
    if (-not ('TokenManipulator' -as [type])) {
        Add-Type @'
using System;
using System.Runtime.InteropServices;
public class TokenManipulator {
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("kernel32.dll", ExactSpelling=true)]
    internal static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", ExactSpelling=true, SetLastError=true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError=true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack=1)]
    internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool AddPrivilege(string privilege) {
        IntPtr htok = IntPtr.Zero;
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        TokPriv1Luid tp; tp.Count = 1; tp.Luid = 0; tp.Attr = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
'@
    }
    [TokenManipulator]::AddPrivilege($Privilege) | Out-Null
}

# Take ownership of the WaaSMedicSvc service key, grant admins full control, set its Start value.
function Set-WaaSMedicStart {
    param([int]$StartValue)
    $sub  = 'SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
    Enable-Privilege SeTakeOwnershipPrivilege
    Enable-Privilege SeRestorePrivilege

    $admins = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')  # BUILTIN\Administrators

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $sub,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::TakeOwnership)
    $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Owner)
    $acl.SetOwner($admins)
    $key.SetAccessControl($acl)
    $key.Close()

    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
        $sub,
        [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
        [System.Security.AccessControl.RegistryRights]::ChangePermissions)
    $acl  = $key.GetAccessControl()
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule(
        $admins, 'FullControl', 'Allow')
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
    $key.Close()

    Set-ItemProperty -Path "HKLM:\$sub" -Name Start -Value $StartValue -Type DWord -ErrorAction Stop
}

Write-Host ""
if ($Revert) {
    Write-Host "=== WINDOWS UPDATE : RESTORE (re-enable) ===" -ForegroundColor Cyan
} else {
    Write-Host "=== WINDOWS UPDATE : DISABLE ===" -ForegroundColor Yellow
}

# ------------------------------------------------------------
# 1. Group Policy
# ------------------------------------------------------------
Write-Head "GROUP POLICY (Auto Update)"
$auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
if ($Revert) {
    try {
        if (Test-Path $auKey) {
            Remove-ItemProperty -Path $auKey -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue
        }
        Report $true "NoAutoUpdate policy removed"
    } catch { Report $false "remove NoAutoUpdate" $_.Exception.Message }
} else {
    try {
        if (-not (Test-Path $auKey)) { New-Item -Path $auKey -Force | Out-Null }
        Set-ItemProperty -Path $auKey -Name 'NoAutoUpdate' -Value 1 -Type DWord -ErrorAction Stop
        Report $true "NoAutoUpdate = 1"
    } catch { Report $false "set NoAutoUpdate" $_.Exception.Message }
}

# ------------------------------------------------------------
# 2. Services
# ------------------------------------------------------------
Write-Head "SERVICES"
# On disable -> Disabled + stop; on revert -> Manual (services are demand/trigger started).
$services = 'wuauserv','UsoSvc','BITS','DoSvc'
foreach ($svc in $services) {
    try {
        if ($Revert) {
            Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
            Report $true ("{0} -> Manual" -f $svc)
        } else {
            Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Report $true ("{0} -> Disabled + stopped" -f $svc)
        }
    } catch { Report $false $svc $_.Exception.Message }
}

# ------------------------------------------------------------
# 3. WaaSMedicSvc (self-healing "medic" - protected key, needs ownership)
# ------------------------------------------------------------
Write-Head "WaaSMedicSvc (Update Medic)"
$medicStart = if ($Revert) { 3 } else { 4 }   # 3 = Manual, 4 = Disabled
try {
    Set-WaaSMedicStart -StartValue $medicStart
    if ($Revert) { Stop-Service WaaSMedicSvc -ErrorAction SilentlyContinue }
    else         { Stop-Service WaaSMedicSvc -Force -ErrorAction SilentlyContinue }
    Report $true ("WaaSMedicSvc Start = {0} ({1})" -f $medicStart, $(if($Revert){'Manual'}else{'Disabled'}))
} catch {
    Report $false "WaaSMedicSvc (take ownership / set Start)" $_.Exception.Message
    Write-Host "         Update may re-enable itself while WaaSMedicSvc is still active." -ForegroundColor DarkGray
}

# ------------------------------------------------------------
# 4. Scheduled tasks
# ------------------------------------------------------------
Write-Head "SCHEDULED TASKS (UpdateOrchestrator / WindowsUpdate)"
$taskPaths = '\Microsoft\Windows\UpdateOrchestrator\', '\Microsoft\Windows\WindowsUpdate\'
$tasks = foreach ($p in $taskPaths) {
    Get-ScheduledTask -TaskPath $p -ErrorAction SilentlyContinue
}
if (-not $tasks) {
    Write-Host "  (no matching scheduled tasks found)"
} else {
    foreach ($t in $tasks) {
        $label = "{0}{1}" -f $t.TaskPath, $t.TaskName
        try {
            if ($Revert) {
                Enable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null
                Report $true ("enabled  {0}" -f $label)
            } else {
                Disable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null
                Report $true ("disabled {0}" -f $label)
            }
        } catch { Report $false $label $_.Exception.Message }
    }
}

# ------------------------------------------------------------
# 5. Resulting state
# ------------------------------------------------------------
Write-Head "SERVICE STATE"
Get-Service wuauserv, UsoSvc, WaaSMedicSvc, BITS, DoSvc -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-Head "POLICY STATE"
if (Test-Path $auKey) {
    $na = (Get-ItemProperty -Path $auKey -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue).NoAutoUpdate
    Write-Host ("  NoAutoUpdate = {0}" -f $(if ($null -eq $na) { '(not set)' } else { $na }))
} else {
    Write-Host "  NoAutoUpdate = (policy key absent)"
}

Write-Host ""
if ($Revert) {
    Write-Host "Windows Update restored. A reboot is recommended." -ForegroundColor Green
} else {
    Write-Host "Windows Update disabled. A reboot is recommended to settle service state." -ForegroundColor Green
}
Write-Host "DONE." -ForegroundColor Green
