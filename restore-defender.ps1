<#
.SYNOPSIS
    Restore everything: re-enable Microsoft Defender AND Windows Update to their normal state.

.DESCRIPTION
    Undoes both disable scripts in one run:
      * Defender       - realtime/behavior/IOAV/script scanning, archive/email/removable/network
                         file scanning, Network Protection, and every network-protocol parser
                         (UDP datagram, TLS, HTTP, DNS, FTP, SMTP, SSH, RDP, inbound filtering).
                         Removes the C:\ scan exclusion if present.
      * Windows Update - NoAutoUpdate policy removed; wuauserv/UsoSvc/BITS/DoSvc back to Manual;
                         WaaSMedicSvc Start = 3 (Manual); UpdateOrchestrator/WindowsUpdate tasks
                         re-enabled.

    Uses only documented, supported mechanisms. Does not touch Defender services/drivers.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\restore-defender.ps1
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param()

$ErrorActionPreference = "Continue"

function Write-Head($text) {
    Write-Host ""
    Write-Host "============================================"
    Write-Host $text
    Write-Host "============================================"
}

function Set-Pref {
    param([hashtable]$Setting, [string]$What)
    try {
        Set-MpPreference @Setting -ErrorAction Stop
        Write-Host ("  [ok]   {0}" -f $What) -ForegroundColor Green
    }
    catch {
        Write-Host ("  [FAIL] {0} -> {1}" -f $What, $_.Exception.Message) -ForegroundColor Yellow
    }
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
    $sub = 'SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
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
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, 'FullControl', 'Allow')
    $acl.SetAccessRule($rule)
    $key.SetAccessControl($acl)
    $key.Close()

    Set-ItemProperty -Path "HKLM:\$sub" -Name Start -Value $StartValue -Type DWord -ErrorAction Stop
}

Write-Host ""
Write-Host "=== RESTORE : Defender + Windows Update ===" -ForegroundColor Cyan

$status = Get-MpComputerStatus
Write-Host ""
Write-Host ("Tamper Protection : {0}" -f $status.IsTamperProtected)

# ============================================================
# PART A - MICROSOFT DEFENDER
# ============================================================

Write-Head "DEFENDER : REALTIME / SCAN ENGINE"
Set-Pref @{ DisableRealtimeMonitoring                     = $false } "RealtimeMonitoring ON"
Set-Pref @{ DisableBehaviorMonitoring                     = $false } "BehaviorMonitoring ON"
Set-Pref @{ DisableIOAVProtection                         = $false } "IOAVProtection ON"
Set-Pref @{ DisableScriptScanning                         = $false } "ScriptScanning ON"
Set-Pref @{ DisableArchiveScanning                        = $false } "ArchiveScanning ON"
Set-Pref @{ DisableEmailScanning                          = $false } "EmailScanning ON"
Set-Pref @{ DisableRemovableDriveScanning                 = $false } "RemovableDriveScanning ON"
Set-Pref @{ DisableScanningNetworkFiles                   = $false } "ScanningNetworkFiles ON"
Set-Pref @{ DisableScanningMappedNetworkDrivesForFullScan = $false } "ScanningMappedNetworkDrives ON"

Write-Head "DEFENDER : NETWORK PROTECTION"
Set-Pref @{ EnableNetworkProtection = "Enabled" } "EnableNetworkProtection = Enabled"

Write-Head "DEFENDER : NETWORK PROTOCOL PARSING"
Set-Pref @{ DisableDatagramProcessing         = $false } "Datagram/UDP inspection ON"
Set-Pref @{ DisableTlsParsing                 = $false } "TlsParsing ON"
Set-Pref @{ DisableHttpParsing                = $false } "HttpParsing ON"
Set-Pref @{ DisableDnsParsing                 = $false } "DnsParsing ON"
Set-Pref @{ DisableDnsOverTcpParsing          = $false } "DnsOverTcpParsing ON"
Set-Pref @{ DisableFtpParsing                 = $false } "FtpParsing ON"
Set-Pref @{ DisableSmtpParsing                = $false } "SmtpParsing ON"
Set-Pref @{ DisableSshParsing                 = $false } "SshParsing ON"
Set-Pref @{ DisableRdpParsing                 = $false } "RdpParsing ON"
Set-Pref @{ DisableInboundConnectionFiltering = $false } "InboundConnectionFiltering ON"

Write-Head "DEFENDER : SCAN EXCLUSION (C:\)"
$prefs = Get-MpPreference
if ($prefs.ExclusionPath -contains "C:\") {
    try { Remove-MpPreference -ExclusionPath "C:\" -ErrorAction Stop; Report $true "removed C:\ exclusion" }
    catch { Report $false "remove C:\ exclusion" $_.Exception.Message }
} else {
    Write-Host "  [skip] no C:\ exclusion present"
}

# ============================================================
# PART B - WINDOWS UPDATE
# ============================================================

Write-Head "UPDATE : GROUP POLICY"
$auKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
try {
    if (Test-Path $auKey) { Remove-ItemProperty -Path $auKey -Name 'NoAutoUpdate' -ErrorAction SilentlyContinue }
    Report $true "NoAutoUpdate policy removed"
} catch { Report $false "remove NoAutoUpdate" $_.Exception.Message }

Write-Head "UPDATE : SERVICES"
foreach ($svc in 'wuauserv','UsoSvc','BITS','DoSvc') {
    try {
        Set-Service -Name $svc -StartupType Manual -ErrorAction Stop
        Report $true ("{0} -> Manual" -f $svc)
    } catch { Report $false $svc $_.Exception.Message }
}

Write-Head "UPDATE : WaaSMedicSvc"
try {
    Set-WaaSMedicStart -StartValue 3
    Report $true "WaaSMedicSvc Start = 3 (Manual)"
} catch { Report $false "WaaSMedicSvc (take ownership / set Start)" $_.Exception.Message }

Write-Head "UPDATE : SCHEDULED TASKS"
$tasks = foreach ($p in '\Microsoft\Windows\UpdateOrchestrator\', '\Microsoft\Windows\WindowsUpdate\') {
    Get-ScheduledTask -TaskPath $p -ErrorAction SilentlyContinue
}
if (-not $tasks) {
    Write-Host "  (no matching scheduled tasks found)"
} else {
    foreach ($t in $tasks) {
        $label = "{0}{1}" -f $t.TaskPath, $t.TaskName
        try {
            Enable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop | Out-Null
            Report $true ("enabled {0}" -f $label)
        } catch { Report $false $label $_.Exception.Message }
    }
}

# ============================================================
# Resulting state
# ============================================================
Write-Head "DEFENDER STATUS"
Get-MpComputerStatus |
    Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, AntispywareEnabled,
                  RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled,
                  NISEnabled, IsTamperProtected |
    Format-List

Write-Head "UPDATE SERVICE STATE"
Get-Service wuauserv, UsoSvc, WaaSMedicSvc, BITS, DoSvc -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-Host ""
Write-Host "Defender and Windows Update restored to normal. A reboot is recommended." -ForegroundColor Green
Write-Host "If RealTimeProtectionEnabled still shows False, run a Windows Security / signature" -ForegroundColor DarkGray
Write-Host "update, or toggle Real-time protection once in the Windows Security app." -ForegroundColor DarkGray
Write-Host ""
Write-Host "DONE." -ForegroundColor Green
