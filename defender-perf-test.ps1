<#
.SYNOPSIS
    Defender network/scan performance A/B test toggle for an isolated GigE Vision camera host.

.DESCRIPTION
    Disables the Microsoft Defender inspection that can plausibly cost CPU on a high-rate
    UDP receive path (datagram/network-protocol parsing, network protection, realtime scan)
    so you can measure packet loss with Defender's inspection out of the way, then revert.

    Only documented, Microsoft-supported Set-MpPreference switches are used. It does NOT try
    to stop/patch WinDefend, WdFilter, WdNisSvc etc. (unsupported on Windows clients and may
    force a reimage), and it does NOT pretend to bypass Tamper Protection.

    Tamper Protection cannot be disabled by a local script on standalone Windows 11 Pro.
    If it is ON, several antivirus settings below and the C:\ exclusion may silently be
    ignored. The network-parser switches are still attempted. Turn Tamper Protection off
    manually first (Windows Security > Virus & threat protection > Manage settings) if you
    want realtime/exclusion changes to actually take effect.

.PARAMETER Revert
    Re-enable everything this script turned off (restore Defender to normal).

.PARAMETER ExcludeSystemDrive
    Also add a Defender scan exclusion for the whole system drive (C:\). Off by default
    because it only matters for on-access file scanning, not the UDP path, and it is
    blocked while Tamper Protection is on. Ignored together with -Revert (the exclusion
    is always removed on revert).

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1 -Revert
#>

#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Revert,
    [switch]$ExcludeSystemDrive
)

$ErrorActionPreference = "Continue"

function Write-Head($text) {
    Write-Host ""
    Write-Host "============================================"
    Write-Host $text
    Write-Host "============================================"
}

# Wrap Set-MpPreference so a single blocked setting (e.g. Tamper Protection) does not abort the run.
function Set-Pref {
    param([hashtable], [string])
    try {
        Set-MpPreference @Setting -ErrorAction Stop
        Write-Host ("  [ok]   {0}" -f $What) -ForegroundColor Green
    }
    catch {
        Write-Host ("  [FAIL] {0} -> {1}" -f $What, $_.Exception.Message) -ForegroundColor Yellow
    }
}

Write-Host ""
if ($Revert) {
    Write-Host "=== DEFENDER PERFORMANCE TEST : REVERT (re-enable) ===" -ForegroundColor Cyan
} else {
    Write-Host "=== DEFENDER PERFORMANCE TEST : DISABLE inspection ===" -ForegroundColor Yellow
}

# ------------------------------------------------------------
# 0. Pre-flight: report Tamper Protection so the operator knows
#    whether the antivirus/exclusion changes below can stick.
# ------------------------------------------------------------
$status = Get-MpComputerStatus
Write-Host ""
Write-Host ("Tamper Protection : {0}" -f $status.IsTamperProtected)
Write-Host ("Realtime          : {0}" -f $status.RealTimeProtectionEnabled)
Write-Host ("NIS               : {0}" -f $status.NISEnabled)

if ($status.IsTamperProtected) {
    Write-Host ""
    Write-Warning "Tamper Protection is ON."
    Write-Warning "Realtime / behavior / IOAV / script-scan changes and the C:\ exclusion may be IGNORED."
    Write-Warning "Network-parser switches are still attempted. Disable Tamper Protection manually in"
    Write-Warning "Windows Security if you need the antivirus settings to actually take effect."
}

# Desired value for the 'disable' switches: $true to disable, $false to revert.
$off = -not $Revert

# ------------------------------------------------------------
# 1. Realtime / scan engine
# ------------------------------------------------------------
Write-Head "REALTIME / SCAN ENGINE"
Set-Pref @{ DisableRealtimeMonitoring              = $off } "DisableRealtimeMonitoring"
Set-Pref @{ DisableBehaviorMonitoring             = $off } "DisableBehaviorMonitoring"
Set-Pref @{ DisableIOAVProtection                 = $off } "DisableIOAVProtection (downloaded files)"
Set-Pref @{ DisableScriptScanning                 = $off } "DisableScriptScanning"
Set-Pref @{ DisableArchiveScanning                = $off } "DisableArchiveScanning"
Set-Pref @{ DisableEmailScanning                  = $off } "DisableEmailScanning"
Set-Pref @{ DisableRemovableDriveScanning         = $off } "DisableRemovableDriveScanning"
Set-Pref @{ DisableScanningNetworkFiles           = $off } "DisableScanningNetworkFiles"
Set-Pref @{ DisableScanningMappedNetworkDrivesForFullScan = $off } "DisableScanningMappedNetworkDrivesForFullScan"

# ------------------------------------------------------------
# 2. Network Protection
# ------------------------------------------------------------
Write-Head "NETWORK PROTECTION"
if ($Revert) {
    Set-Pref @{ EnableNetworkProtection = "Enabled" }  "EnableNetworkProtection = Enabled"
} else {
    Set-Pref @{ EnableNetworkProtection = "Disabled" } "EnableNetworkProtection = Disabled"
}

# ------------------------------------------------------------
# 3. Network protocol parsing  (the part most relevant to the UDP camera path)
#    DisableDatagramProcessing = disable inspection of UDP connections.
# ------------------------------------------------------------
Write-Head "NETWORK PROTOCOL PARSING"
Set-Pref @{ DisableDatagramProcessing        = $off } "DisableDatagramProcessing (UDP inspection)"
Set-Pref @{ DisableTlsParsing                = $off } "DisableTlsParsing"
Set-Pref @{ DisableHttpParsing               = $off } "DisableHttpParsing"
Set-Pref @{ DisableDnsParsing                = $off } "DisableDnsParsing"
Set-Pref @{ DisableDnsOverTcpParsing         = $off } "DisableDnsOverTcpParsing"
Set-Pref @{ DisableFtpParsing                = $off } "DisableFtpParsing"
Set-Pref @{ DisableSmtpParsing               = $off } "DisableSmtpParsing"
Set-Pref @{ DisableSshParsing                = $off } "DisableSshParsing"
Set-Pref @{ DisableRdpParsing                = $off } "DisableRdpParsing"
Set-Pref @{ DisableInboundConnectionFiltering = $off } "DisableInboundConnectionFiltering"

# ------------------------------------------------------------
# 4. Optional system-drive exclusion (on-access file scanning only)
# ------------------------------------------------------------
Write-Head "SCAN EXCLUSION (C:\)"
$prefs = Get-MpPreference
$hasC  = $prefs.ExclusionPath -contains "C:\"
if ($Revert) {
    if ($hasC) {
        try { Remove-MpPreference -ExclusionPath "C:\" -ErrorAction Stop; Write-Host "  [ok]   removed C:\ exclusion" -ForegroundColor Green }
        catch { Write-Host ("  [FAIL] remove C:\ exclusion -> {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    } else { Write-Host "  [skip] no C:\ exclusion present" }
}
elseif ($ExcludeSystemDrive) {
    if (-not $hasC) {
        try { Add-MpPreference -ExclusionPath "C:\" -ErrorAction Stop; Write-Host "  [ok]   added C:\ exclusion" -ForegroundColor Green }
        catch { Write-Host ("  [FAIL] add C:\ exclusion -> {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
    } else { Write-Host "  [skip] C:\ exclusion already present" }
} else {
    Write-Host "  [skip] not requested (use -ExcludeSystemDrive to add)"
}

# ------------------------------------------------------------
# 5. Resulting state
# ------------------------------------------------------------
Write-Head "DEFENDER STATUS"
Get-MpComputerStatus |
    Select-Object AMRunningMode, AMServiceEnabled, AntivirusEnabled, AntispywareEnabled,
                  RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled,
                  NISEnabled, IsTamperProtected |
    Format-List

Write-Head "DEFENDER CONFIGURATION"
Get-MpPreference |
    Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection,
                  DisableScriptScanning, DisableScanningNetworkFiles, EnableNetworkProtection,
                  DisableDatagramProcessing, DisableTlsParsing, DisableHttpParsing,
                  DisableDnsParsing, DisableDnsOverTcpParsing, DisableFtpParsing,
                  DisableSmtpParsing, DisableSshParsing, DisableRdpParsing,
                  DisableInboundConnectionFiltering, ExclusionPath |
    Format-List

Write-Head "DEFENDER SERVICES"
Get-Service WinDefend, WdNisSvc -ErrorAction SilentlyContinue |
    Format-Table Name, Status, StartType -AutoSize

Write-Head "DEFENDER PROCESSES"
$procs = Get-Process MsMpEng, NisSrv -ErrorAction SilentlyContinue
if ($procs) {
    $procs | Select-Object ProcessName, Id, CPU, @{n='WorkingSetMB';e={[math]::Round($_.WorkingSet64/1MB,1)}} |
        Format-Table -AutoSize
} else {
    Write-Host "  (no Defender processes running)"
}

Write-Host ""
Write-Host "NOTE: MsMpEng.exe may still be listed even with scanning/parsing disabled." -ForegroundColor DarkGray
Write-Host "      Judge the test by the CONFIGURATION values above, not by whether the process exists." -ForegroundColor DarkGray
Write-Host ""
Write-Host "DONE." -ForegroundColor Green
