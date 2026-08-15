<#
.SYNOPSIS
    Restore Microsoft Defender to its normal, protected state after the performance test.

.DESCRIPTION
    Re-enables every setting that defender-perf-test.ps1 can turn off: realtime/behavior/
    IOAV/script scanning, archive/email/removable/network file scanning, Network Protection,
    and all network-protocol parsers (UDP datagram, TLS, HTTP, DNS, FTP, SMTP, SSH, RDP,
    inbound filtering). Also removes the C:\ scan exclusion if present.

    Uses only documented, Microsoft-supported Set-MpPreference switches. It does not touch
    Defender services/drivers.

    Note: if Tamper Protection is ON, some antivirus settings are managed by Defender itself
    and may already be at their default (protected) values; those calls are harmless.

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
    param([hashtable]$Args, [string]$What)
    try {
        Set-MpPreference @Args -ErrorAction Stop
        Write-Host ("  [ok]   {0}" -f $What) -ForegroundColor Green
    }
    catch {
        Write-Host ("  [FAIL] {0} -> {1}" -f $What, $_.Exception.Message) -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "=== RESTORE MICROSOFT DEFENDER (re-enable protection) ===" -ForegroundColor Cyan

$status = Get-MpComputerStatus
Write-Host ""
Write-Host ("Tamper Protection : {0}" -f $status.IsTamperProtected)

# ------------------------------------------------------------
# 1. Realtime / scan engine  ($false = enabled)
# ------------------------------------------------------------
Write-Head "REALTIME / SCAN ENGINE"
Set-Pref @{ DisableRealtimeMonitoring                     = $false } "RealtimeMonitoring ON"
Set-Pref @{ DisableBehaviorMonitoring                     = $false } "BehaviorMonitoring ON"
Set-Pref @{ DisableIOAVProtection                         = $false } "IOAVProtection ON"
Set-Pref @{ DisableScriptScanning                         = $false } "ScriptScanning ON"
Set-Pref @{ DisableArchiveScanning                        = $false } "ArchiveScanning ON"
Set-Pref @{ DisableEmailScanning                          = $false } "EmailScanning ON"
Set-Pref @{ DisableRemovableDriveScanning                 = $false } "RemovableDriveScanning ON"
Set-Pref @{ DisableScanningNetworkFiles                   = $false } "ScanningNetworkFiles ON"
Set-Pref @{ DisableScanningMappedNetworkDrivesForFullScan = $false } "ScanningMappedNetworkDrives ON"

# ------------------------------------------------------------
# 2. Network Protection
# ------------------------------------------------------------
Write-Head "NETWORK PROTECTION"
Set-Pref @{ EnableNetworkProtection = "Enabled" } "EnableNetworkProtection = Enabled"

# ------------------------------------------------------------
# 3. Network protocol parsing  ($false = inspection enabled)
# ------------------------------------------------------------
Write-Head "NETWORK PROTOCOL PARSING"
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

# ------------------------------------------------------------
# 4. Remove C:\ scan exclusion if present
# ------------------------------------------------------------
Write-Head "SCAN EXCLUSION (C:\)"
$prefs = Get-MpPreference
if ($prefs.ExclusionPath -contains "C:\") {
    try { Remove-MpPreference -ExclusionPath "C:\" -ErrorAction Stop; Write-Host "  [ok]   removed C:\ exclusion" -ForegroundColor Green }
    catch { Write-Host ("  [FAIL] remove C:\ exclusion -> {0}" -f $_.Exception.Message) -ForegroundColor Yellow }
} else {
    Write-Host "  [skip] no C:\ exclusion present"
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

Write-Host ""
Write-Host "Defender restored to normal protection." -ForegroundColor Green
Write-Host "If RealTimeProtectionEnabled still shows False, run a Windows Security / signature" -ForegroundColor DarkGray
Write-Host "update, or toggle Real-time protection once in the Windows Security app." -ForegroundColor DarkGray
Write-Host ""
Write-Host "DONE." -ForegroundColor Green
