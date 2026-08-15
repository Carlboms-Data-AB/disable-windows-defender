# disable-windows-defender

PowerShell tooling to temporarily disable Microsoft Defender's scanning and network
inspection on an **isolated** machine, measure packet loss with Defender's inspection out of
the way, and then restore everything.

> ⚠️ **For an isolated, dedicated machine only.** Disabling Defender inspection on an
> internet-facing machine is a real security decision. Confirm it is allowed by the
> applicable IT policy before running it.

The tooling uses **only documented, Microsoft-supported `Set-MpPreference` switches**. It does
*not* touch Defender's services/drivers (unsupported on clients) and does *not* attempt to
bypass Tamper Protection.

## Run directly (no download)

Open **PowerShell as Administrator** and paste:

**Disable inspection (before the test):**
```powershell
irm https://raw.githubusercontent.com/Carlboms-Data-AB/disable-windows-defender/main/defender-perf-test.ps1 | iex
```

**Restore everything (after the test):**
```powershell
irm https://raw.githubusercontent.com/Carlboms-Data-AB/disable-windows-defender/main/restore-defender.ps1 | iex
```

> `irm` = `Invoke-RestMethod`, `iex` = `Invoke-Expression`. PowerShell must run **elevated
> (as Administrator)** — otherwise `Set-MpPreference` cannot write the settings.

## Alternative: download and run as a file

```powershell
# Disable
powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1

# Disable + exclude the whole C:\ from file scanning (optional)
powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1 -ExcludeSystemDrive

# Restore (same as the restore script)
powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1 -Revert
```

## Files

| File | Description |
|------|-------------|
| `defender-perf-test.ps1` | Disables realtime scanning, Network Protection, and all network parsers (UDP datagram, TLS, HTTP, DNS, FTP, SMTP, SSH, RDP, inbound filtering). Supports `-Revert` and `-ExcludeSystemDrive`. |
| `restore-defender.ps1` | Standalone restore — turns everything back on and removes any `C:\` exclusion. |

## Reading the result

After running, look at the **CONFIGURATION** block in the output, not at whether
`MsMpEng.exe` still appears in Task Manager. What you want to see is:

```
EnableNetworkProtection   = Disabled
DisableDatagramProcessing = True     # UDP inspection off
DisableTlsParsing         = True
DisableHttpParsing        = True
...
```

If packet loss is unchanged after that, you have effectively ruled out Defender's network
inspection as the primary cause — even though `MsMpEng.exe` may still be running as a process.

## Verify (also after a reboot)

The `Set-MpPreference` settings persist across reboots, so you do not need to re-run the
script after every boot. To confirm the state is still in effect, run:

```powershell
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, NISEnabled, IsTamperProtected
Get-MpPreference   | Select-Object DisableDatagramProcessing, EnableNetworkProtection
```

You want to see `RealTimeProtectionEnabled = False` and `DisableDatagramProcessing = True`
(and `EnableNetworkProtection = 0`, i.e. Disabled). If Windows has turned realtime protection
back on after a Defender platform/signature update, just run `defender-perf-test.ps1` again.

## About Tamper Protection

If Tamper Protection is **on** (the default on Windows 11 Pro), changes to realtime
protection, behavior monitoring, IOAV and the `C:\` exclusion may *appear* to succeed but
still be ignored. The network-parser switches are attempted regardless. To make the antivirus
settings actually take effect, turn Tamper Protection off manually in **Windows Security →
Virus & threat protection → Manage settings**. No local, supported method can disable Tamper
Protection via script on a standalone machine.
