# disable-windows-defender

PowerShell-verktyg för att tillfälligt stänga av Microsoft Defenders skanning och
nätverksinspektion på en **isolerad** GigE Vision-kameravärd, mäta paketförlust utan
Defenders inspektion i vägen, och sedan återställa allt.

> ⚠️ **Endast för en isolerad, dedikerad maskin.** Att stänga av Defender-inspektion på en
> internetansluten dator är ett verkligt säkerhetsbeslut. Kontrollera att det är tillåtet
> enligt gällande IT-policy innan du kör det.

Verktyget använder **endast dokumenterade, Microsoft-stödda `Set-MpPreference`-switchar**.
Det rör *inte* Defenders tjänster/drivrutiner (osupporterat på klienter) och försöker *inte*
kringgå Tamper Protection.

## Kör direkt (utan att ladda ner)

Öppna **PowerShell som administratör** och klistra in:

**Stäng av inspektion (inför testet):**
```powershell
irm https://raw.githubusercontent.com/Carlboms-Data-AB/disable-windows-defender/main/defender-perf-test.ps1 | iex
```

**Återställ allt (efter testet):**
```powershell
irm https://raw.githubusercontent.com/Carlboms-Data-AB/disable-windows-defender/main/restore-defender.ps1 | iex
```

> `irm` = `Invoke-RestMethod`, `iex` = `Invoke-Expression`. PowerShell måste köras
> **förhöjt (som administratör)** — annars kan inte `Set-MpPreference` skriva inställningarna.

## Alternativ: ladda ner och kör som fil

```powershell
# Stäng av
powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1

# Stäng av + exkludera hela C:\ från filskanning (valfritt)
powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1 -ExcludeSystemDrive

# Återställ (samma som restore-skriptet)
powershell -ExecutionPolicy Bypass -File .\defender-perf-test.ps1 -Revert
```

## Filer

| Fil | Beskrivning |
|-----|-------------|
| `defender-perf-test.ps1` | Stänger av realtidsskanning, Network Protection och alla nätverksparsrar (UDP-datagram, TLS, HTTP, DNS, FTP, SMTP, SSH, RDP, inbound filtering). Har `-Revert` och `-ExcludeSystemDrive`. |
| `restore-defender.ps1` | Fristående återställning — slår på allt igen och tar bort en ev. `C:\`-exkludering. |

## Så tolkar du resultatet

Efter körning: titta på **CONFIGURATION**-blocket i utskriften, inte på om `MsMpEng.exe`
fortfarande syns i Task Manager. Det du vill se är:

```
EnableNetworkProtection   = Disabled
DisableDatagramProcessing = True     # UDP-inspektionen avstängd
DisableTlsParsing         = True
DisableHttpParsing        = True
...
```

Är paketförlusten oförändrad efter det har du i praktiken eliminerat Defenders
nätverksinspektion som huvudorsak — även om `MsMpEng.exe` fortfarande ligger kvar som process.

## Om Tamper Protection

Är Tamper Protection **på** (standard på Windows 11 Pro) kan ändringar av realtidsskydd,
beteendeövervakning, IOAV och `C:\`-exkludering *se ut* att lyckas men ändå ignoreras.
Nätverksparser-switcharna försöks ändå. Vill du att antivirus-inställningarna verkligen ska
ta effekt: stäng av Tamper Protection manuellt i **Windows Security → Virus- och hotskydd →
Hantera inställningar**. Ingen lokal, stödd metod kan stänga av Tamper Protection via skript
på en fristående maskin.
