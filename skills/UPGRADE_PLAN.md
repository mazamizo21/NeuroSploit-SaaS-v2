# TazoSploit Skills Upgrade Plan
**Created:** 2026-02-11
**Goal:** Every phase of the kill chain at 🔥 quality — matching defense_evasion (3,854 lines, 75 MITRE, 20 references)

## Quality Bar (per phase skill)
- SKILL.md: 150-350 lines, actionable playbook with decision trees
- skill.yaml: Full MITRE technique coverage for the tactic
- tools.yaml: All relevant Kali tools with real commands (10-25 tools)
- references/: 5-15 deep-dive files, 80-300 lines each
- toolcards/: Every tool referenced should have a non-TBD toolcard

## Kill Chain Status & Plan

### 1. Discovery (TA0007) — 🔴 MISSING → BUILD FROM SCRATCH
**Priority: CRITICAL — this is what happens RIGHT AFTER getting a shell**

MITRE Techniques needed:
- T1087 Account Discovery (local, domain, email, cloud)
- T1482 Domain Trust Discovery
- T1083 File and Directory Discovery
- T1135 Network Share Discovery
- T1040 Network Sniffing
- T1201 Password Policy Discovery
- T1120 Peripheral Device Discovery
- T1069 Permission Groups Discovery
- T1057 Process Discovery
- T1012 Query Registry
- T1018 Remote System Discovery
- T1518 Software Discovery (incl security software)
- T1082 System Information Discovery
- T1016 System Network Configuration Discovery
- T1049 System Network Connections Discovery
- T1033 System Owner/User Discovery
- T1007 System Service Discovery
- T1124 System Time Discovery
- T1497 Virtualization/Sandbox Detection

Tools: enum4linux, ldapsearch, net commands, wmic, PowerView, BloodHound, 
       ADRecon, seatbelt, winPEAS, linPEAS, pspy, ss/netstat, arp, nbtstat

References needed:
- linux_enumeration.md (system, users, network, processes, cron, SUID)
- windows_enumeration.md (whoami /all, net user/group, systeminfo, reg query)
- active_directory_enumeration.md (PowerView, BloodHound, ldapsearch, RPCClient)
- network_discovery.md (ARP scan, internal nmap, share enum, service mapping)
- sensitive_file_discovery.md (config files, credentials, databases, SSH keys, browser data)
- cloud_enumeration.md (AWS metadata, Azure IMDS, GCP metadata)

### 2. Privilege Escalation (TA0004) — 🟡 EXISTS BUT THIN (45 lines) → MAJOR UPGRADE
**Priority: CRITICAL — can't do post-exploit without elevated access**

MITRE Techniques needed:
- T1548 Abuse Elevation Control (UAC bypass, SUID, sudo)
- T1134 Access Token Manipulation
- T1068 Exploitation for Privilege Escalation (kernel exploits)
- T1484 Domain Policy Modification
- T1611 Escape to Host (container breakout)
- T1546 Event Triggered Execution
- T1068 Exploit vuln for privesc

Tools: linpeas, winpeas, linux-exploit-suggester, windows-exploit-suggester,
       pspy, GTFOBins, PEASS-ng, PrintSpoofer, JuicyPotato, GodPotato,
       BeRoot, PowerUp, SharpUp, Seatbelt

References needed:
- linux_privesc.md (SUID, sudo, capabilities, cron, PATH, kernel, docker escape, NFS)
- windows_privesc.md (token privs, service misconfig, unquoted paths, DLL hijack, AlwaysInstallElevated, potato attacks, PrintNightmare)
- kernel_exploits.md (dirty pipe, dirty cow, pwnkit, eternal blue local, windows kernel)
- container_escape.md (docker socket, privileged container, cap_sys_admin, cgroup escape)
- ad_privesc.md (Kerberoasting, AS-REP roasting, DCSync, RBCD, shadow credentials)

### 3. Collection (TA0009) — 🔴 MISSING → BUILD FROM SCRATCH
**Priority: HIGH — what you grab before exfil**

MITRE Techniques needed:
- T1560 Archive Collected Data (zip, tar, 7z, encrypted)
- T1123 Audio Capture
- T1119 Automated Collection (scripts, scheduled)
- T1185 Browser Session Hijacking
- T1115 Clipboard Data
- T1530 Data from Cloud Storage
- T1213 Data from Information Repositories (SharePoint, Confluence, wiki)
- T1005 Data from Local System
- T1039 Data from Network Shared Drive
- T1025 Data from Removable Media
- T1074 Data Staged (local, remote)
- T1114 Email Collection (local, remote, forwarding rules)
- T1056 Input Capture (keylogging, web portal capture)
- T1113 Screen Capture
- T1557 Adversary-in-the-Middle

Tools: mimikatz (credential dump), lazagne, secretsdump, keyscan (msf),
       screenshot (msf), file scraper scripts, tar/7z/zip,
       Responder, bettercap, mitmproxy

References needed:
- data_harvesting.md (find sensitive files, databases, config files, SSH keys, browser data)
- credential_harvesting.md (lazagne, mimikatz, secretsdump, browser creds, wifi passwords)
- screen_keylog.md (Meterpreter keyscan/screenshot, xdotool, xwd, import)
- email_collection.md (Exchange, Gmail, IMAP, PST parsing, OWA)
- data_staging.md (compress, encrypt, stage for exfil, split large files)

### 4. Exfiltration (TA0010) — 🟡 EXISTS BUT THIN (53 lines) → MAJOR UPGRADE
**Priority: HIGH — getting data out is the mission objective**

MITRE Techniques needed:
- T1020 Automated Exfiltration
- T1030 Data Transfer Size Limits (chunking)
- T1048 Exfiltration Over Alternative Protocol (DNS, ICMP, SMTP)
- T1041 Exfiltration Over C2 Channel
- T1011 Exfiltration Over Other Network Medium
- T1052 Exfiltration Over Physical Medium
- T1567 Exfiltration Over Web Service (cloud storage, code repos, paste sites)
- T1029 Scheduled Transfer
- T1537 Transfer Data to Cloud Account

Tools: dnscat2, iodine, curl, scp, sftp, rclone, aws s3, 
       base64, xxd, steghide, exfiltration scripts, ncat, socat

References needed:
- dns_exfiltration.md (dnscat2, iodine, manual DNS TXT encoding, xxd+nslookup)
- https_exfiltration.md (curl, wget, rclone to cloud, code repos, paste sites)
- covert_channels.md (ICMP, steganography, timing channels, protocol abuse)
- data_packaging.md (compression, encryption, splitting, encoding for transport)
- exfil_detection_avoidance.md (rate limiting, mimicking normal traffic, timing)

### 5. Credential Access (TA0006) — 🟡 56 lines → UPGRADE
**Priority: MEDIUM — good tool coverage but thin methodology**

Add references:
- windows_credential_dump.md (LSASS dump, SAM/SYSTEM, DPAPI, vault, WiFi, browser)
- linux_credential_hunt.md (/etc/shadow, .bash_history, SSH keys, config files, memory)
- ad_credential_attacks.md (Kerberoasting, AS-REP, DCSync, silver ticket, password spray)
- web_credential_attacks.md (SQL dump users, session hijack, token theft, OAuth abuse)
- password_cracking.md (hashcat rules, john, wordlists, rainbow tables, cloud cracking)

### 6. Lateral Movement (TA0008) — 🟡 50 lines → UPGRADE
**Priority: MEDIUM — exists but needs depth**

Add references:
- windows_lateral.md (PsExec, WMI, WinRM, RDP, DCOM, SCM, MMC)
- linux_lateral.md (SSH, ansible, puppet, salt, proxychains)
- ad_lateral.md (Pass-the-Hash, Pass-the-Ticket, Overpass-the-Hash, NTLM relay)
- pivoting.md (SSH tunnels, chisel, ligolo-ng, socat, meterpreter routes)
- cloud_lateral.md (role assumption, metadata service, cross-account)

### 7. Exploitation (TA0001) — 🟡 59 lines → ENHANCE
**Priority: MEDIUM — works but could be stronger**

Add references:
- web_exploitation.md (SQLi, XSS, SSRF, XXE, deserialization, file upload, IDOR, SSTI)
- network_exploitation.md (EternalBlue, BlueKeep, SMBGhost, service-specific CVEs)
- binary_exploitation.md (buffer overflow, ROP, format string — for CTF/lab targets)
- exploit_chaining.md (combining vulns for higher impact, pivoting from web to shell)

### 8. Reconnaissance (TA0043) — 🟡 50 lines → ENHANCE
**Priority: LOW — already good tool coverage, just needs deeper methodology**

Add references:
- osint_methodology.md (Google dorking, Shodan, Censys, crt.sh, LinkedIn, GitHub)
- web_recon.md (content discovery, parameter mining, API enumeration, JS analysis)
- infrastructure_mapping.md (DNS zone transfer, subdomain brute, vhost discovery, CDN bypass)

### 9. Impact (TA0040) — 🔴 MISSING → BUILD
**Priority: LOW — important for completeness but less common in pentests**

MITRE Techniques:
- T1485 Data Destruction
- T1486 Data Encrypted for Impact (ransomware simulation)
- T1491 Defacement (web)
- T1561 Disk Wipe
- T1499 Endpoint Denial of Service
- T1496 Resource Hijacking (crypto mining)
- T1489 Service Stop

Tools: dd, shred, openssl, curl, stress, hping3

References needed:
- ransomware_simulation.md (safe demo: encrypt test files, leave ransom note)
- dos_simulation.md (resource exhaustion testing, controlled)
- defacement_simulation.md (web page modification proof)

## Execution Order
1. **Wave 1 (NOW):** Discovery + Privilege Escalation (critical gaps)
2. **Wave 2 (NOW):** Collection + Exfiltration (complete the data pipeline)
3. **Wave 3 (NOW):** Credential Access + Lateral Movement (depth upgrades)
4. **Wave 4 (NOW):** Exploitation + Recon enhancements
5. **Wave 5 (NOW):** Impact (completeness)

## Done Criteria
- [ ] Every phase has 100+ lines in SKILL.md
- [ ] Every phase has 5+ reference files
- [ ] Every phase has 10+ tools in tools.yaml
- [ ] All toolcards referenced are non-TBD
- [ ] Skill catalog loads clean (python3 verification)
- [ ] Total MITRE coverage: 200+ unique technique IDs
- [ ] Guard patterns updated in dynamic_agent.py for any new restricted techniques
