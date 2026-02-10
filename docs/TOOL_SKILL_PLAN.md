# Tool Skill Plan

## Goal
Create per-tool skills with advanced techniques and workflows (no duplication). Start with post-exploitation tools (lateral movement, persistence, defense evasion, forensics), then cover the remaining Kali tools.

## Conventions
- **Tool skills live in**: `skills/tool_<toolname>/`
- **Skill id**: `tool_<toolname>`
- **Avoid duplication**: If a tool already has a dedicated service skill, the tool skill references that service skill and focuses only on tool-specific advanced usage.
- **References**: Each tool skill should point to its toolcard and an `references/advanced.md` with advanced techniques from official docs.
- **Priority**: `20` (keeps tool skills available without crowding out phase/service skills).

## Doc Verification Log
- 2026-02-05: Phase 1 (post-exploit tools) advanced technique references updated and re-verified.

## Phase 1 — Post-Exploit Tool Skills (Start Here)
Scope: lateral movement, persistence, defense evasion, forensics.

Status legend: `TODO`, `IN_PROGRESS`, `DONE`

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| bloodhound | Lateral movement / AD pathing | DONE | skills/tool_bloodhound |
| sharphound | Lateral movement / AD collection | DONE | skills/tool_sharphound |
| netexec | Lateral movement / credential validation | DONE | skills/tool_netexec |
| crackmapexec | Lateral movement / credential validation | DONE | skills/tool_crackmapexec |
| impacket-scripts | Lateral movement / remote execution | DONE | skills/tool_impacket_scripts |
| evil-winrm | Lateral movement / WinRM access | DONE | skills/tool_evil_winrm |
| responder | Credential capture / lateral prep | DONE | skills/tool_responder |
| mitm6 | Credential capture / lateral prep | DONE | skills/tool_mitm6 |
| rubeus | Credential access / tickets | DONE | skills/tool_rubeus |
| mimikatz | Credential access / ticket ops | DONE | skills/tool_mimikatz |
| macchanger | Defense evasion / spoofing | DONE | skills/tool_macchanger |
| hping3 | Defense evasion / packet crafting | DONE | skills/tool_hping3 |
| autopsy | Forensics / triage | DONE | skills/tool_autopsy |
| tcpdump | Forensics / packet capture | DONE | skills/tool_tcpdump |
| wireshark | Forensics / packet analysis | DONE | skills/tool_wireshark |
| yara | Forensics / pattern scanning | DONE | skills/tool_yara |
| testdisk | Forensics / recovery | DONE | skills/tool_testdisk |

## Phase 2 — Remaining Kali Tool Skills
Scope: all other tools in `docs/KALI_TOOLS_INVENTORY.md` not listed above.

Progress tracking will be appended here in batches, each with the same status table.

### Batch 1 — Recon & Subdomain Tool Skills

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| amass | Recon / OSINT + DNS enum | DONE | skills/tool_amass |
| subfinder | Recon / passive subdomains | DONE | skills/tool_subfinder |
| assetfinder | Recon / passive subdomains | DONE | skills/tool_assetfinder |
| sublist3r | Recon / OSINT subdomains | DONE | skills/tool_sublist3r |
| theharvester | Recon / OSINT collection | DONE | skills/tool_theharvester |
| recon-ng | Recon / OSINT framework | DONE | skills/tool_recon_ng |
| masscan | Scan / fast port discovery | DONE | skills/tool_masscan |
| nmap | Scan / service enumeration | DONE | skills/tool_nmap |

### Batch 2 — Web Content Discovery & Fuzzing Tool Skills

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| gobuster | Scan / content discovery | DONE | skills/tool_gobuster |
| ffuf | Scan / fuzzing | DONE | skills/tool_ffuf |
| feroxbuster | Scan / recursive discovery | DONE | skills/tool_feroxbuster |
| dirsearch | Scan / path discovery | DONE | skills/tool_dirsearch |
| dirb | Scan / path discovery | DONE | skills/tool_dirb |
| wfuzz | Scan / fuzzing | DONE | skills/tool_wfuzz |
| nikto | Scan / web vuln checks | DONE | skills/tool_nikto |
| whatweb | Recon / tech fingerprinting | DONE | skills/tool_whatweb |

### Batch 3 — DNS + SMTP + SNMP Tool Skills

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| dnsrecon | Recon / DNS enum | DONE | skills/tool_dnsrecon |
| dnsenum | Recon / DNS enum | DONE | skills/tool_dnsenum |
| fierce | Recon / DNS recon | DONE | skills/tool_fierce |
| dmitry | Recon / OSINT | DONE | skills/tool_dmitry |
| dnschef | Post / DNS spoofing | DONE | skills/tool_dnschef |
| smtp-user-enum | Recon / SMTP user enum | DONE | skills/tool_smtp_user_enum |
| onesixtyone | Scan / SNMP community | DONE | skills/tool_onesixtyone |
| snmpwalk | Scan / SNMP enum | DONE | skills/tool_snmpwalk |
| snmp-check | Scan / SNMP enum | DONE | skills/tool_snmp_check |

### Batch 4 — Wireless Tool Skills

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| aircrack-ng | Scan / capture + audit | DONE | skills/tool_aircrack_ng |
| wifite | Scan / automated audit | DONE | skills/tool_wifite |
| wifiphisher | Exploit / rogue AP | DONE | skills/tool_wifiphisher |
| wifipumpkin3 | Exploit / rogue AP | DONE | skills/tool_wifipumpkin3 |
| fern-wifi-cracker | Exploit / GUI audit | DONE | skills/tool_fern_wifi_cracker |
| reaver | Exploit / WPS | DONE | skills/tool_reaver |
| bully | Exploit / WPS | DONE | skills/tool_bully |
| cowpatty | Exploit / WPA cracking | DONE | skills/tool_cowpatty |

### Batch 5 — Credential + SQLi Tool Skills

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| hydra | Credential / brute-force | DONE | skills/tool_hydra |
| medusa | Credential / brute-force | DONE | skills/tool_medusa |
| cewl | Recon / wordlist generation | DONE | skills/tool_cewl |
| crunch | Recon / wordlist generation | DONE | skills/tool_crunch |
| john | Credential / cracking | DONE | skills/tool_john |
| hashcat | Credential / cracking | DONE | skills/tool_hashcat |
| hash-identifier | Analysis / hash ID | DONE | skills/tool_hash_identifier |
| sqlmap | Exploit / SQLi automation | DONE | skills/tool_sqlmap |
| sqlninja | Exploit / SQL Server SQLi | DONE | skills/tool_sqlninja |
| sqlsus | Exploit / MySQL SQLi | DONE | skills/tool_sqlsus |

### Batch 6 — Network Utilities & MITM Tool Skills

| Tool | Primary Phase | Status | Skill Path |
|---|---|---|---|
| netcat | Post / connectivity & transfer | DONE | skills/tool_netcat |
| socat | Post / relay & forwarding | DONE | skills/tool_socat |
| proxychains | Post / proxy routing | DONE | skills/tool_proxychains |
| tor | Post / anonymized routing | DONE | skills/tool_tor |
| ettercap | Post / MITM | DONE | skills/tool_ettercap |
| bettercap | Post / MITM | DONE | skills/tool_bettercap |
| arp-scan | Recon / L2 discovery | DONE | skills/tool_arp_scan |
| arping | Recon / L2 validation | DONE | skills/tool_arping |
| netdiscover | Recon / L2 discovery | DONE | skills/tool_netdiscover |
