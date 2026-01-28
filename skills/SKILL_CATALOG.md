# TazoSploit Skills Catalog

Welcome to the TazoSploit Skills Marketplace! This catalog contains all available skills for professional penetration testing.

## Overview

Skills are self-contained modules that provide specific pentest capabilities. Each skill includes:
- **Documentation** (SKILL.md)
- **Tools configuration** (tools.yaml)
- **Implementation** (main.py)
- **Dependencies** (requirements.txt)

## Browse by Category

### 🔍 Reconnaissance

#### subdomain_skill
**Description:** Comprehensive subdomain enumeration
- **Tools:** subfinder, amass, dnsx
- **MITRE ATT&CK:** T1018
- **Downloads:** 700
- **Rating:** ⭐ 4.7/5

Use for: Discovering all subdomains for a target domain

#### recon_skill
**Description:** Comprehensive reconnaissance automation
- **Tools:** theHarvester, whois, dnsrecon
- **MITRE ATT&CK:** T1018, T1016
- **Downloads:** 900
- **Rating:** ⭐ 4.8/5

Use for: General OSINT and discovery operations

---

### 📡 Scanning

#### nmap_skill
**Description:** Advanced network scanning and service detection
- **Tools:** nmap
- **MITRE ATT&CK:** T1046
- **Downloads:** 1,000
- **Rating:** ⭐ 5.0/5

Use for: Port scanning, service detection, OS fingerprinting

#### nuclei_skill
**Description:** Fast vulnerability scanner with customizable templates
- **Tools:** nuclei
- **MITRE ATT&CK:** T1190, T1195
- **Downloads:** 850
- **Rating:** ⭐ 4.8/5

Use for: Quick vulnerability scanning with template-based detection

#### web_scan_skill
**Description:** Web application vulnerability scanner
- **Tools:** nikto, wpscan, dirsearch
- **MITRE ATT&CK:** T1190
- **Downloads:** 650
- **Rating:** ⭐ 4.6/5

Use for: Web vulnerability scanning and directory enumeration

#### burp_skill
**Description:** Burp Suite automation and API integration
- **Tools:** burpsuite
- **MITRE ATT&CK:** T1190
- **Downloads:** 500
- **Rating:** ⭐ 4.5/5

Use for: Professional web security testing with Burp Suite

---

### 💥 Exploitation

#### metasploit_skill
**Description:** Advanced exploitation framework with hundreds of exploits
- **Tools:** msfconsole, msfvenom
- **MITRE ATT&CK:** T1210, T1068
- **Downloads:** 1,200
- **Rating:** ⭐ 4.9/5

Use for: Exploitation, payload generation, post-exploitation

#### xss_skill
**Description:** Cross-site scripting detection and exploitation
- **Tools:** xsser, dalfox
- **MITRE ATT&CK:** T1059
- **Downloads:** 450
- **Rating:** ⭐ 4.4/5

Use for: XSS vulnerability detection and exploitation

#### sql_injection_skill
**Description:** SQL injection vulnerability detection and exploitation
- **Tools:** sqlmap, bbqsql
- **MITRE ATT&CK:** T1190
- **Downloads:** 950
- **Rating:** ⭐ 4.8/5

Use for: SQL injection testing and exploitation

---

### 🚀 Privilege Escalation

#### privesc_skill
**Description:** Automated privilege escalation checks
- **Tools:** linpeas, winpeas, linuxprivchecker
- **MITRE ATT&CK:** T1068, T1548
- **Downloads:** 1,100
- **Rating:** ⭐ 4.9/5

Use for: Linux and Windows privilege escalation enumeration

---

### 🔐 Credential Access

#### credential_access_skill
**Description:** Credential extraction and dumping
- **Tools:** mimikatz, hashcat, john
- **MITRE ATT&CK:** T1003, T1555
- **Downloads:** 750
- **Rating:** ⭐ 4.7/5

Use for: Dumping credentials, cracking hashes

---

### 🌐 Lateral Movement

#### lateral_skill
**Description:** Network lateral movement techniques
- **Tools:** crackmapexec, psexec, smbclient
- **MITRE ATT&CK:** T1021, T1077
- **Downloads:** 550
- **Rating:** ⭐ 4.6/5

Use for: Moving between systems in a network

---

### 📊 Reporting

#### report_skill
**Description:** Professional pentest report generation
- **Tools:** pandoc, wkhtmltopdf
- **Downloads:** 800
- **Rating:** ⭐ 4.7/5

Use for: Generating professional pentest reports

---

### 👁️ Monitoring

#### monitor_skill
**Description:** Continuous security monitoring and alerting
- **Tools:** prometheus, grafana
- **Downloads:** 400
- **Rating:** ⭐ 4.5/5

Use for: Continuous monitoring and alerting

---

## Quick Start

### Install a Skill
```bash
tazos skills install nmap_skill
tazos skills install metasploit_skill
tazos skills install "Nmap Scanner"
```

### List All Skills
```bash
tazos skills list
tazos skills list --category scanning
tazos skills list --installed-only
```

### Search Skills
```bash
tazos skills search web
tazos skills search sql
tazos skills search privilege
```

### Get Skill Information
```bash
tazos skills info nmap_skill
tazos skills info "Nmap Scanner"
```

### Create Custom Skill
```bash
tazos skills create "Custom Exploit" \
  --description "My custom exploit framework" \
  --category exploitation \
  --author "My Name"
```

### Remove a Skill
```bash
tazos skills remove nmap_skill
```

## Skill Development

### Creating Custom Skills

1. **Use the Skill Template:**
   ```bash
   tazos skills create "My Skill" \
     --description "Skill description" \
     --category custom
   ```

2. **Edit the generated files:**
   - `SKILL.md` - Documentation
   - `tools.yaml` - Tool configurations
   - `main.py` - Implementation
   - `requirements.txt` - Dependencies

3. **Test your skill:**
   ```bash
   python3 -m skills.<skill_name>.main
   ```

### Skill Structure

```
skill-name/
├── SKILL.md           # Documentation (required)
├── tools.yaml         # Tool configurations (optional)
├── main.py           # Implementation (required)
├── __init__.py       # Package init (generated)
├── requirements.txt  # Dependencies (optional)
└── examples/         # Usage examples (optional)
```

## Categories

- **reconnaissance** - Discovery and OSINT
- **scanning** - Port, service, vulnerability scanning
- **exploitation** - Exploiting vulnerabilities
- **privilege_escalation** - Escalating privileges
- **lateral_movement** - Moving through networks
- **credential_access** - Accessing credentials
- **persistence** - Maintaining access
- **defense_evasion** - Evading detection
- **exfiltration** - Data exfiltration
- **command_control** - C2 operations
- **impact** - System impact operations
- **reporting** - Report generation
- **monitoring** - Continuous monitoring
- **custom** - Custom skills

## MITRE ATT&CK Integration

All skills are mapped to MITRE ATT&CK techniques for:

- **T1018** - Remote System Discovery
- **T1016** - System Network Configuration Discovery
- **T1046** - Network Service Scanning
- **T1190** - Exploit Public-Facing Application
- **T1195** - Supply Chain Compromise
- **T1210** - Exploitation of Remote Services
- **T1068** - Exploitation for Privilege Escalation
- **T1548** - Abuse Elevation Control Mechanism
- **T1021** - Remote Services
- **T1077** - Windows Admin Shares
- **T1003** - OS Credential Dumping
- **T1555** - Credentials from Password Stores
- **T1059** - Command and Scripting Interpreter

## Contributing

Want to contribute a skill? Follow these steps:

1. Create your skill using the template
2. Test thoroughly
3. Submit to the marketplace
4. Get reviewed and published

## Support

For help with skills:
- Check the skill's SKILL.md
- Review examples in `examples/`
- Open an issue on GitHub

## Statistics

- **Total Skills:** 14
- **Categories:** 14
- **Total Downloads:** 9,700+
- **Average Rating:** 4.7/5

---

*TazoSploit Skills Marketplace v1.0.0*
