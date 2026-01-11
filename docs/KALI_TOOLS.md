# Kali Linux Tool Suite - 150+ Pentest Tools

## Tool Categories for MITRE ATT&CK Coverage

### 1. RECONNAISSANCE (25 tools)

#### Network Scanning
- `nmap` - Network mapper, port scanning, service detection
- `masscan` - Fast TCP port scanner
- `zmap` - Internet-wide scanner
- `unicornscan` - Asynchronous TCP/UDP scanner

#### DNS Enumeration
- `dnsrecon` - DNS enumeration
- `dnsenum` - DNS information gathering
- `fierce` - DNS reconnaissance tool
- `dnsmap` - DNS network mapper

#### Subdomain Discovery
- `subfinder` - Subdomain discovery
- `amass` - Attack surface mapping
- `sublist3r` - Subdomain enumeration
- `assetfinder` - Find domains and subdomains

#### OSINT
- `theHarvester` - Email, subdomain, IP harvester
- `recon-ng` - Web reconnaissance framework
- `maltego` - OSINT and graphical link analysis
- `spiderfoot` - OSINT automation

#### Web Reconnaissance
- `whatweb` - Web scanner
- `wafw00f` - WAF fingerprinting
- `httprobe` - HTTP/HTTPS probe
- `httpx` - Fast HTTP toolkit

#### Information Gathering
- `whois` - Domain registration lookup
- `dmitry` - Deepmagic information gathering
- `netdiscover` - Network address discovery
- `arp-scan` - ARP scanner
- `p0f` - Passive OS fingerprinting

---

### 2. VULNERABILITY SCANNING (20 tools)

#### Web Vulnerability Scanners
- `nikto` - Web server scanner
- `nuclei` - Template-based vulnerability scanner
- `wpscan` - WordPress vulnerability scanner
- `joomscan` - Joomla vulnerability scanner
- `droopescan` - CMS scanner (Drupal, Joomla, etc.)

#### Network Vulnerability Scanners
- `openvas` - Open vulnerability assessment
- `nessus` - Vulnerability scanner (if licensed)
- `lynis` - Security auditing tool

#### Application Scanners
- `sqlmap` - SQL injection tool
- `commix` - Command injection exploiter
- `xsser` - XSS vulnerability scanner
- `dalfox` - XSS scanning and analysis

#### SSL/TLS Testing
- `sslscan` - SSL/TLS scanner
- `testssl.sh` - SSL/TLS testing
- `sslyze` - SSL/TLS configuration analyzer

#### Fuzzing
- `wfuzz` - Web fuzzer
- `ffuf` - Fast web fuzzer
- `gobuster` - Directory/file brute-forcer
- `dirb` - Web content scanner
- `dirbuster` - Directory brute force

---

### 3. EXPLOITATION (30 tools)

#### Frameworks
- `metasploit-framework` - Exploitation framework
- `beef-xss` - Browser exploitation framework
- `empire` - Post-exploitation framework
- `covenant` - .NET C2 framework

#### Web Exploitation
- `burpsuite` - Web security testing
- `zaproxy` - OWASP ZAP proxy
- `sqlmap` - SQL injection automation
- `nosqlmap` - NoSQL injection

#### Network Exploitation
- `responder` - LLMNR/NBT-NS poisoner
- `bettercap` - Network attack tool
- `ettercap` - MITM attacks
- `arpspoof` - ARP spoofing

#### Exploit Tools
- `searchsploit` - Exploit database search
- `exploitdb` - Exploit database
- `msfvenom` - Payload generator
- `shellter` - Shellcode injection

#### Wireless
- `aircrack-ng` - WiFi security auditing
- `wifite` - Automated WiFi auditing
- `reaver` - WPS brute force
- `fern-wifi-cracker` - Wireless auditing

#### Password Attacks
- `hydra` - Network login cracker
- `medusa` - Parallel password cracker
- `ncrack` - Network authentication cracker
- `crowbar` - Brute force tool
- `patator` - Multi-purpose brute-forcer

#### Payload Generation
- `msfvenom` - Metasploit payload generator
- `veil` - Payload generator (evasion)
- `unicorn` - PowerShell downgrade attack

---

### 4. POST-EXPLOITATION (25 tools)

#### Privilege Escalation
- `linpeas` - Linux privilege escalation
- `winpeas` - Windows privilege escalation
- `linux-exploit-suggester` - Linux kernel exploits
- `windows-exploit-suggester` - Windows exploits
- `beroot` - Privilege escalation checks
- `suid3num` - SUID enumeration

#### Credential Dumping
- `mimikatz` - Windows credential extraction
- `lazagne` - Password recovery
- `secretsdump.py` - Impacket secrets dump
- `pypykatz` - Mimikatz in Python
- `lsassy` - Remote lsass dumping

#### Lateral Movement (Impacket Suite)
- `psexec.py` - Remote execution
- `smbexec.py` - SMB execution
- `wmiexec.py` - WMI execution
- `atexec.py` - Task scheduler execution
- `dcomexec.py` - DCOM execution

#### Remote Access
- `evil-winrm` - WinRM shell
- `crackmapexec` - Network pentesting
- `smbclient` - SMB client
- `rpcclient` - RPC client
- `winexe` - Remote Windows execution

#### Persistence
- `pwncat` - Post-exploitation platform
- `weevely` - Web shell
- `webacoo` - Web backdoor cookie

---

### 5. CREDENTIAL ATTACKS (15 tools)

#### Password Cracking
- `john` - John the Ripper
- `hashcat` - GPU password cracker
- `hashid` - Hash identifier
- `hash-identifier` - Hash identification

#### Wordlists
- `cewl` - Custom wordlist generator
- `crunch` - Wordlist generator
- `cupp` - Custom user password profiler

#### Credential Testing
- `hydra` - Online password cracking
- `medusa` - Parallel login brute-force
- `ncrack` - Network auth cracker
- `spray` - Password spraying

#### Hash Tools
- `hashcat-utils` - Hashcat utilities
- `hcxtools` - WiFi hash tools
- `ophcrack` - Windows password cracker
- `rainbowcrack` - Rainbow table cracker

---

### 6. FORENSICS & ANALYSIS (20 tools)

#### Memory Forensics
- `volatility` - Memory forensics
- `rekall` - Memory forensics framework

#### Disk Forensics
- `autopsy` - Digital forensics platform
- `sleuthkit` - Forensic toolkit
- `foremost` - File carving
- `scalpel` - File carving
- `photorec` - File recovery

#### Network Forensics
- `wireshark` - Network protocol analyzer
- `tcpdump` - Network traffic capture
- `tshark` - Terminal Wireshark
- `networkMiner` - Network forensic analyzer

#### Log Analysis
- `logwatch` - Log analyzer
- `lnav` - Log file navigator

#### Malware Analysis
- `yara` - Pattern matching
- `clamav` - Antivirus scanner
- `radare2` - Reverse engineering
- `ghidra` - Software reverse engineering
- `binwalk` - Firmware analysis
- `strings` - Extract strings
- `objdump` - Object file analyzer

---

### 7. REPORTING & DOCUMENTATION (10 tools)

#### Note Taking
- `cherrytree` - Hierarchical note taking
- `keepnote` - Note taking
- `dradis` - Reporting framework

#### Report Generation
- `faraday` - Collaborative pentest IDE
- `pipal` - Password analysis
- `eyewitness` - Screenshot websites

#### Evidence Collection
- `metagoofil` - Metadata extractor
- `exiftool` - Metadata reader/writer
- `pdfinfo` - PDF metadata
- `foca` - Metadata analyzer

---

### 8. UTILITY TOOLS (15 tools)

#### Networking
- `netcat` / `ncat` - Network utility
- `socat` - Multipurpose relay
- `proxychains` - Proxy chains
- `tor` - Anonymity network

#### Encoding/Decoding
- `base64` - Base64 encoding
- `xxd` - Hex dump
- `cyberchef` - Data manipulation

#### Scripting
- `python3` - Python interpreter
- `ruby` - Ruby interpreter
- `perl` - Perl interpreter
- `bash` - Shell scripting

#### File Transfer
- `wget` - HTTP download
- `curl` - Data transfer
- `scp` - Secure copy
- `rsync` - Remote sync

---

## Tool Installation Dockerfile

```dockerfile
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

# Update and install tool categories
RUN apt-get update && apt-get install -y \
    # Reconnaissance
    nmap masscan zmap unicornscan \
    dnsrecon dnsenum fierce dnsmap \
    subfinder amass sublist3r \
    theharvester recon-ng \
    whatweb wafw00f \
    whois dmitry netdiscover arp-scan p0f \
    # Vulnerability Scanning
    nikto nuclei wpscan joomscan \
    sqlmap commix \
    sslscan testssl.sh sslyze \
    wfuzz ffuf gobuster dirb dirbuster \
    # Exploitation
    metasploit-framework \
    burpsuite zaproxy \
    responder bettercap ettercap-graphical \
    searchsploit exploitdb \
    aircrack-ng wifite reaver \
    hydra medusa ncrack crowbar patator \
    # Post-Exploitation
    crackmapexec evil-winrm \
    smbclient rpcclient \
    impacket-scripts \
    # Credential Attacks
    john hashcat hashid \
    cewl crunch cupp \
    # Forensics
    volatility3 \
    autopsy sleuthkit foremost scalpel photorec \
    wireshark tcpdump tshark \
    yara clamav radare2 binwalk \
    # Utilities
    netcat-traditional ncat socat proxychains4 tor \
    python3 python3-pip ruby perl \
    wget curl openssh-client rsync \
    git vim tmux \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python tools
RUN pip3 install --break-system-packages \
    linpeas winpeas \
    pwntools impacket \
    requests beautifulsoup4 \
    scapy paramiko \
    pypykatz lsassy

# Install additional tools from GitHub
RUN git clone https://github.com/carlospolop/PEASS-ng.git /opt/PEASS-ng
RUN git clone https://github.com/AlessandroZ/LaZagne.git /opt/LaZagne
RUN git clone https://github.com/bitsadmin/wesng.git /opt/wesng

# Wordlists
RUN gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

WORKDIR /pentest
CMD ["tail", "-f", "/dev/null"]
```

## Tool Capability Matrix

| Tool | Recon | Vuln | Exploit | Post-Exp | Creds | Forensics |
|------|-------|------|---------|----------|-------|-----------|
| nmap | ✅ | ✅ | | | | |
| metasploit | | ✅ | ✅ | ✅ | ✅ | |
| sqlmap | | ✅ | ✅ | | | |
| hydra | | | ✅ | | ✅ | |
| impacket | | | ✅ | ✅ | ✅ | |
| mimikatz | | | | ✅ | ✅ | |
| linpeas | | ✅ | | ✅ | | |
| wireshark | ✅ | | | | | ✅ |
| volatility | | | | | ✅ | ✅ |
