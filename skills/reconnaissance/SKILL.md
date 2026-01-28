# Reconnaissance Skill

## Overview
Systematic information gathering about target infrastructure, services, and potential vulnerabilities before exploitation.

## Methodology

### 1. Network Discovery
- Identify active hosts and network ranges
- Map network topology and services
- Identify firewalls and security controls

### 2. Port Scanning
- Comprehensive port scanning (TCP/UDP)
- Service version detection
- OS fingerprinting
- Scan for common services: HTTP/HTTPS, SSH, FTP, SMB, RDP, Database ports

### 3. Service Enumeration
- HTTP/HTTPS: Web server fingerprinting, headers, technologies
- DNS: Zone transfer, subdomain enumeration
- SMB: Share enumeration, user enumeration
- SNMP: Community string enumeration, OID enumeration
- LDAP: Directory enumeration

### 4. Web Application Recon
- Directory and file enumeration
- Technology stack identification
- WAF detection and bypass
- API endpoint discovery

### 5. Vulnerability Scanning
- Automated vulnerability scanning
- CVE detection
- Misconfiguration identification
- Outdated software detection

## MITRE ATT&CK Mappings
- T1595 - Active Scanning
- T1590 - Gather Victim Network Information
- T1592 - Gather Victim Organization Information
- T1593 - Gather Victim Host Information
- T1596 - Search Open Websites/Domains

## Tools Available
- nmap: Network mapper and port scanner
- rustscan: Fast port scanner
- masscan: High-speed port scanner
- dnsenum: DNS enumeration
- dnsrecon: DNS reconnaissance
- gobuster: Directory brute-forcing
- dirsearch: Directory and file search
- nikto: Web server scanner
- whatweb: Web technology identification
- wafw00f: WAF detection
- eyewitness: Screenshot tool
- httpx: HTTP toolkit
- subfinder: Subdomain discovery
- amass: DNS enumeration and attack surface mapping
- shodan: Internet intelligence (via API)

## Evidence Collection
1. Network scan results (nmap -oA output)
2. Service banners and versions
3. Screenshot of web applications
4. Directory listings
5. DNS records and subdomains
6. Vulnerability scan reports

## Success Criteria
- All active hosts and network ranges identified
- All open ports and services mapped
- Service versions identified
- Web application technologies cataloged
- DNS and subdomain enumeration complete
- Vulnerability scan report generated
