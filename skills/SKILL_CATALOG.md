# Skill Catalog

Auto-generated catalog of available skills.

## Credential Access (`credential_access`)

- Category: `credential_access`
- Description: Identify, validate, and document credentials discovered during testing.
- MITRE: T1110, T1555
- Tools: mimikatz, hashcat, john, hashid, cewl, crunch, fcrackzip, pdfcrack, secretsdump, laZagne, parse_hashcat_show

## Defense Evasion (`defense_evasion`)

- Category: `defense_evasion`
- Description: Assess evasion risks without disabling defenses.
- MITRE: T1562, T1070
- Tools: system_tools, lnav, logwatch, tcpdump, tshark, lynis, tiger, summarize_defense_controls

## Example Skill (`example_skill`)

- Category: `custom`
- Description: Example skill skeleton for new skills.
- Tools: example_parser
- Tags: example, template

## Data Access Validation (`exfiltration`)

- Category: `exfiltration`
- Description: Validate data exposure with minimal collection to prove impact.
- MITRE: T1005
- Tools: system_tools, redact_samples, smbclient, psql, mysql, mongosh, redis-cli, scp, rsync, socat

## Exploitation (`exploitation`)

- Category: `exploitation`
- Description: Validate exploitability with minimal, controlled proof of impact.
- MITRE: T1190, T1203
- Tools: metasploit, sqlmap, commix

## Forensics (`forensics`)

- Category: `analysis`
- Description: Post-exploitation evidence triage for disk and memory artifacts.
- Tools: autopsy, sleuthkit, volatility, binwalk, foremost, scalpel, photorec, testdisk, exiftool
- Tags: forensics, triage, artifacts

## Lateral Movement (`lateral_movement`)

- Category: `lateral_movement`
- Description: Validate controlled lateral movement within approved scope.
- MITRE: T1021
- Tools: crackmapexec, impacket-psexec, impacket-wmiexec, impacket-smbexec, impacket-secretsdump, impacket-getST, impacket-ticketConverter, responder, evil-winrm, freerdp, sshpass, summarize_movement_log

## Persistence (`persistence`)

- Category: `persistence`
- Description: Assess persistence risk without leaving lasting changes.
- MITRE: T1053, T1547
- Tools: system_tools, winpeas, seatbelt, linpeas, normalize_persistence

## Privilege Escalation (`privilege_escalation`)

- Category: `privilege_escalation`
- Description: Assess and validate privilege escalation paths after access is gained.
- MITRE: T1068
- Tools: linpeas, winpeas, linux-exploit-suggester, sherlock, gtfobins, lse, pspy, summarize_peas

## Reconnaissance (`reconnaissance`)

- Category: `reconnaissance`
- Description: Systematic discovery of hosts, ports, services, and web surface area.
- MITRE: T1595, T1590, T1592, T1593, T1596
- Tools: nmap, rustscan, masscan, gobuster, dirsearch, nikto, whatweb, wafw00f, httpx, subfinder, amass, dnsenum...

## Reporting (`reporting`)

- Category: `reporting`
- Description: Produce final report with evidence and remediation.
- Tools: jq, assemble_report, merge_bundles, normalize_findings, summarize_findings, validate_bundle, check_report_readiness, check_schema, check_evidence_manifest, gate_report, summary_rollup, emit_schema...

## Reverse Engineering (`reverse_engineering`)

- Category: `analysis`
- Description: Static analysis of binaries and extraction of indicators.
- Tools: ghidra, radare2, objdump, strings, python3
- Tags: reverse_engineering, binaries, ioc

## Vulnerability Scanning (`scanning`)

- Category: `scanning`
- Description: Identify likely vulnerabilities and misconfigurations with safe, automated scans.
- MITRE: T1595, T1190
- Tools: nuclei, nikto, nmap, parse_nuclei_json

## Active Directory (`service_active_directory`)

- Category: `service`
- Description: Domain discovery and risk validation across LDAP, Kerberos, SMB, and ADCS.
- MITRE: T1069, T1087, T1018
- Tools: ldapsearch, ldapdomaindump, kerbrute, bloodhound, sharphound, certipy, certify, powerview, rubeus, netexec, crackmapexec, secretsdump...
- Tags: active_directory, ad, ldap, kerberos, smb

## API Gateway Service (`service_api_gateway`)

- Category: `service`
- Description: Service-specific enumeration for API gateways.
- Tools: httpx, sslscan, nmap, katana, kiterunner, curl, nuclei, summarize_gateway_inventory
- Tags: api_gateway, api

## Application Security Patterns (`service_app_security`)

- Category: `service`
- Description: Application security validation patterns for auth, session, access control, and input safety.
- Tools: httpx, katana, nuclei, burpsuite, arjun, ffuf, sqlmap, dalfox, headers_to_json, rate_limit_report, merge_findings, idor_log_parser...
- Tags: appsec, owasp, api

## AWS Service (`service_aws`)

- Category: `service`
- Description: Service-specific enumeration for AWS.
- Tools: awscli, prowler, scoutsuite, trivy, summarize_aws_inventory
- Tags: aws

## AZURE Service (`service_azure`)

- Category: `service`
- Description: Service-specific enumeration for AZURE.
- Tools: azure-cli, scoutsuite, trivy, summarize_azure_inventory
- Tags: azure

## CI/CD Service (`service_cicd`)

- Category: `service`
- Description: Service-specific enumeration for CI/CD platforms.
- Tools: httpx, nuclei, trivy, gitleaks, nmap, summarize_cicd_inventory
- Tags: cicd, ci, cd, pipeline

## DNS Service (`service_dns`)

- Category: `service`
- Description: Service-specific enumeration for DNS.
- Tools: dig, dnsrecon, dnsenum, amass, subfinder, parse_dig
- Tags: dns

## Docker Service (`service_docker`)

- Category: `service`
- Description: Service-specific enumeration for Docker.
- Tools: docker, docker-bench-security, trivy, nmap, summarize_docker_info
- Tags: docker

## Drupal Service (`service_drupal`)

- Category: `service`
- Description: Service-specific enumeration for Drupal.
- Tools: droopescan, nuclei, nikto, nmap, parse_droopescan
- Tags: drupal

## ELASTICSEARCH Service (`service_elasticsearch`)

- Category: `service`
- Description: Service-specific enumeration for ELASTICSEARCH.
- Tools: curl, httpx, nmap, summarize_es
- Tags: elasticsearch, es

## FTP Service (`service_ftp`)

- Category: `service`
- Description: Service-specific enumeration for FTP.
- Tools: nmap, netcat, socat, hydra, parse_ftp_nmap
- Tags: ftp

## GCP Service (`service_gcp`)

- Category: `service`
- Description: Service-specific enumeration for GCP.
- Tools: gcloud, scoutsuite, trivy, summarize_gcp_inventory
- Tags: gcp, google-cloud

## HTTP Service (`service_http`)

- Category: `service`
- Description: Service-specific enumeration for HTTP/HTTPS targets.
- Tools: httpx, whatweb, wafw00f, ffuf, gobuster, nikto, nuclei, curl, summarize_httpx
- Tags: http, https

## IMAP Service (`service_imap`)

- Category: `service`
- Description: Service-specific enumeration for IMAP.
- Tools: nmap, netcat, socat, hydra, parse_imap_nmap
- Tags: imap

## Joomla Service (`service_joomla`)

- Category: `service`
- Description: Service-specific enumeration for Joomla.
- Tools: joomscan, nuclei, nikto, nmap, parse_joomscan
- Tags: joomla

## KERBEROS Service (`service_kerberos`)

- Category: `service`
- Description: Service-specific enumeration for KERBEROS.
- Tools: kinit, klist, nmap, parse_klist
- Tags: kerberos, krb

## Kubernetes Service (`service_kubernetes`)

- Category: `service`
- Description: Service-specific enumeration for Kubernetes.
- Tools: kubectl, kube-bench, kube-hunter, nmap, summarize_k8s_inventory
- Tags: kubernetes, k8s

## LDAP Service (`service_ldap`)

- Category: `service`
- Description: Service-specific enumeration for LDAP.
- Tools: ldapsearch, ldapdomaindump, nmap, parse_ldapsearch
- Tags: ldap

## Linux Host (`service_linux_host`)

- Category: `service`
- Description: Service-specific validation for Linux host security posture.
- Tools: linpeas, lynis, linux-exploit-suggester, linux_inventory, auditd_status_parser, sshd_config_parser, firewall_status_parser, sudoers_parser, cron_parser, merge_posture, normalize_findings, package_evidence...
- Tags: linux, host

## MongoDB Service (`service_mongodb`)

- Category: `service`
- Description: Service-specific enumeration for MongoDB.
- Tools: mongosh, mongodump, nosqlmap, nmap, summarize_mongo_inventory
- Tags: mongodb

## MSSQL Service (`service_mssql`)

- Category: `service`
- Description: Service-specific enumeration for MSSQL.
- Tools: tsql, sqlcmd, nmap, parse_sqlcmd_json
- Tags: mssql, sqlserver, ms-sql

## MySQL Service (`service_mysql`)

- Category: `service`
- Description: Service-specific enumeration for MySQL.
- Tools: mysql, nmap, parse_mysql_show
- Tags: mysql, mariadb

## Network Evasion & Traffic Shaping (`service_network_evasion`)

- Category: `service`
- Description: Safe traffic shaping and authorized evasion checks.
- Tools: nmap, proxychains, tor, tcpdump, tshark, hping3, summarize_network_profile
- Tags: network, evasion, traffic_shaping

## POP3 Service (`service_pop3`)

- Category: `service`
- Description: Service-specific enumeration for POP3.
- Tools: nmap, netcat, socat, hydra, parse_pop3_nmap
- Tags: pop3, pop

## PostgreSQL Service (`service_postgres`)

- Category: `service`
- Description: Service-specific enumeration for PostgreSQL.
- Tools: psql, nmap, parse_psql_table
- Tags: postgres, postgresql

## RDP Service (`service_rdp`)

- Category: `service`
- Description: Service-specific enumeration for RDP.
- Tools: xfreerdp, nmap, parse_rdp_nmap
- Tags: rdp

## Redis Service (`service_redis`)

- Category: `service`
- Description: Service-specific enumeration for Redis.
- Tools: redis-cli, nmap, summarize_redis_info
- Tags: redis

## SCM Service (`service_scm`)

- Category: `service`
- Description: Service-specific enumeration for source control platforms.
- Tools: git, gh, glab, azure-devops-cli, curl, gitleaks, trufflehog, summarize_scm_inventory
- Tags: scm, git, github, gitlab

## Secrets Manager Service (`service_secrets_manager`)

- Category: `service`
- Description: Service-specific enumeration for secrets managers.
- Tools: vault, awscli, azure-cli, gcloud, policy_diff
- Tags: secrets, vault, keyvault, secretmanager

## SMB Service (`service_smb`)

- Category: `service`
- Description: Service-specific enumeration for SMB.
- Tools: smbclient, nmap, parse_smbclient
- Tags: smb, cifs

## SMTP Service (`service_smtp`)

- Category: `service`
- Description: Service-specific enumeration for SMTP.
- Tools: nmap, netcat, socat, smtp-user-enum, hydra, parse_smtp_nmap
- Tags: smtp

## SNMP Service (`service_snmp`)

- Category: `service`
- Description: Service-specific enumeration for SNMP.
- Tools: snmpwalk, snmp-check, onesixtyone, nmap, parse_snmpwalk
- Tags: snmp

## SSH Service (`service_ssh`)

- Category: `service`
- Description: Service-specific enumeration for SSH.
- Tools: ssh, ssh-keyscan, nmap, parse_ssh_nmap
- Tags: ssh

## TLS Service (`service_tls`)

- Category: `service`
- Description: Service-specific enumeration for TLS.
- Tools: openssl, sslscan, sslyze, nmap, parse_sslscan
- Tags: tls, ssl

## VPN Service (`service_vpn`)

- Category: `service`
- Description: Service-specific enumeration for VPN endpoints.
- Tools: ike-scan, openvpn, sslscan, nmap, parse_ikescan
- Tags: vpn, ipsec, sslvpn

## Windows Host (`service_windows_host`)

- Category: `service`
- Description: Service-specific validation for Windows host security posture.
- Tools: winpeas, seatbelt, powershell, wesng, windows_inventory, auditpol_parser, defender_status_parser, firewall_profile_parser, scheduled_tasks_parser, autoruns_parser, merge_posture, normalize_findings...
- Tags: windows, host

## Wireless Service (`service_wireless`)

- Category: `service`
- Description: Service-specific enumeration for wireless networks.
- Tools: aircrack-ng, wifite, wifiphisher, reaver, bully, hcxtools, airgeddon, bettercap, macchanger, tcpdump, tshark, airodump_csv_to_json
- Tags: wireless, wifi

## WordPress Service (`service_wordpress`)

- Category: `service`
- Description: Service-specific enumeration for WordPress.
- Tools: wpscan, nuclei, nikto, nmap, parse_wpscan_json
- Tags: wordpress, wp

## SQL Injection (`sql_injection`)

- Category: `exploitation`
- Description: Detect and exploit SQL injection vulnerabilities to extract data safely.
- MITRE: T1190
- Tools: sqlmap, bbqsql, sqlninja, havij, commix, parse_sqlmap_log

## Tool: Aircrack-ng (`tool_aircrack_ng`)

- Category: `scanning`
- Description: Wireless security suite for monitoring, injection, and WPA/WEP auditing.
- MITRE: T1040, T1595
- Tools: aircrack-ng
- Tags: aircrack-ng, wireless

## Tool: Amass (`tool_amass`)

- Category: `reconnaissance`
- Description: OSINT and DNS enumeration with graph-backed investigations.
- MITRE: T1590, T1593, T1596
- Tools: amass
- Tags: amass, osint, dns

## Tool: arp-scan (`tool_arp_scan`)

- Category: `scanning`
- Description: Layer-2 ARP scanning to discover hosts on local networks.
- MITRE: T1046
- Tools: arp-scan
- Tags: arp-scan, arp

## Tool: arping (`tool_arping`)

- Category: `scanning`
- Description: ARP ping utility for host reachability and MAC validation.
- MITRE: T1046
- Tools: arping
- Tags: arping, arp

## Tool: assetfinder (`tool_assetfinder`)

- Category: `reconnaissance`
- Description: Find related domains and subdomains via passive sources.
- MITRE: T1593, T1596
- Tools: assetfinder
- Tags: assetfinder, subdomain

## Tool: Autopsy (`tool_autopsy`)

- Category: `forensics`
- Description: Digital forensics platform for analyzing disk images and data sources.
- MITRE: T1005
- Tools: autopsy
- Tags: autopsy, forensics, sleuthkit

## Tool: Bettercap (`tool_bettercap`)

- Category: `defense_evasion`
- Description: Modular network attack and monitoring framework with caplets.
- MITRE: T1557
- Tools: bettercap
- Tags: bettercap, mitm

## Tool: BloodHound (`tool_bloodhound`)

- Category: `analysis`
- Description: Graph-based AD attack path analysis using BloodHound CE.
- MITRE: T1069, T1087, T1482
- Tools: bloodhound
- Tags: bloodhound, active_directory, ad, graph

## Tool: Bully (`tool_bully`)

- Category: `exploitation`
- Description: WPS attack tool with PixieWPS integration and robust options.
- MITRE: T1110
- Tools: bully
- Tags: bully, wps

## Tool: CeWL (`tool_cewl`)

- Category: `reconnaissance`
- Description: Custom wordlist generator by crawling target websites.
- Tools: cewl
- Tags: cewl, wordlist

## Tool: cowpatty (`tool_cowpatty`)

- Category: `exploitation`
- Description: Offline WPA/WPA2-PSK dictionary attack tool.
- MITRE: T1110
- Tools: cowpatty
- Tags: cowpatty, wireless

## Tool: CrackMapExec (`tool_crackmapexec`)

- Category: `lateral_movement`
- Description: Credential validation and remote execution framework (CME).
- MITRE: T1021, T1078
- Tools: crackmapexec
- Tags: crackmapexec, cme, smb, winrm, ldap

## Tool: Crunch (`tool_crunch`)

- Category: `reconnaissance`
- Description: Wordlist generator with patterns and permutations.
- Tools: crunch
- Tags: crunch, wordlist

## Tool: DIRB (`tool_dirb`)

- Category: `scanning`
- Description: Web content discovery using wordlists.
- MITRE: T1595
- Tools: dirb
- Tags: dirb, content

## Tool: dirsearch (`tool_dirsearch`)

- Category: `scanning`
- Description: Web path discovery with extensions and recursion support.
- MITRE: T1595
- Tools: dirsearch
- Tags: dirsearch, content

## Tool: DMitry (`tool_dmitry`)

- Category: `reconnaissance`
- Description: Information gathering (WHOIS, subdomains, email, ports) for targets.
- MITRE: T1593, T1590
- Tools: dmitry
- Tags: dmitry, osint

## Tool: DNSChef (`tool_dnschef`)

- Category: `defense_evasion`
- Description: Configurable DNS proxy for spoofing and traffic analysis.
- MITRE: T1565
- Tools: dnschef
- Tags: dnschef, dns, spoofing

## Tool: dnsenum (`tool_dnsenum`)

- Category: `reconnaissance`
- Description: Multi-threaded DNS enumeration with whois and reverse lookups.
- MITRE: T1590, T1593, T1596
- Tools: dnsenum
- Tags: dnsenum, dns

## Tool: dnsrecon (`tool_dnsrecon`)

- Category: `reconnaissance`
- Description: DNS enumeration with record checks, brute force, and zone transfer tests.
- MITRE: T1590, T1593, T1596
- Tools: dnsrecon
- Tags: dnsrecon, dns

## Tool: Ettercap (`tool_ettercap`)

- Category: `defense_evasion`
- Description: MITM framework for sniffing, interception, and filtering on LANs.
- MITRE: T1557
- Tools: ettercap
- Tags: ettercap, mitm

## Tool: Evil-WinRM (`tool_evil_winrm`)

- Category: `lateral_movement`
- Description: WinRM shell for post-exploitation on Windows hosts.
- MITRE: T1021.006
- Tools: evil-winrm
- Tags: evil-winrm, winrm, powershell

## Tool: Fern WiFi Cracker (`tool_fern_wifi_cracker`)

- Category: `exploitation`
- Description: GUI wireless auditing tool leveraging aircrack-ng and WPS tooling.
- MITRE: T1040, T1595
- Tools: fern-wifi-cracker
- Tags: fern, wireless

## Tool: Feroxbuster (`tool_feroxbuster`)

- Category: `scanning`
- Description: Recursive content discovery for web servers.
- MITRE: T1595
- Tools: feroxbuster
- Tags: feroxbuster, content

## Tool: ffuf (`tool_ffuf`)

- Category: `scanning`
- Description: Fast web fuzzer with flexible matchers and filters.
- MITRE: T1595
- Tools: ffuf
- Tags: ffuf, fuzz

## Tool: Fierce (`tool_fierce`)

- Category: `reconnaissance`
- Description: DNS reconnaissance for finding non-contiguous IP space and hosts.
- MITRE: T1590, T1593
- Tools: fierce
- Tags: fierce, dns

## Tool: Gobuster (`tool_gobuster`)

- Category: `scanning`
- Description: Directory, DNS, and vhost enumeration with wordlists.
- MITRE: T1595
- Tools: gobuster
- Tags: gobuster, enum

## Tool: hash-identifier (`tool_hash_identifier`)

- Category: `analysis`
- Description: Identify possible hash types from hash strings.
- Tools: hash-identifier
- Tags: hash-identifier, hash

## Tool: Hashcat (`tool_hashcat`)

- Category: `credential_access`
- Description: Advanced password recovery tool with modes, rules, and masks.
- MITRE: T1110
- Tools: hashcat
- Tags: hashcat, password

## Tool: hping3 (`tool_hping3`)

- Category: `defense_evasion`
- Description: Packet crafting and probing tool for network testing.
- MITRE: T1046
- Tools: hping3
- Tags: hping3, packet, network

## Tool: Hydra (`tool_hydra`)

- Category: `credential_access`
- Description: Network login cracker supporting many services and protocols.
- MITRE: T1110
- Tools: hydra
- Tags: hydra, bruteforce

## Tool: Impacket Scripts (`tool_impacket_scripts`)

- Category: `lateral_movement`
- Description: Impacket example scripts for SMB/LDAP/Kerberos remote ops.
- MITRE: T1021, T1078, T1047
- Tools: impacket-scripts
- Tags: impacket, smb, kerberos

## Tool: John the Ripper (`tool_john`)

- Category: `credential_access`
- Description: Password cracking tool with rules, modes, and formats.
- MITRE: T1110
- Tools: john
- Tags: john, password

## Tool: macchanger (`tool_macchanger`)

- Category: `defense_evasion`
- Description: Change or spoof MAC addresses on network interfaces.
- MITRE: T1036
- Tools: macchanger
- Tags: macchanger, spoofing

## Tool: Masscan (`tool_masscan`)

- Category: `scanning`
- Description: High-speed TCP port scanner with rate controls and config files.
- MITRE: T1046
- Tools: masscan
- Tags: masscan, scan

## Tool: Medusa (`tool_medusa`)

- Category: `credential_access`
- Description: Parallel login brute-force tool with modular service support.
- MITRE: T1110
- Tools: medusa
- Tags: medusa, bruteforce

## Tool: Mimikatz (`tool_mimikatz`)

- Category: `credential_access`
- Description: Windows credential extraction and ticket operations.
- MITRE: T1003, T1558
- Tools: mimikatz
- Tags: mimikatz, credentials

## Tool: mitm6 (`tool_mitm6`)

- Category: `credential_access`
- Description: IPv6-based DNS spoofing to coerce NTLM authentication.
- MITRE: T1187, T1557
- Tools: mitm6
- Tags: mitm6, ipv6, ntlm

## Tool: Netcat (`tool_netcat`)

- Category: `network_evasion`
- Description: TCP/UDP utility for connection testing, file transfer, and simple relays.
- MITRE: T1046, T1105
- Tools: netcat
- Tags: netcat, network

## Tool: netdiscover (`tool_netdiscover`)

- Category: `scanning`
- Description: Active/passive ARP discovery for local network mapping.
- MITRE: T1046
- Tools: netdiscover
- Tags: netdiscover, arp

## Tool: NetExec (`tool_netexec`)

- Category: `lateral_movement`
- Description: Credential validation and remote execution framework (CME successor).
- MITRE: T1021, T1078
- Tools: netexec
- Tags: netexec, cme, smb, winrm, ldap

## Tool: Nikto (`tool_nikto`)

- Category: `scanning`
- Description: Web server scanner for known issues and misconfigurations.
- MITRE: T1595
- Tools: nikto
- Tags: nikto, web

## Tool: Nmap (`tool_nmap`)

- Category: `scanning`
- Description: Network discovery and service enumeration with NSE scripting.
- MITRE: T1046
- Tools: nmap
- Tags: nmap, scan

## Tool: onesixtyone (`tool_onesixtyone`)

- Category: `scanning`
- Description: Fast SNMP community string scanner.
- MITRE: T1046
- Tools: onesixtyone
- Tags: onesixtyone, snmp

## Tool: Proxychains (`tool_proxychains`)

- Category: `network_evasion`
- Description: Force network traffic through proxy chains for scoped routing.
- MITRE: T1090
- Tools: proxychains
- Tags: proxychains, proxy

## Tool: Reaver (`tool_reaver`)

- Category: `exploitation`
- Description: WPS PIN attack tool with wash scanner integration.
- MITRE: T1110
- Tools: reaver
- Tags: reaver, wps

## Tool: Recon-ng (`tool_recon_ng`)

- Category: `reconnaissance`
- Description: Modular OSINT framework with workspaces and marketplace modules.
- MITRE: T1593, T1596
- Tools: recon-ng
- Tags: recon-ng, osint

## Tool: Responder (`tool_responder`)

- Category: `credential_access`
- Description: LLMNR/NBNS/mDNS poisoning and credential capture.
- MITRE: T1187, T1557
- Tools: responder
- Tags: responder, llmnr, nbns, mdns

## Tool: Rubeus (`tool_rubeus`)

- Category: `credential_access`
- Description: Kerberos abuse and ticket operations on Windows.
- MITRE: T1558, T1550
- Tools: rubeus
- Tags: rubeus, kerberos

## Tool: SharpHound (`tool_sharphound`)

- Category: `analysis`
- Description: Active Directory data collection for BloodHound analysis.
- MITRE: T1069, T1087, T1482
- Tools: sharphound
- Tags: sharphound, active_directory, ad

## Tool: smtp-user-enum (`tool_smtp_user_enum`)

- Category: `reconnaissance`
- Description: SMTP user enumeration via VRFY/EXPN/RCPT methods.
- MITRE: T1590, T1593
- Tools: smtp-user-enum
- Tags: smtp-user-enum, smtp

## Tool: snmp-check (`tool_snmp_check`)

- Category: `scanning`
- Description: SNMP device enumeration with human-readable output.
- MITRE: T1046
- Tools: snmp-check
- Tags: snmp-check, snmp

## Tool: snmpwalk (`tool_snmpwalk`)

- Category: `scanning`
- Description: SNMP subtree enumeration using GETNEXT requests.
- MITRE: T1046
- Tools: snmpwalk
- Tags: snmpwalk, snmp

## Tool: Socat (`tool_socat`)

- Category: `network_evasion`
- Description: Multipurpose relay tool for sockets, TTYs, and port forwarding.
- MITRE: T1090
- Tools: socat
- Tags: socat, network, proxy

## Tool: sqlmap (`tool_sqlmap`)

- Category: `exploitation`
- Description: Automated SQL injection testing and database enumeration tool.
- MITRE: T1190
- Tools: sqlmap
- Tags: sqlmap, sqli

## Tool: sqlninja (`tool_sqlninja`)

- Category: `exploitation`
- Description: SQL Server injection tool focused on Microsoft SQL Server exploitation.
- MITRE: T1190
- Tools: sqlninja
- Tags: sqlninja, sqli

## Tool: sqlsus (`tool_sqlsus`)

- Category: `exploitation`
- Description: MySQL injection and exploitation tool with configuration-based workflows.
- MITRE: T1190
- Tools: sqlsus
- Tags: sqlsus, sqli

## Tool: subfinder (`tool_subfinder`)

- Category: `reconnaissance`
- Description: Passive subdomain discovery using curated sources.
- MITRE: T1593, T1596
- Tools: subfinder
- Tags: subfinder, subdomain

## Tool: Sublist3r (`tool_sublist3r`)

- Category: `reconnaissance`
- Description: OSINT subdomain enumeration using multiple search engines.
- MITRE: T1593, T1596
- Tools: sublist3r
- Tags: sublist3r, subdomain

## Tool: tcpdump (`tool_tcpdump`)

- Category: `forensics`
- Description: Command-line packet capture using libpcap filters.
- MITRE: T1040
- Tools: tcpdump
- Tags: tcpdump, pcap, network

## Tool: TestDisk (`tool_testdisk`)

- Category: `forensics`
- Description: Recover lost partitions and files from damaged media.
- Tools: testdisk
- Tags: testdisk, recovery, forensics

## Tool: theHarvester (`tool_theharvester`)

- Category: `reconnaissance`
- Description: OSINT collection of emails, subdomains, hosts, and URLs from public sources.
- MITRE: T1593, T1596
- Tools: theharvester
- Tags: theharvester, osint

## Tool: Tor (`tool_tor`)

- Category: `network_evasion`
- Description: Tor daemon and tools for anonymized routing through the Tor network.
- MITRE: T1090
- Tools: tor
- Tags: tor, proxy

## Tool: Wfuzz (`tool_wfuzz`)

- Category: `scanning`
- Description: Flexible web fuzzer with payloads, encoders, and filters.
- MITRE: T1595
- Tools: wfuzz
- Tags: wfuzz, fuzz

## Tool: WhatWeb (`tool_whatweb`)

- Category: `reconnaissance`
- Description: Web technology fingerprinting using plugin-based detection.
- MITRE: T1595
- Tools: whatweb
- Tags: whatweb, fingerprint

## Tool: Wifiphisher (`tool_wifiphisher`)

- Category: `exploitation`
- Description: Rogue AP framework for wireless phishing and client capture.
- MITRE: T1557, T1566
- Tools: wifiphisher
- Tags: wifiphisher, wireless, rogue-ap

## Tool: WiFiPumpkin3 (`tool_wifipumpkin3`)

- Category: `exploitation`
- Description: Rogue AP and wireless testing framework with modular proxies.
- MITRE: T1557, T1566
- Tools: wifipumpkin3
- Tags: wifipumpkin3, wireless, rogue-ap

## Tool: Wifite (`tool_wifite`)

- Category: `scanning`
- Description: Automated wireless audit workflow for WEP/WPA/WPS targets.
- MITRE: T1040, T1595
- Tools: wifite
- Tags: wifite, wireless

## Tool: Wireshark (`tool_wireshark`)

- Category: `forensics`
- Description: GUI network protocol analyzer for inspecting pcaps.
- MITRE: T1040
- Tools: wireshark
- Tags: wireshark, pcap, network

## Tool: YARA (`tool_yara`)

- Category: `forensics`
- Description: Pattern-matching rules for identifying files and artifacts.
- MITRE: T1083
- Tools: yara
- Tags: yara, forensics, malware

## Cross-Site Scripting (`xss`)

- Category: `exploitation`
- Description: Identify and validate XSS vulnerabilities with safe payloads.
- MITRE: T1059
- Tools: xsstrike, xsser, dalfox, beef, burpsuite, beef-xss, parse_dalfox_json
