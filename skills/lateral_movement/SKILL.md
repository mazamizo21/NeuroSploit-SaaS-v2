# Lateral Movement Skill

## Overview
Moving through a network from the initial compromise point to other systems, pivoting through compromised hosts to reach more valuable targets.

## Methodology

### 1. Network Discovery
- Identify other hosts on the network
- Identify trust relationships between hosts
- Identify services and credentials that allow movement

### 2. Credential Reuse
- Test discovered credentials on other hosts
- Reuse SSH keys across systems
- Reuse database credentials
- Reuse web application credentials
- Reuse Active Directory credentials

### 3. Pass-the-Hash
- Use NTLM hashes to authenticate to Windows systems
- Use cached credentials
- Use Kerberos tickets (Pass-the-Ticket)

### 4. Remote Command Execution
- Execute commands via SSH (with keys or passwords)
- Execute commands via RDP (with credentials)
- Execute commands via WMI/WinRM
- Execute commands via RPC
- Execute commands via SMB (psexec, wmiexec, smbexec)

### 5. Pivoting and Tunneling
- Set up SSH tunnels (local, remote, dynamic)
- Set up SOCKS proxy for network traversal
- Set up port forwarding
- Use compromised hosts as jump boxes
- Chain multiple pivots

### 6. Service Exploitation
- Exploit vulnerable services on other hosts
- Exploit trust relationships (e.g., domain trust)
- Exploit misconfigured permissions
- Exploit scheduled tasks across systems

### 7. Active Directory Movement
- Domain enumeration (computers, users, groups, GPOs)
- Kerberoasting (extract service principal name tickets)
- AS-REP Roasting
- Golden ticket creation
- Silver ticket creation
- DCShadow

### 8. Automated Tools
- CrackMapExec: Network penetration testing tool
- Impacket: Collection of Python classes for working with network protocols
- Responder: LLMNR, NBT-NS, and MDNS poisoner
- Empire: Post-exploitation framework
- Metasploit: Post-exploitation modules

## MITRE ATT&CK Mappings
- T1021 - Remote Services
- T1550 - Use Alternate Authentication Material
- T1558 - Steal or Forge Kerberos Tickets
- T1021.002 - SMB/Windows Admin Shares
- T1021.004 - SSH
- T1021.001 - Remote Desktop Protocol
- T1059.003 - Windows Command Shell

## Tools Available
- crackmapexec: Network penetration testing and lateral movement tool
- impacket: Python library for network protocol manipulation
- responder: Multi-purpose SMB/LLMNR/NBT-NS poisoner
- metasploit: Penetration testing framework with post-exploitation modules
- empire: Post-exploitation and adversary emulation framework
- evil-winrm: WinRM shell for hacking
- freerdp: Remote Desktop Protocol client
- sshpass: Non-interactive SSH password provider

## Evidence Collection
1. Network map and discovered hosts
2. Successful lateral movement commands
3. Screenshots of remote access
4. Extracted credentials from new hosts
5. Pivot tunnel configurations
6. Domain enumeration results
7. Privilege escalation results on new hosts

## Success Criteria
- Additional hosts identified and accessed
- Lateral movement achieved via at least one method
- Credentials reused or pivoting established
- Domain information extracted if applicable
- Higher-value targets accessed
- Persistence established on new hosts if applicable
- All evidence documented
