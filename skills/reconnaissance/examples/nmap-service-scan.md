# Nmap Service Scan Example

## Command
```bash
nmap -sV -sC -p- -T4 -oA full_scan 10.10.10.40
```

## Output
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-15 14:23 EST
Nmap scan report for 10.10.10.40
Host is up (0.032s latency).
Not shown: 65527 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled but not required
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery:
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-01-15T19:25:12+00:00

Service detection performed. Scan took 127.43 seconds.
Nmap done: 1 IP address (1 host up) scanned in 131.56 seconds
```

## Key Findings
- **Windows 7 SP1** — End of life, likely missing patches
- **SMB signing disabled** — NTLM relay potential
- **Port 445 open** — Check for EternalBlue (MS17-010)
- **Guest access** — May allow null session enumeration

## Next Steps
→ **scanning skill**: `nmap --script smb-vuln-ms17-010 -p 445 10.10.10.40`
→ **credential_access skill**: NTLM relay possible (signing disabled)
→ **exploitation skill**: If MS17-010 confirmed, use EternalBlue module
