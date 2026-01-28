# Credential Access Skill

## Overview
Identifying and extracting credentials from compromised systems, including passwords, hash dumps, API keys, tokens, and other authentication secrets.

## Methodology

### 1. Credential Discovery
- Locate credential storage locations
- Identify credential types (passwords, hashes, keys, tokens)
- Search configuration files, databases, memory, logs

### 2. Windows Credential Extraction
- Dump LSASS memory with Mimikatz
- Extract cached credentials
- Dump SAM/SYSTEM/SECURITY registry hives
- Extract LSA secrets
- Extract DPAPI master keys
- Extract RDP credentials
- Extract browser saved passwords

### 3. Linux Credential Extraction
- Dump /etc/passwd and /etc/shadow
- Extract user history files (.bash_history, .zsh_history)
- Extract SSH keys and authorized_keys
- Extract sudoers configuration
- Extract database credentials from config files
- Extract passwords from memory (mimipenguin)

### 4. Database Credential Extraction
- Extract database credentials from connection strings
- Extract database users and password hashes
- Extract application config files with credentials

### 5. Network Credential Extraction
- Capture network authentication (NTLM, Kerberos)
- Extract credentials from network traffic
- Extract credentials from network shares

### 6. Browser Credential Extraction
- Extract saved passwords from browsers (Chrome, Firefox, Edge)
- Extract cookies and sessions
- Extract form data and autocomplete

### 7. Application Credential Extraction
- Extract credentials from application config files
- Extract API keys and tokens
- Extract secrets from environment variables

### 8. Credential Cracking
- Crack Windows hashes (NTLM)
- Crack Linux hashes (Unix, SHA-512)
- Crack password-protected files (zip, pdf, etc.)
- Use dictionary, rainbow table, and brute-force attacks

## MITRE ATT&CK Mappings
- T1003 - OS Credential Dumping
- T1555 - Credentials from Password Stores
- T1056 - Input Capture (Keylogging)
- T1552 - Unsecured Credentials
- T1528 - Steal Application Access Token
- T1059.001 - PowerShell (credential extraction scripts)

## Tools Available
- mimikatz: Windows credential extraction tool
- hashcat: Password recovery and hash cracking tool
- john: Fast password cracker (John the Ripper)
- hashid: Identify hash types
- cewl: Custom wordlist generator
- crunch: Wordlist generator
- fcrackzip: Zip file password cracker
- pdfcrack: PDF password cracker
- pdfcrack: PDF password recovery
- secretsdump: Extract secrets from Windows registry
- LaZagne: Password recovery for many applications

## Evidence Collection
1. Dumped hashes (NTLM, Unix, etc.)
2. Extracted plaintext passwords
3. Configuration files with credentials
4. SSH keys and certificates
5. Browser saved passwords
6. Cracking results
7. Screenshot of credential files

## Success Criteria
- Credential storage locations identified
- At least one credential type extracted
- Hashes dumped if applicable
- Passwords cracked if feasible
- All extracted credentials documented
- Sensitive files preserved
