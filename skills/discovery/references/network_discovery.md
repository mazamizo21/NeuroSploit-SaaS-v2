# Internal Network Discovery Reference

## Network Position Assessment

### Linux
```bash
# Interface and IP enumeration
ip a                                    # All interfaces
ip -4 addr show                         # IPv4 only
ip -6 addr show                         # IPv6 only
ifconfig -a 2>/dev/null                # Legacy interface listing

# Routing table
ip route                                # Routing table
ip route show table all                 # All routing tables
route -n 2>/dev/null                   # Legacy routing (numeric)

# DNS configuration
cat /etc/resolv.conf                    # DNS servers and search domains
cat /etc/hosts                          # Static mappings
systemd-resolve --status 2>/dev/null   # systemd-resolved details
resolvectl status 2>/dev/null          # Modern systemd-resolved
```

### Windows
```cmd
ipconfig /all                           :: Full config with DNS
route print                             :: Routing table
ipconfig /displaydns                    :: DNS cache
```

```powershell
Get-NetIPAddress | Select-Object InterfaceAlias, IPAddress, PrefixLength, AddressFamily
Get-NetRoute | Select-Object DestinationPrefix, NextHop, InterfaceAlias, RouteMetric
Get-DnsClientServerAddress | Select-Object InterfaceAlias, ServerAddresses
Get-DnsClientCache | Select-Object Entry, Data
```

---

## ARP / Neighbor Discovery

### Linux
```bash
ip neigh                                # ARP/NDP table
ip neigh show nud reachable             # Only reachable neighbors
arp -a 2>/dev/null                     # Legacy ARP table
cat /proc/net/arp                       # Direct from procfs
```

### Windows
```cmd
arp -a                                  :: ARP cache
```

```powershell
Get-NetNeighbor | Where-Object {$_.State -ne "Unreachable"} | Select-Object IPAddress, LinkLayerAddress, State
```

---

## Host Discovery (Ping Sweep)

### Without Tools
```bash
# Bash ping sweep
for i in $(seq 1 254); do
    (ping -c1 -W1 10.0.0.$i &>/dev/null && echo "10.0.0.$i alive") &
done; wait

# Using /dev/tcp (no ping needed)
for i in $(seq 1 254); do
    (echo > /dev/tcp/10.0.0.$i/80 2>/dev/null && echo "10.0.0.$i:80 open") &
done; wait

# ARP scan via arping (requires root, layer 2)
for i in $(seq 1 254); do
    arping -c1 -w1 10.0.0.$i 2>/dev/null | grep "reply from"
done
```

```cmd
:: Windows ping sweep
for /L %i in (1,1,254) do @ping -n 1 -w 200 10.0.0.%i | findstr "Reply" && echo 10.0.0.%i alive
```

### Nmap Host Discovery
```bash
# ICMP ping sweep
nmap -sn 10.0.0.0/24 -oG ping_sweep.gnmap

# ARP discovery (local subnet, fastest)
nmap -sn -PR 10.0.0.0/24

# TCP SYN discovery (no ICMP needed)
nmap -sn -PS22,80,443 10.0.0.0/24

# Multiple techniques combined
nmap -sn -PE -PS22,80,443 -PA80 -PP 10.0.0.0/24

# Large network fast sweep
nmap -sn -T4 --min-parallelism 100 10.0.0.0/16 -oG large_sweep.gnmap
```

### nbtscan (NetBIOS Discovery)
```bash
nbtscan 10.0.0.0/24                    # Scan subnet for NetBIOS names
nbtscan -r 10.0.0.0/24                # Use local port 137
nbtscan -v -s : 10.0.0.0/24           # Verbose with colon separator
```

---

## Port Scanning

### Quick Discovery
```bash
# Top 100 TCP ports
nmap -sS --top-ports 100 -T4 <target> -oG quick.gnmap

# Common service ports
nmap -sS -p22,25,53,80,88,110,135,139,143,389,443,445,636,993,995,1433,1521,3306,3389,5432,5900,5985,8080,8443 <target>

# Full TCP port scan
nmap -sS -p- -T4 <target> -oA full_tcp

# UDP top ports (slower)
nmap -sU --top-ports 50 -T4 <target> -oA udp_scan

# Service version detection
nmap -sV -sC -p<ports> <target> -oA service_scan
```

### Without Nmap
```bash
# Bash TCP port scanner
for port in 21 22 23 25 53 80 88 110 135 139 143 389 443 445 636 993 1433 3306 3389 5432 5900 5985 8080 8443; do
    (echo > /dev/tcp/<target>/$port 2>/dev/null && echo "Port $port open") &
done; wait

# Netcat port scan
nc -zvn <target> 1-1024 2>&1 | grep open

# Using /dev/tcp for specific ports
timeout 1 bash -c "echo > /dev/tcp/<target>/445" 2>/dev/null && echo "SMB open"
```

---

## Service-Specific Enumeration

### SMB (445/TCP, 139/TCP)
```bash
# Share enumeration
smbclient -L //<target> -N              # Null session
smbclient -L //<target> -U '<user>%<pass>'  # Authenticated
enum4linux-ng -As <target>              # Full SMB enum
crackmapexec smb <target> -u '<user>' -p '<pass>' --shares

# Access shares
smbclient //<target>/<share> -U '<user>%<pass>'
smbclient //<target>/<share> -U '<user>%<pass>' -c 'recurse ON; prompt OFF; ls'

# Nmap SMB scripts
nmap --script smb-enum-shares,smb-enum-users,smb-os-discovery -p445 <target>
nmap --script smb-vuln* -p445 <target>
```

### NFS (2049/TCP)
```bash
showmount -e <target>                   # List exports
mount -t nfs <target>:/<export> /mnt/nfs -o nolock  # Mount export
nmap --script nfs-ls,nfs-showmount,nfs-statfs -p2049 <target>
```

### SNMP (161/UDP)
```bash
snmpwalk -v2c -c public <target>        # Walk with 'public' community
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.1  # System info
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>
snmp-check <target> -c public           # Formatted SNMP enum
```

### DNS (53/TCP, 53/UDP)
```bash
dig @<dns_server> <domain> any          # All records
dig @<dns_server> <domain> axfr         # Zone transfer attempt
host -l <domain> <dns_server>           # Zone transfer via host
dnsrecon -d <domain> -n <dns_server> -t axfr  # Zone transfer
dig @<dns_server> -x <ip>              # Reverse lookup
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain> <dns_server>  # Find DCs
dig @<dns_server> _ldap._tcp.<domain> SRV  # Find DCs via dig
```

### LDAP (389/TCP, 636/TCP)
```bash
ldapsearch -x -H ldap://<target> -b "" -s base namingContexts  # Get base DN
ldapsearch -x -H ldap://<target> -b "dc=domain,dc=local" "(objectClass=*)" | head -100
nmap --script ldap-rootdse -p389 <target>
nmap --script ldap-search -p389 <target>
```

### RDP (3389/TCP)
```bash
nmap --script rdp-enum-encryption,rdp-ntlm-info -p3389 <target>
xfreerdp /v:<target> /u:<user> /p:<pass> +clipboard /cert:ignore  # Connect
rdesktop <target> -u <user> -p <pass>   # Alternative client
```

### WinRM (5985/TCP, 5986/TCP)
```bash
crackmapexec winrm <target> -u '<user>' -p '<pass>'  # Test WinRM access
evil-winrm -i <target> -u '<user>' -p '<pass>'       # Interactive shell
```

---

## Network Mapping Summary

### Build Internal Network Map
1. **Identify subnets** from interface IPs and routes
2. **ARP scan** local subnet for immediate neighbors
3. **Ping sweep** each discovered subnet
4. **Top-ports scan** discovered hosts
5. **Full scan** high-value targets (DCs, servers)
6. **Service enum** discovered services (SMB, LDAP, DNS, etc.)
7. **Map trusts and routes** to adjacent networks

### Common Internal Subnets to Check
```
10.0.0.0/8          # Class A private
172.16.0.0/12       # Class B private
192.168.0.0/16      # Class C private
169.254.0.0/16      # Link-local
```

### Identifying High-Value Targets
- **Domain Controllers**: ports 53, 88, 135, 389, 445, 636, 3268, 3269
- **Exchange/Mail**: ports 25, 110, 143, 443, 587, 993, 995
- **Database servers**: ports 1433 (MSSQL), 3306 (MySQL), 5432 (PostgreSQL), 1521 (Oracle), 27017 (MongoDB)
- **Web servers**: ports 80, 443, 8080, 8443
- **Admin interfaces**: ports 3389 (RDP), 5985/5986 (WinRM), 22 (SSH)
- **File servers**: ports 445 (SMB), 2049 (NFS), 21 (FTP)
