# iodine Toolcard

## Overview
- Summary: iodine tunnels IPv4 data through DNS by creating a tun network interface for a full IP tunnel. Unlike dnscat2 (C2-focused), iodine provides raw IP connectivity — route any traffic through DNS. Auto-detects best encoding (NULL, Base128, Base64, Base32) and fragment size for maximum throughput (~50-100 KB/s). Useful for bypassing captive portals and firewalled networks where DNS is allowed. Tunnel data is NOT encrypted — layer SSH/VPN on top. MITRE ATT&CK T1572 (Protocol Tunneling), T1071.004 (DNS).

## Advanced Techniques
- DNS delegation required: `t1 IN NS t1ns.example.com.` and `t1ns IN A <server_ip>` in zone file.
- Server start: `iodined -f -c -P secretpass 10.0.0.1/24 t1.example.com` — `-f` foreground, `-c` disable client IP check, `-P` password.
- Server on non-standard port: `iodined -f -c -P secretpass -p 5353 10.0.0.1/24 t1.example.com`.
- Server with upstream DNS forwarding: `iodined -f -c -P secretpass -b 5353 10.0.0.1/24 t1.example.com`.
- Enable NAT on server: `iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE` + `echo 1 > /proc/sys/net/ipv4/ip_forward`.
- Client start: `iodine -f -P secretpass t1.example.com` — auto-detects encoding and fragment size.
- Client with explicit DNS server: `iodine -f -P secretpass 8.8.8.8 t1.example.com`.
- Force encoding: `-T NULL` (fastest), `-T TXT` (default), `-T CNAME` (most compatible), `-T BASE32` (fallback).
- Force DNS tunneling (skip raw UDP detection): `iodine -f -r -P secretpass t1.example.com`.
- After connection: client gets `10.0.0.2`, server is `10.0.0.1` — verify with `ping 10.0.0.1`.
- SSH SOCKS proxy through tunnel: `ssh -N -D 1080 user@10.0.0.1` → `proxychains4 curl http://internal-target` (T1090).
- SSH port forwarding: `ssh -N -L 8080:internal-host:80 user@10.0.0.1` (local), `ssh -N -R 9090:127.0.0.1:9090 user@10.0.0.1` (remote).
- Full internet routing: `ip route add <dns_server_ip> via <original_gw>` then `ip route replace default via 10.0.0.1`.
- Root/admin required on both sides (creates tun interfaces). MTU auto-negotiated (~1000-1200 bytes).
- Detection indicators: high volume DNS queries to single subdomain, NULL record queries (unusual), consistent large DNS responses, tun interface creation on endpoints, DNS traffic volume disproportionate to normal usage.

## Safe Defaults
- Rate limits: throughput limited by DNS infrastructure (~50-100 KB/s max); avoid bulk transfers
- Scope rules: explicit target only — always layer encryption (SSH/VPN) over the tunnel since iodine traffic is unencrypted

## Evidence Outputs
- outputs: evidence.json, findings.json (as applicable)

## References
- https://github.com/yarrick/iodine
- https://code.kryo.se/iodine
