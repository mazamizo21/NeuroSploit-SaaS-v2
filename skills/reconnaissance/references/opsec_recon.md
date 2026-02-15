# OPSEC Recon Reference

## Noise Tiers

Every recon technique has a detection footprint. Plan phase order by noise level.

---

## 🟢 Passive (Zero Touch — No Target Interaction)

These techniques generate ZERO traffic to the target. Undetectable.

| Technique | Tool / Source | Notes |
|-----------|--------------|-------|
| Certificate Transparency | crt.sh, censys.io | Query CT logs, no target contact |
| DNS lookups (cached) | dig, nslookup via public resolvers | 8.8.8.8 / 1.1.1.1 — target NS never sees query |
| WHOIS | whois, ViewDNS, DomainTools | Public registrar data |
| Shodan cached results | shodan host, shodan search | Queries Shodan index, no live scan |
| Censys cached results | censys search, censys view | Queries Censys index |
| Google Dorking | Google search operators | Google's cache, not target |
| Wayback Machine | waybackurls, web.archive.org | Archived copies, no live request |
| GitHub/GitLab search | gh api, trufflehog (GitHub mode) | Searches code hosting, not target |
| LinkedIn / OSINT | Manual browsing, CrossLinked | Social platform queries |
| Passive DNS databases | SecurityTrails, RiskIQ, VirusTotal | Historical DNS records |
| ASN/BGP lookups | bgp.he.net, bgpview.io | Public routing data |
| Breach databases | dehashed, haveibeenpwned (API) | Check leaked credentials (legal gray) |

```bash
# Full passive recon pipeline (zero target interaction)
subfinder -d target.com -all -silent | sort -u > passive_subs.txt
curl -s 'https://crt.sh/?q=%.target.com&output=json' | jq -r '.[].name_value' | sort -u >> passive_subs.txt
shodan search 'ssl.cert.subject.CN:target.com' --fields ip_str,port,product 2>/dev/null
waybackurls target.com | sort -u > wayback_urls.txt
whois target.com > whois.txt
theHarvester -d target.com -b all -l 500 -f harvester 2>/dev/null
```

---

## 🟡 Semi-Passive (Light Touch — Minimal Interaction)

Single requests or low-volume probes. Blends with normal traffic.
Most targets won't notice. IDS unlikely to trigger.

| Technique | Traffic Profile | Risk Level |
|-----------|----------------|------------|
| Banner grab (single SYN) | 1 packet per port | Very low |
| robots.txt / sitemap.xml | 1-2 HTTP requests | Very low |
| Single page fetch | 1 HTTP request | Very low |
| DNS query to target NS | 1 DNS query | Low |
| TLS certificate grab | 1 TLS handshake | Very low |
| HTTP header inspection | 1 HTTP request | Very low |
| WHOIS on target IP | 1 query to registrar | None (not to target) |

```bash
# Semi-passive fingerprinting (1-5 requests total)
curl -sI https://target.com | head -20                           # 1 request
curl -s https://target.com/robots.txt                             # 1 request
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates                    # 1 TLS handshake
dig target.com ANY @ns1.target.com +noall +answer                # 1 DNS query
nmap -sS -p 80,443 --max-retries 1 -T2 target.com               # 2 SYN packets
```

---

## 🔴 Active (Noisy — Direct Probing)

High-volume, easily detected. Use only when authorized. Plan timing.

| Technique | Traffic Volume | Detection Risk |
|-----------|---------------|----------------|
| Full port scan (-p-) | 65,535 SYN packets | HIGH |
| Service version scan (-sV) | Hundreds of banner probes | HIGH |
| Directory brute-force | 5K-200K HTTP requests | VERY HIGH |
| Vulnerability scanning (nuclei/nikto) | Thousands of requests | VERY HIGH |
| Spider/crawl | Hundreds-thousands of requests | HIGH |
| Subdomain brute-force (active DNS) | Thousands of DNS queries | MODERATE |
| Parameter fuzzing | Thousands of requests | VERY HIGH |
| Credential brute-force | Hundreds of auth attempts | CRITICAL |

```bash
# Active scan example with OPSEC considerations
# Rate-limited port scan
nmap -sS -p- --min-rate 300 --max-retries 2 -T3 target.com -oA nmap_full

# Slow directory brute (avoid rate limits)
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -rate 50 -o dirs.json -of json

# Vulnerability scan with rate control
nuclei -u http://target -t /root/nuclei-templates/ -rl 30 -c 5 -o nuclei.txt
```

---

## Scan Timing Strategies

### Nmap Timing Templates
```
-T0 (paranoid)   : 5 min between probes — IDS evasion, painfully slow
-T1 (sneaky)     : 15 sec between probes — slow but stealthy
-T2 (polite)     : 0.4 sec between probes — good for external targets
-T3 (normal)     : default, parallel scanning
-T4 (aggressive) : reduced timeouts, faster — labs/internal only
-T5 (insane)     : no regard for accuracy — CTFs only
```

### Custom Timing for IDS Evasion
```bash
# Below common IDS thresholds (15 ports/sec triggers most SYN flood rules)
nmap -sS -p 1-1000 --scan-delay 500ms --max-retries 1 target

# Randomize scan order to avoid sequential port patterns
nmap -sS -p- --randomize-hosts --data-length 40 target

# Fragment packets to evade simple packet inspection
nmap -sS -p 1-1000 -f --mtu 24 target

# Use decoys (makes source attribution harder)
nmap -sS -p 80,443 -D RND:5 target

# Idle scan (completely spoofed source IP)
nmap -sI zombie_host:135 -p 80,443 target
```

### IDS Threshold Awareness
```
Common IDS thresholds (Snort/Suricata defaults):
  - SYN flood: >15 SYN packets/sec to different ports
  - Port scan: >5 ports probed in <3 seconds
  - HTTP flood: >100 requests/minute from single source
  - SSH brute: >5 failed auths in 60 seconds
  - DNS amplification: >50 ANY queries/min

Stay under thresholds:
  - Use --scan-delay 1s (nmap) for port scans
  - Use -rate 30 (ffuf) for web brute-force
  - Use -t 4 -W 3 (hydra) for credential attacks
  - Space out different scan types by 5-10 minutes
```

---

## Source IP Considerations

### Scanning Infrastructure
```bash
# Option 1: Commercial VPN (fastest setup)
# Use different VPN server per scan phase
# Mullvad / ProtonVPN — anonymous signup, no logs

# Option 2: Cloud instance in same region as target
# Reduces latency, appears as "normal" cloud traffic
# AWS: same region as target (check via IP geolocation)
# Disposable: spin up, scan, tear down

# Option 3: Tor (last resort — very slow, many ports blocked)
proxychains4 nmap -sT -Pn -p 80,443 target    # TCP connect only through Tor
# Note: Tor exit nodes are widely blacklisted

# Option 4: SSH tunnel through multiple hops
ssh -D 9050 user@jump1 -J user@jump2
proxychains4 nmap -sT -Pn target
```

### Source Rotation
```bash
# Rotate through multiple VPN endpoints
# Scan first 1000 ports from VPN1, next 1000 from VPN2, etc.

# Use multiple cloud instances in parallel
# Instance 1: ports 1-21000
# Instance 2: ports 21001-42000
# Instance 3: ports 42001-65535

# Combine results
cat scan_part*.gnmap | grep 'Ports:' | sort -u > combined_scan.txt
```

---

## Rate Limiting Detection & Avoidance

### Detecting Rate Limits
```bash
# Check for rate limit headers
curl -sI http://target/api/ | grep -iE '(rate|limit|retry|throttl)'

# Test with rapid requests
for i in $(seq 1 50); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://target/)
  [ "$code" = "429" ] && echo "Rate limited at request $i" && break
  [ "$code" = "503" ] && echo "Service unavailable at request $i" && break
done

# Signs of rate limiting:
# HTTP 429 Too Many Requests
# HTTP 503 Service Unavailable (temporary)
# Connection reset (TCP RST)
# Increasing response times (throttling)
# CAPTCHA/challenge page returned
# Empty responses (drop mode)
```

### Staying Under Rate Limits
```bash
# ffuf with rate limiting
ffuf -u http://target/FUZZ -w wordlist.txt -rate 10 -p 0.5-2.0

# gobuster with throttle
gobuster dir -u http://target -w wordlist.txt --delay 500ms

# Burp Intruder: set resource pool to 1 concurrent, 500ms delay

# Custom delay between requests
cat urls.txt | while read url; do
  curl -s "$url" -o /dev/null -w '%{http_code} %{url_effective}\n'
  sleep $(shuf -i 1-3 -n 1)  # random 1-3 second delay
done

# Distribute across time: run scans during business hours
# when normal traffic volume provides cover
```

### WAF-Specific Rate Limit Notes
```
Cloudflare:  Default 100 req/10s per IP. Under Attack Mode: JS challenge.
             Bypass: slower rate + legitimate headers + keep-alive

AWS WAF:     Custom rules per customer. Check X-Amzn headers for hints.
             Rate-based rules typically 100-2000 req per 5 min.

Akamai:      Bot Manager scores request anomalies. Focus on realistic
             browser fingerprint (TLS JA3, headers order, User-Agent).

Imperva:     IncapRules with custom thresholds. Session tracking via
             cookies. Must solve initial JS challenge to get session.
```

---

## Defensive Perspective

### What Blue Team Sees
```
Your recon generates these defender-visible artifacts:
  - Firewall logs: source IP, dest port, timestamp, packet count
  - IDS/IPS alerts: signature matches (nmap -sS, nikto UA, etc.)
  - WAF logs: full HTTP requests, blocked payloads, source IP
  - Web server logs: User-Agent, URL, response code, source IP
  - DNS logs: query type, queried name, source IP
  - SIEM correlation: same source hitting multiple services

Reduce footprint:
  - Use realistic User-Agent strings (Chrome/Firefox current version)
  - Avoid default tool signatures (nikto, sqlmap, dirbuster UAs)
  - Don't run everything from the same IP
  - Space out scan phases (recon today, exploitation tomorrow)
  - Clean up: don't leave artifacts on target (uploaded files, modified data)
```
