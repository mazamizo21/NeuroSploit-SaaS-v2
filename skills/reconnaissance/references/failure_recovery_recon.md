# Failure Recovery — When Recon Stalls

## Purpose
Standard recon doesn't always work. This reference covers what to try
when your normal tools return nothing, hit walls, or produce unreliable results.

---

## Port Scan Shows Nothing

**Symptom:** `nmap` returns 0 open ports or "host seems down."

### Cause 1: Host Discovery Failing (ICMP Blocked)
```bash
# Skip host discovery entirely
nmap -Pn -sS -p 80,443,22,8080,8443 target

# Try different discovery methods
nmap -PS80,443 target          # TCP SYN discovery on web ports
nmap -PA80,443 target          # TCP ACK discovery
nmap -PU53,161 target          # UDP discovery
nmap -PY target                # SCTP discovery
```

### Cause 2: Firewall Dropping SYN Packets
```bash
# TCP connect scan (completes 3-way handshake — harder to silently drop)
nmap -sT -Pn -p 80,443,22,8080,3389 target

# ACK scan (finds filtered vs unfiltered — maps firewall rules)
nmap -sA -Pn -p 1-1000 target

# Window scan (like ACK but can distinguish open/closed on some systems)
nmap -sW -Pn -p 1-1000 target

# FIN scan (some firewalls only filter SYN)
nmap -sF -Pn -p 1-1000 target
```

### Cause 3: Behind Load Balancer / CDN
```bash
# CDN only proxies 80/443 — scan the origin IP directly
# Find origin: SecurityTrails DNS history, SPF records, Censys cert search
dig target.com TXT +short | grep spf    # look for ip4: entries

# Scan origin IP with Host header
nmap -Pn -sS -p- ORIGIN_IP
curl -sI -H 'Host: target.com' http://ORIGIN_IP/
```

### Cause 4: UDP Services Only
```bash
# Top UDP ports
nmap -sU -Pn --top-ports 100 target -oA udp_scan

# Specific high-value UDP services
nmap -sU -Pn -p 53,69,123,161,162,500,514,1900,5353 target

# Faster UDP scan (less accurate but quick)
nmap -sU -Pn --max-retries 1 --min-rate 500 -p 1-1000 target
```

### Cause 5: Non-Standard Ports
```bash
# Common alternative web ports
nmap -Pn -sS -p 81,443,3000,4443,5000,5443,8000,8008,8080,8081,8443,8888,9000,9090,9443,10000 target

# Full port scan if authorized
nmap -Pn -sS -p- --min-rate 1000 target -oA full_scan

# Check if IPv6 is exposed but IPv4 is firewalled
nmap -6 -sS -p 80,443 target_ipv6
dig AAAA target.com +short
```

---

## Directory Brute-Force Finds Nothing

**Symptom:** gobuster/ffuf returns 0 results or only false positives.

### Try Different Wordlists
```bash
# Escalate through wordlist sizes
# Quick: 4,614 entries
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -t 50

# Medium: 30,000 entries
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50

# Large: 220,546 entries
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 30

# Technology-specific wordlists
# IIS: /usr/share/seclists/Discovery/Web-Content/IIS.fuzz.txt
# Tomcat: /usr/share/seclists/Discovery/Web-Content/tomcat.txt
# API: /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
# CGI: /usr/share/seclists/Discovery/Web-Content/CGIs.txt
```

### Try File Extensions
```bash
# Technology-appropriate extensions
ffuf -u http://target/FUZZ -w wordlist.txt -e .php,.html,.txt,.bak,.old,.conf,.xml,.json,.yml \
  -mc 200,301,302,403

# Backup/dev extensions (often forgotten)
ffuf -u http://target/FUZZ -w wordlist.txt -e .bak,.old,.orig,.save,.swp,.tmp,.~,.copy,.dist \
  -mc 200

# Language-specific
# PHP:  .php,.php3,.php4,.php5,.phtml,.phar
# ASP:  .asp,.aspx,.asmx,.ashx,.svc
# Java: .jsp,.jsf,.do,.action,.jspx
# Ruby: .rb,.erb
# Python: .py,.pyc
```

### Try Recursive Mode
```bash
# feroxbuster excels at recursive discovery
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 4 -t 30 -o ferox_deep.txt

# Fuzz within discovered directories
gobuster dir -u http://target/api/ -w wordlist.txt -t 50
gobuster dir -u http://target/admin/ -w wordlist.txt -t 50
```

### Try VHost / Hostname Brute-Force
```bash
# Different sites on same IP respond to different Host headers
ffuf -u http://TARGET_IP -H 'Host: FUZZ.target.com' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs $(curl -s http://TARGET_IP/ | wc -c)

# Also try non-subdomain vhosts
ffuf -u http://TARGET_IP -H 'Host: FUZZ' \
  -w /usr/share/seclists/Discovery/DNS/namelist.txt -fs $(curl -s http://TARGET_IP/ | wc -c)
```

### Wildcard / Custom 404 Handling
```bash
# If everything returns 200 (wildcard response)
# Filter by response size
ffuf -u http://target/FUZZ -w wordlist.txt -fs $(curl -s http://target/randomstring12345 | wc -c)

# Filter by word count or line count
ffuf -u http://target/FUZZ -w wordlist.txt -fw WORD_COUNT
ffuf -u http://target/FUZZ -w wordlist.txt -fl LINE_COUNT

# Filter by response hash (auto-calibrate)
ffuf -u http://target/FUZZ -w wordlist.txt -ac   # auto-calibrate filters
```

---

## Subdomain Enumeration Returns Empty

**Symptom:** subfinder/amass return 0 or very few subdomains.

### Use Multiple Sources
```bash
# Layer multiple passive tools
subfinder -d target.com -all -o subs1.txt
amass enum -passive -d target.com -o subs2.txt
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u > subs3.txt
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns" | \
  jq -r '.passive_dns[].hostname' | sort -u > subs4.txt

# SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: KEY" | jq -r '.subdomains[]' | sed 's/$/.target.com/' > subs5.txt

# Merge all
cat subs*.txt | sed 's/\*\.//g' | sort -u > all_subs.txt
echo "Found $(wc -l < all_subs.txt) unique subdomains"
```

### Try Permutation / Mutation
```bash
# altdns — generate permutations and resolve
altdns -i all_subs.txt -o permuted.txt -w /usr/share/seclists/Discovery/DNS/dns-prefixes.txt
cat permuted.txt | puredns resolve --resolvers resolvers.txt -o resolved_permutations.txt

# dnsgen — smarter permutation
cat all_subs.txt | dnsgen - | puredns resolve --resolvers resolvers.txt -o dnsgen_resolved.txt

# Common patterns to try manually
for pre in dev staging stg qa uat test demo beta alpha prod api mail vpn; do
  dig +short ${pre}.target.com | head -1 | grep -v '^$' && echo " → ${pre}.target.com"
done
```

### Check for Wildcard DNS
```bash
# Detect wildcard: query a random non-existent subdomain
dig +short randomnonexistent12345.target.com
# If it resolves → wildcard DNS is configured
# All subdomain brute-force will return false positives

# Work around wildcard: filter by the wildcard IP
WILDCARD_IP=$(dig +short randomnonexistent12345.target.com)
cat brute_results.txt | while read sub; do
  ip=$(dig +short "$sub")
  [ "$ip" != "$WILDCARD_IP" ] && echo "$sub → $ip"
done
```

### Active DNS Brute-Force (Authorized)
```bash
# Large wordlist brute with puredns (wildcard-aware)
puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  target.com -r resolvers.txt -o brute_subs.txt

# Gobuster DNS with larger wordlist
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt \
  -t 50 -o gobuster_dns.txt
```

---

## WAF Blocking All Scans

**Symptom:** Every request returns 403, CAPTCHA, or connection drops.

### Slow Down Significantly
```bash
# Very low rate scanning
ffuf -u http://target/FUZZ -w wordlist.txt -rate 5 -p 2-5
gobuster dir -u http://target -w wordlist.txt --delay 3000ms -t 1

# Add jitter (random delays)
cat wordlist.txt | while read word; do
  curl -s -o /dev/null -w '%{http_code} %{url_effective}\n' "http://target/$word" \
    -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  sleep $(python3 -c "import random; print(random.uniform(1,5))")
done
```

### Blend with Legitimate Traffic
```bash
# Use realistic User-Agent
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
ffuf -u http://target/FUZZ -w wordlist.txt -H "User-Agent: $UA" -rate 10

# Add standard browser headers
curl -s http://target/ \
  -H "User-Agent: $UA" \
  -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' \
  -H 'Accept-Language: en-US,en;q=0.5' \
  -H 'Accept-Encoding: gzip, deflate' \
  -H 'Connection: keep-alive' \
  -H 'Upgrade-Insecure-Requests: 1'

# Try HTTP/2 (some WAFs only inspect HTTP/1.1)
curl --http2 -s http://target/
```

### Change Source IP
```bash
# Switch VPN server
# Switch to cloud instance
# Use a residential proxy

# Test if IP is specifically blacklisted
curl -s -o /dev/null -w '%{http_code}' http://target/      # from current IP
# Compare from different IP — if new IP works, you're IP-banned
```

### Try Alternative Entry Points
```bash
# Scan non-standard ports (WAF may only protect 80/443)
nmap -Pn -sS -p 8080,8443,3000,4443,9090,9443 target

# Scan the origin IP directly (bypass CDN/WAF entirely)
# Use techniques from CDN Bypass section

# Try IP-based access (WAF rules may be hostname-specific)
curl -sI http://93.184.216.34/ -H 'Host: target.com'
```

---

## No Web Application Found

**Symptom:** Port 80/443 closed or returns generic page.

### Check Non-Standard Web Ports
```bash
# Comprehensive web port scan
nmap -Pn -sS -p 80,81,443,3000,4443,5000,5001,5443,8000,8008,8080,8081,8443,8888,9000,9090,9443,10000 target

# Verify each with HTTP request
for port in 80 81 443 3000 4443 5000 8000 8080 8081 8443 8888 9000 9090 9443 10000; do
  for scheme in http https; do
    title=$(curl -sk --connect-timeout 3 "${scheme}://target:${port}/" -o /dev/null -w '%{http_code}' 2>/dev/null)
    [ "$title" != "000" ] && echo "${scheme}://target:${port}/ → HTTP $title"
  done
done
```

### Check HTTPS Specifically
```bash
# Some servers respond on HTTPS but not HTTP
curl -sk https://target/ | head -20
curl -sk https://target:8443/ | head -20

# Check TLS certificate for hostname hints
openssl s_client -connect target:443 </dev/null 2>/dev/null | \
  openssl x509 -noout -text | grep -E '(Subject:|DNS:)'
```

### Try IP vs Hostname Access
```bash
# Server may require specific hostname
curl -s http://target/                              # by hostname
curl -s http://IP_ADDRESS/                          # by IP
curl -s http://IP_ADDRESS/ -H 'Host: target.com'   # IP with Host header
curl -s http://IP_ADDRESS/ -H 'Host: www.target.com'

# Try other hostnames that might resolve to this IP
# Check reverse DNS
dig -x IP_ADDRESS +short
```

### Check Non-HTTP Services
```bash
# Target might not be a web server at all
# Full service scan on discovered ports
nmap -Pn -sV -sC -p OPEN_PORTS target -oA service_scan

# Common non-web services to check
nmap -Pn -sV -p 21,22,23,25,53,110,111,135,139,143,161,389,445,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,27017 target
```

---

## Everything Looks Normal But You're Missing Things

### Expand Scope Checklist
```bash
# Did you check ALL subdomains?
subfinder -d target.com -all | wc -l    # should be >0

# Did you check JavaScript files for hidden endpoints?
gau target.com | grep '\.js$' | sort -u | head -20

# Did you check API documentation?
for path in swagger.json openapi.json api-docs graphql; do
  curl -s -o /dev/null -w '%{http_code}' "http://target/$path" && echo " $path"
done

# Did you check cloud assets?
cloud_enum -k target -k target.com 2>/dev/null | grep -v 'not found'

# Did you check for subdomain takeovers?
cat all_subs.txt | while read sub; do
  cname=$(dig CNAME +short "$sub")
  [ -n "$cname" ] && echo "$sub → $cname"
done

# Did you check Wayback for old/forgotten pages?
waybackurls target.com | grep -iE '(admin|config|backup|test|debug)' | sort -u
```
