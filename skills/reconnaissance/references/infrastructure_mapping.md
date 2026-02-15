# Infrastructure Mapping Reference

## DNS Enumeration

### Zone Transfer
```bash
# Attempt zone transfer (AXFR) — often blocked but always try
dig axfr target.com @ns1.target.com
dig axfr target.com @ns2.target.com
dnsrecon -d target.com -t axfr

# If successful, provides complete DNS zone data
# Includes all subdomains, MX, NS, TXT, CNAME records
```

### Standard DNS Records
```bash
# All record types
dig target.com ANY +noall +answer

# Specific records
dig target.com A +short              # IPv4 addresses
dig target.com AAAA +short           # IPv6 addresses
dig target.com MX +short             # mail servers
dig target.com NS +short             # name servers
dig target.com TXT +short            # SPF, DKIM, DMARC, verification
dig target.com CNAME +short          # canonical names
dig target.com SOA +short            # start of authority

# TXT records reveal infrastructure
# SPF records: "v=spf1 include:_spf.google.com ~all" → using Google Workspace
# DMARC: "_dmarc.target.com" → email security posture
# Verification: "google-site-verification=..." → Google services
# Other: "MS=..." → Microsoft 365, "docusign=..." → DocuSign
```

### Reverse DNS
```bash
# Single IP
dig -x 93.184.216.34 +short

# Scan a range
dnsrecon -r 93.184.216.0/24 -t rvl

# Find other domains on same IP (reverse IP lookup)
# Tools: ViewDNS.info, HackerTarget, SecurityTrails
```

---

## Subdomain Enumeration

### Passive Enumeration (No Target Interaction)
```bash
# subfinder — multi-source passive discovery
subfinder -d target.com -all -o subs_subfinder.txt
subfinder -d target.com -all -cs -o subs_with_source.txt   # show sources

# amass — comprehensive passive enum
amass enum -passive -d target.com -o subs_amass.txt

# Certificate transparency
curl -s 'https://crt.sh/?q=%.target.com&output=json' | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > subs_ct.txt

# Merge all passive results
cat subs_*.txt | sort -u > all_subdomains.txt
```

### Active Brute-Force (Requires Authorization)
```bash
# gobuster DNS mode
gobuster dns -d target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -t 50 -o subs_brute.txt

# dnsenum with brute-force
dnsenum target.com --enum -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# amass active mode
amass enum -active -d target.com -brute -o subs_active.txt

# puredns — mass resolve with wildcard filtering
puredns bruteforce wordlist.txt target.com -r resolvers.txt -o subs_puredns.txt
```

### Verify Live Subdomains
```bash
# Resolve DNS and check HTTP
cat all_subdomains.txt | httpx -silent -status-code -title -o live_subs.txt

# With full details
cat all_subdomains.txt | httpx -status-code -title -tech-detect \
  -content-length -web-server -json -o live_subs.json

# DNS resolution only
cat all_subdomains.txt | while read sub; do
  ip=$(dig +short "$sub" | head -1)
  [ -n "$ip" ] && echo "$sub → $ip"
done
```

---

## VHost Discovery

### Brute-Force Virtual Hosts
```bash
# Get default response size first
curl -s http://TARGET/ | wc -c    # note the size

# ffuf vhost discovery
ffuf -u http://TARGET -H 'Host: FUZZ.target.com' \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -fs <default_size> -o vhosts.json -of json

# gobuster vhost mode
gobuster vhost -u http://target.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain

# Note: vhosts may exist without DNS records
# They respond differently based on Host header
```

---

## CDN Bypass (Finding Origin IP)

### Indicators of CDN
```bash
# Check if behind CDN
nslookup target.com        # multiple IPs or CDN ranges = CDN
dig target.com +short       # Cloudflare: 104.x.x.x, 172.64.x.x
curl -sI http://target | grep -iE '(cf-ray|server: cloudflare|x-cdn|x-cache|x-amz-cf)'
wafw00f http://target       # identifies CDN/WAF vendor
```

### Finding Origin IP
```bash
# Historical DNS records
# SecurityTrails: show DNS history → find pre-CDN IP
# ViewDNS.info → IP History

# Subdomains not behind CDN
# mail.target.com, ftp.target.com, dev.target.com, staging.target.com
# Direct IP often used for non-web services
dig mail.target.com +short
dig ftp.target.com +short
dig direct.target.com +short

# SPF/TXT record analysis
dig target.com TXT +short
# "v=spf1 ip4:203.0.113.10 ..." → origin IP in SPF

# MX record analysis
dig target.com MX +short
# Mail server may be on same IP as web server

# Censys certificate search
censys search 'services.tls.certificates.leaf.names: target.com'
# Returns all IPs serving certs for the domain

# Shodan
shodan search 'ssl.cert.subject.CN:target.com'
# Or: shodan search 'http.html:"unique string from target"'

# Once origin IP found, verify:
curl -sI -H 'Host: target.com' http://ORIGIN_IP/
# Should return same content as target.com
```

---

## Cloud Asset Discovery

### AWS Assets
```bash
# S3 bucket enumeration
curl -s http://target.s3.amazonaws.com        # direct bucket
curl -s http://s3.amazonaws.com/target        # path-style
# Brute-force: cloud_enum, S3Scanner, bucket_finder

# Common AWS patterns
target.s3.amazonaws.com
target-dev.s3.amazonaws.com
target-staging.s3.amazonaws.com
target-backup.s3.amazonaws.com
target-assets.s3.amazonaws.com

# CloudFront distributions
nslookup target.com   # *.cloudfront.net CNAME
```

### Azure Assets
```bash
# Blob storage
curl -s https://target.blob.core.windows.net/?comp=list
# App Service
curl -s https://target.azurewebsites.net

# Common Azure patterns
target.blob.core.windows.net
target.file.core.windows.net
target.queue.core.windows.net
target.table.core.windows.net
target.azurewebsites.net
target.database.windows.net
```

### GCP Assets
```bash
# Storage buckets
curl -s https://storage.googleapis.com/target
# Cloud Run / App Engine
curl -s https://target.appspot.com

# Common GCP patterns
storage.googleapis.com/target
target.appspot.com
target.cloudfunctions.net
```

### Automated Cloud Enum
```bash
# cloud_enum — multi-cloud asset discovery
cloud_enum -k target -k target.com -k targetcorp

# Outputs discovered S3 buckets, Azure blobs, GCP buckets
```

---

## WAF Identification

### wafw00f
```bash
wafw00f http://target                     # detect WAF
wafw00f -l                                # list known WAFs
wafw00f -a http://target                  # aggressive detection

# Common WAFs and their tells:
# Cloudflare  → cf-ray header, 403 body contains "cloudflare"
# AWS WAF     → x-amzn-requestid, 403 body
# Akamai      → akamai-ghost headers
# Imperva     → incap_ses cookie, visid_incap
# ModSecurity → Server: Apache + distinctive 403
# F5 BIG-IP   → BigipServer cookie
```

### WAF Bypass Implications
```
Knowing the WAF helps choose:
- Payload encoding (URL, Unicode, double-encode)
- Request chunking (Transfer-Encoding manipulation)
- HTTP method switching (GET → POST)
- Case variation and null bytes
- Refer to exploitation skill references for specific bypass payloads
```
