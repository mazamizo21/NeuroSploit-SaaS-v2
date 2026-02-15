# OSINT Methodology Reference

## Phase Order
```
1. Passive collection — no target interaction
2. Semi-passive validation — minimal, indirect interaction
3. Active verification — direct contact (only if authorized)
```

---

## Google Dorking

### Discovery Dorks
```
site:target.com                           # all indexed pages
site:target.com filetype:pdf              # PDF documents
site:target.com filetype:xlsx             # Excel files
site:target.com filetype:docx             # Word documents
site:target.com filetype:sql              # SQL dumps
site:target.com filetype:log              # log files
site:target.com filetype:bak             # backup files
site:target.com filetype:conf            # configuration files
site:target.com filetype:env             # environment files
```

### Sensitive Data Dorks
```
site:target.com inurl:admin               # admin panels
site:target.com inurl:login               # login pages
site:target.com inurl:dashboard           # dashboards
site:target.com intitle:"index of"        # directory listings
site:target.com intext:"password"         # credential leaks
site:target.com intext:"api_key"          # API keys
site:target.com ext:xml | ext:json        # data files
site:target.com inurl:wp-content          # WordPress installs
site:target.com inurl:phpinfo             # PHP info pages
```

### Third-Party Leaks
```
"target.com" site:pastebin.com            # paste sites
"target.com" site:github.com              # code repositories
"target.com" site:trello.com              # project boards
"target.com" site:stackoverflow.com       # developer questions
"@target.com" site:linkedin.com           # employee profiles
"target.com" site:shodan.io               # Shodan results
intext:"target.com" filetype:env          # .env files
intext:"target.com" "DB_PASSWORD"         # database credentials
```

---

## Shodan

### CLI Usage
```bash
# Initialize (one-time)
shodan init YOUR_API_KEY

# Host lookup
shodan host 93.184.216.34

# Search
shodan search 'hostname:target.com'
shodan search 'org:"Target Corporation"'
shodan search 'ssl.cert.subject.CN:target.com'
shodan search 'http.title:"Target Admin" port:443'

# Count results
shodan count 'hostname:target.com'

# Download results
shodan download results 'hostname:target.com'
shodan parse results.json.gz --fields ip_str,port,org
```

### Useful Shodan Filters
```
hostname:target.com          # reverse DNS match
org:"Target Inc"             # organization name
ssl.cert.subject.CN:*.target.com  # certificate CN
http.title:"Dashboard"       # HTTP title
port:3389                    # RDP exposed
product:"Apache"             # specific product
vuln:CVE-2021-44228          # known CVE (paid)
city:"New York"              # geographic filter
```

### Censys CLI
```bash
censys search 'services.tls.certificates.leaf.names: target.com'
censys search 'services.http.response.body: "target.com"'
censys view 93.184.216.34
```

---

## Certificate Transparency

### crt.sh Queries
```bash
# Find all certificates for domain
curl -s 'https://crt.sh/?q=%.target.com&output=json' | \
  jq -r '.[].name_value' | sort -u > ct_subdomains.txt

# Filter by date (recent certs)
curl -s 'https://crt.sh/?q=%.target.com&output=json' | \
  jq -r '.[] | select(.not_before > "2024-01-01") | .name_value' | sort -u

# Wildcard search
curl -s 'https://crt.sh/?q=%.%.target.com&output=json' | \
  jq -r '.[].name_value' | sort -u
```

### Alternative CT Sources
- Google Transparency Report: `transparencyreport.google.com`
- Censys: certificate search
- Facebook CT: `developers.facebook.com/tools/ct`

---

## GitHub Secret Scanning

### Manual GitHub Search
```
# Search in GitHub (web or API)
"target.com" password
"target.com" api_key
"target.com" secret
"target.com" AWS_ACCESS_KEY
"target.com" PRIVATE KEY
org:target-org filename:.env
org:target-org filename:config extension:yml password
```

### Automated Tools
```bash
# TruffleHog — scans git history for secrets
trufflehog github --org=target-org --only-verified
trufflehog git file:///path/to/repo --only-verified

# Gitleaks — fast regex-based secret scanner
gitleaks detect --source=/path/to/repo --report-format=json --report-path=leaks.json
gitleaks detect --source=https://github.com/target/repo

# GitDorker — GitHub dork automation
python3 gitdorker.py -t TOKEN -org target-org -d dorks.txt
```

---

## LinkedIn / Employee Enumeration

### Methodology
```
1. Search: "Target Company" on LinkedIn
2. Map: executives, IT staff, DevOps, security team
3. Pattern: Identify email format from About/Contact pages
   - first.last@target.com
   - f.last@target.com
   - firstl@target.com
4. Verify: Use email verification tools (hunter.io, emailhippo)
5. Build: Username/email wordlists for later phases
```

### Email Pattern Discovery
```bash
# theHarvester — multi-source email harvesting
theHarvester -d target.com -b all -l 500 -f harvester_results

# hunter.io — discover email pattern
# API: https://api.hunter.io/v2/domain-search?domain=target.com&api_key=KEY

# phonebook.cz — free email search
# Web: https://phonebook.cz/ (search by domain)

# CrossLinked — LinkedIn scraping for email generation
crosslinked -f '{first}.{last}@target.com' 'Target Company'
```

---

## OSINT Frameworks & Aggregators

### Tools
```bash
# Recon-ng — modular OSINT framework
recon-ng
[recon-ng] > marketplace install all
[recon-ng] > modules search
[recon-ng] > use recon/domains-hosts/google_site_web

# SpiderFoot — automated OSINT collection
spiderfoot -s target.com -o output.json

# Maltego — visual link analysis (GUI)
# theHarvester + Amass + subfinder — for comprehensive subdomain + email enum
```

### Passive DNS Services
```
SecurityTrails  — historical DNS, WHOIS
ViewDNS.info    — reverse IP, DNS history
DNSDumpster     — DNS recon and mapping
RiskIQ          — passive DNS and web components
```

### WHOIS Intelligence
```bash
whois target.com                    # registrant, NS, dates
whois 93.184.216.34                 # IP WHOIS (netblock, ASN, org)
# Reverse WHOIS: find other domains by same registrant
# Tools: ViewDNS reverse WHOIS, DomainTools
```
