# Advanced Reconnaissance Reference

## Passive Recon Deep Dive

### Certificate Transparency Log Mining
```bash
# crt.sh — comprehensive wildcard search
curl -s 'https://crt.sh/?q=%.target.com&output=json' | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > ct_subs.txt

# crt.sh — filter only recently issued certs (last 90 days)
curl -s 'https://crt.sh/?q=%.target.com&output=json' | \
  jq -r '.[] | select(.not_after > "2026-01-01") | .name_value' | sort -u

# crt.sh — find certificate issuers (reveals hosting/CDN providers)
curl -s 'https://crt.sh/?q=%.target.com&output=json' | \
  jq -r '.[].issuer_name' | sort | uniq -c | sort -rn

# Censys certificate search (API key required)
censys search 'services.tls.certificates.leaf.names: target.com' \
  --index-type hosts -o censys_hosts.json

# Censys — find IPs serving certs for a domain (origin IP discovery)
censys search 'services.tls.certificates.leaf.names: target.com' | \
  jq -r '.[] | .ip' | sort -u

# Google Certificate Transparency lookup
# https://transparencyreport.google.com/https/certificates
```

### DNS History & Intelligence
```bash
# SecurityTrails — historical DNS records (API)
curl -s "https://api.securitytrails.com/v1/history/target.com/dns/a" \
  -H "APIKEY: YOUR_KEY" | jq '.records[].values[].ip'

# SecurityTrails — associated domains (shared nameserver/MX/IP)
curl -s "https://api.securitytrails.com/v1/domain/target.com/associated" \
  -H "APIKEY: YOUR_KEY"

# ViewDNS.info — IP History (web: viewdns.info/iphistory/?domain=target.com)
# DNSDumpster — visual DNS mapping (web: dnsdumpster.com)

# Passive DNS aggregation with pDNS tools
# RiskIQ/PassiveTotal community API
curl -s "https://api.riskiq.net/pt/v2/dns/passive?query=target.com" \
  -u "user:key" | jq '.results[].resolve'
```

### Wayback Machine Endpoint Mining
```bash
# Pull all archived URLs
waybackurls target.com | sort -u > wayback_all.txt

# Find old API endpoints that may still work
cat wayback_all.txt | grep -iE '(api|v[0-9]|graphql|rest|json|xml)' | sort -u

# Find forgotten admin panels and login pages
cat wayback_all.txt | grep -iE '(admin|login|dashboard|manage|portal|console)' | sort -u

# Extract old config/backup files
cat wayback_all.txt | grep -iE '\.(bak|old|orig|swp|save|conf|config|env|sql|dump|zip|tar|gz)$' | sort -u

# Find credentials or secrets in archived pages
for url in $(cat wayback_all.txt | head -500); do
  content=$(curl -s "https://web.archive.org/web/2024/$url" 2>/dev/null)
  echo "$content" | grep -oiE '(password|secret|api.?key|token|auth)["\s:=]+[^\s"<]{4,}' && echo "^^^ $url"
done

# gau — multi-source URL aggregation (Wayback + CommonCrawl + OTX + URLScan)
gau target.com --subs --providers wayback,commoncrawl,otx | sort -u > gau_all.txt
gau target.com | unfurl -u domains | sort -u  # extract unique domains
gau target.com | unfurl -u paths | sort -u     # extract unique paths
```

### GitHub/GitLab Secret Scanning
```bash
# TruffleHog — scan org repos with verification
trufflehog github --org=target-org --only-verified --json > trufflehog_results.json
trufflehog github --repo=https://github.com/target/app --only-verified

# TruffleHog — scan specific branch or commit range
trufflehog git file:///path/to/cloned/repo --since-commit=abc123 --only-verified

# Gitleaks — regex-based scanning
gitleaks detect --source=https://github.com/target/repo --report-format=json --report-path=gitleaks.json
gitleaks detect --source=/path/to/repo --verbose

# GitHub code search (manual or via API)
# Effective search queries:
#   "target.com" password
#   "target.com" filename:.env
#   org:target "AWS_SECRET_ACCESS_KEY"
#   org:target filename:id_rsa
#   org:target filename:credentials
#   org:target extension:pem private
#   org:target "jdbc:mysql://"
#   org:target "mongodb+srv://"

# GitHub API search for code
gh api search/code -X GET -f q='org:target-org filename:.env' --jq '.items[].html_url'
gh api search/code -X GET -f q='"target.com" password' --jq '.items[].html_url'

# GitDorker — automated GitHub dorking
python3 gitdorker.py -t GITHUB_TOKEN -org target-org -d /path/to/dorks.txt

# GitLab-specific: search via API
curl -s "https://gitlab.com/api/v4/search?scope=blobs&search=target.com+password" \
  -H "PRIVATE-TOKEN: YOUR_TOKEN"
```

### Shodan / Censys / ZoomEye Advanced Queries
```bash
# Shodan — find all assets for an organization
shodan search 'org:"Target Corporation"' --fields ip_str,port,product,version
shodan search 'ssl.cert.subject.CN:target.com' --fields ip_str,port,product
shodan search 'ssl.cert.subject.CN:*.target.com' --fields ip_str,port,hostnames

# Shodan — find specific misconfigurations
shodan search 'hostname:target.com http.title:"Index of"'          # directory listing
shodan search 'hostname:target.com "default password"'              # default creds
shodan search 'hostname:target.com port:9200'                       # Elasticsearch
shodan search 'hostname:target.com port:27017'                      # MongoDB
shodan search 'hostname:target.com port:6379'                       # Redis
shodan search 'hostname:target.com product:"Jenkins"'               # Jenkins
shodan search 'net:203.0.113.0/24 port:22,80,443,3389'             # scan a range
shodan search 'asn:AS12345'                                         # full ASN search

# Shodan — download bulk results
shodan download target_results 'org:"Target Corporation"'
shodan parse target_results.json.gz --fields ip_str,port,product,version -O target_parsed.csv

# Censys — advanced host search
censys search 'services.http.response.body: "target.com"' --index-type hosts
censys search 'services.port: 3306 AND autonomous_system.asn: 12345'
censys search 'services.tls.certificates.leaf.subject.common_name: "*.target.com"'

# ZoomEye (web: zoomeye.org, API available)
# Queries: app:"Jenkins" +hostname:target.com
# Queries: service:"mysql" +ip:203.0.113.0/24
```

### ASN Mapping for Full IP Range Discovery
```bash
# Find the organization's ASN
whois -h whois.radb.net -- '-i origin AS12345' | grep -E '^route'
curl -s "https://api.bgpview.io/search?query_term=Target+Corp" | jq '.data.asns'

# Get all IP prefixes for an ASN
whois -h whois.radb.net -- '-i origin AS12345' | grep '^route:' | awk '{print $2}'
curl -s "https://api.bgpview.io/asn/12345/prefixes" | jq -r '.data.ipv4_prefixes[].prefix'

# Hurricane Electric BGP Toolkit (web: bgp.he.net)
# Search by org name, ASN, or IP — shows all announced prefixes

# Amass — ASN enumeration
amass intel -asn 12345 -o asn_domains.txt
amass intel -org "Target Corporation" -o org_asns.txt

# Map discovered IPs back to domains
cat ip_list.txt | while read ip; do
  host=$(dig -x "$ip" +short 2>/dev/null)
  echo "$ip → $host"
done
```

---

## JavaScript Analysis

### LinkFinder for Endpoint Extraction
```bash
# Crawl target and extract endpoints from all JS
linkfinder -i http://target.com -d -o cli | sort -u > js_endpoints.txt

# Analyze a specific JS file
linkfinder -i http://target.com/static/js/app.bundle.js -o cli

# HTML report for review
linkfinder -i http://target.com -d -o /tmp/linkfinder_report.html

# Bulk JS analysis from collected URLs
cat jsfiles.txt | while read url; do
  echo "--- $url ---"
  linkfinder -i "$url" -o cli 2>/dev/null
done | sort -u > all_js_endpoints.txt
```

### JSFScan — Comprehensive JS Scanning
```bash
# JSFScan wraps multiple tools (LinkFinder, SecretFinder, etc.)
# Install: git clone https://github.com/KathanP19/JSFScan.sh
bash JSFScan.sh -l jsfiles.txt --all -o jsfscandump

# Extract secrets only
bash JSFScan.sh -l jsfiles.txt --secrets -o jsfscandump

# Extract endpoints only
bash JSFScan.sh -l jsfiles.txt --endpoints -o jsfscandump
```

### Source Map Extraction
```bash
# Check if .map files exist (developers often leave them deployed)
cat jsfiles.txt | while read url; do
  mapurl="${url}.map"
  code=$(curl -s -o /dev/null -w '%{http_code}' "$mapurl")
  [ "$code" = "200" ] && echo "FOUND: $mapurl"
done

# Also check for sourceMappingURL comment inside JS
cat jsfiles.txt | while read url; do
  curl -s "$url" | grep -oP 'sourceMappingURL=\K[^\s]+' && echo " (in $url)"
done

# Recover original source from .map files
# npm install -g source-map-explorer
# source-map-explorer app.bundle.js app.bundle.js.map
# Or use: https://nicedoc.io/nicolo-ribaudo/source-map-unpack
# shuji — .map to source recovery
npx shuji app.bundle.js.map -o recovered_source/
```

### API Key and Secret Patterns in JS
```bash
# Comprehensive secret grep
cat jsfiles.txt | while read url; do
  curl -s "$url" | grep -oiE \
    'AKIA[0-9A-Z]{16}|'`                                    # AWS Access Key
    `'[a-zA-Z0-9/+=]{40}|'`                                 # AWS Secret (40 char base64)
    `'AIza[0-9A-Za-z\-_]{35}|'`                             # Google API Key
    `'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com|'` # Google OAuth
    `'sk_live_[0-9a-zA-Z]{24,}|'`                           # Stripe Secret Key
    `'pk_live_[0-9a-zA-Z]{24,}|'`                           # Stripe Publishable Key
    `'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}|'`                    # Square
    `'ghp_[0-9a-zA-Z]{36}|'`                                # GitHub Personal Token
    `'glpat-[0-9A-Za-z\-_]{20}|'`                           # GitLab Personal Token
    `'xox[bpoas]-[0-9a-zA-Z\-]{10,}|'`                      # Slack Token
    `'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'`  # JWT
  && echo " ^^^ FOUND IN: $url"
done
```

### GraphQL Introspection Discovery
```bash
# Common GraphQL paths to probe
for path in graphql graphiql v1/graphql v2/graphql api/graphql query gql; do
  code=$(curl -s -o /dev/null -w '%{http_code}' -X POST "http://target/$path" \
    -H 'Content-Type: application/json' \
    -d '{"query":"{__typename}"}')
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "GraphQL candidate: /$path (HTTP $code)"
done

# Full introspection query
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"query{__schema{queryType{name}mutationType{name}types{name kind description fields{name args{name type{name kind ofType{name kind}}}type{name kind ofType{name kind}}}}}}"}'

# Save introspection schema and visualize
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' | \
  python3 -m json.tool > graphql_schema.json

# Use graphql-voyager or InQL Burp extension for visualization
# clairvoyance — GraphQL schema discovery even when introspection is disabled
python3 -m clairvoyance http://target/graphql -o clairvoyance_schema.json
```

---

## API Reconnaissance

### Swagger/OpenAPI Endpoint Discovery
```bash
# Common OpenAPI/Swagger documentation paths
for path in \
  swagger.json swagger/v1/swagger.json openapi.json api-docs \
  v2/api-docs v3/api-docs api/swagger.json api/openapi.json \
  swagger-ui.html swagger-ui/ docs api/docs swagger-resources \
  .well-known/openapi.json api/v1/docs api/v2/docs; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://target/$path")
  [ "$code" = "200" ] && echo "FOUND: /$path"
done

# Download and parse OpenAPI spec
curl -s http://target/swagger.json | python3 -m json.tool > api_spec.json

# Extract all paths from OpenAPI spec
cat api_spec.json | jq -r '.paths | keys[]' | sort

# Extract all paths with methods
cat api_spec.json | jq -r '.paths | to_entries[] | .key as $path | .value | keys[] | "\(.) \($path)"'

# Generate API request list from spec
cat api_spec.json | jq -r '.paths | to_entries[] | .key as $path | .value | to_entries[] | "\(.key | ascii_upcase) \($path)"' > api_requests.txt
```

### WADL/WSDL Enumeration (SOAP/Legacy)
```bash
# WSDL discovery
for path in "?wsdl" "?WSDL" "/service?wsdl" "/ws?wsdl" "/api?wsdl" "/services?wsdl"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://target$path")
  [ "$code" = "200" ] && echo "WSDL: http://target$path"
done

# WADL discovery
for path in "application.wadl" "api/application.wadl"; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://target/$path")
  [ "$code" = "200" ] && echo "WADL: http://target/$path"
done
```

### API Versioning Detection
```bash
# URL-based versioning
for ver in v1 v2 v3 v4 v5 v1.0 v2.0 v1.1; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://target/api/$ver/")
  [ "$code" != "404" ] && echo "API version: /api/$ver/ (HTTP $code)"
done

# Header-based versioning — test with Accept header
curl -sI http://target/api/users -H 'Accept: application/vnd.target.v1+json'
curl -sI http://target/api/users -H 'Accept: application/vnd.target.v2+json'
curl -sI http://target/api/users -H 'X-API-Version: 1'
curl -sI http://target/api/users -H 'X-API-Version: 2'

# Old API versions often lack security patches — always test v1 if v2 exists
```

### Rate Limit Probing
```bash
# Detect rate limiting headers
curl -sI http://target/api/users | grep -iE '(x-rate|x-ratelimit|retry-after|x-limit)'

# Typical headers:
# X-RateLimit-Limit: 100
# X-RateLimit-Remaining: 99
# X-RateLimit-Reset: 1640000000
# Retry-After: 60

# Probe rate limit threshold
for i in $(seq 1 200); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://target/api/users)
  echo "$i → $code"
  [ "$code" = "429" ] && echo "Rate limited at request $i" && break
done
```

### Auth Mechanism Fingerprinting
```bash
# Check 401/403 response headers
curl -sI http://target/api/users
# WWW-Authenticate: Bearer → OAuth2 / JWT
# WWW-Authenticate: Basic  → Basic Auth
# WWW-Authenticate: NTLM   → Windows/AD auth

# Check for API key schemes
curl -sI http://target/api/users -H 'X-API-Key: invalid'
curl -sI http://target/api/users -H 'Authorization: Bearer invalid'

# Test auth bypass patterns
curl -s http://target/api/v1/admin/users                      # direct access
curl -s http://target/api/v1/admin/users -H 'X-Original-URL: /api/v1/admin/users'
curl -s http://target/api/v1/admin/users -H 'X-Forwarded-For: 127.0.0.1'
```

---

## Cloud Asset Discovery

### S3 Bucket Enumeration
```bash
# Common bucket naming patterns to test
for prefix in target target-com target-dev target-staging target-prod target-backup \
  target-assets target-uploads target-media target-logs target-data target-static \
  target.com www-target dev-target stg-target; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://${prefix}.s3.amazonaws.com")
  case $code in
    200) echo "PUBLIC: ${prefix}.s3.amazonaws.com" ;;
    403) echo "EXISTS (denied): ${prefix}.s3.amazonaws.com" ;;
    301) echo "REDIRECT: ${prefix}.s3.amazonaws.com" ;;
  esac
done

# cloud_enum — automated multi-cloud brute
cloud_enum -k target -k target.com -k targetcorp --disable-azure --disable-gcp

# S3Scanner — dedicated S3 tool
s3scanner scan --bucket-file bucket_names.txt
```

### Azure Blob Brute-Force
```bash
# Azure storage account naming conventions
for name in target targetdev targetstg targetprod targetbackup; do
  for service in blob file queue table; do
    code=$(curl -s -o /dev/null -w '%{http_code}' "https://${name}.${service}.core.windows.net/?comp=list")
    [ "$code" != "000" ] && [ "$code" != "400" ] && echo "${name}.${service}.core.windows.net → $code"
  done
done

# Azure webapp discovery
for name in target target-dev target-staging target-api; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://${name}.azurewebsites.net")
  [ "$code" != "000" ] && echo "${name}.azurewebsites.net → $code"
done
```

### GCP Bucket Discovery
```bash
# GCP bucket enumeration
for name in target target-dev target-backup target-data target-uploads; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "https://storage.googleapis.com/${name}")
  [ "$code" = "200" ] && echo "PUBLIC: storage.googleapis.com/${name}"
  [ "$code" = "403" ] && echo "EXISTS: storage.googleapis.com/${name}"
done

# Firebase default endpoints
curl -s "https://target-default-rtdb.firebaseio.com/.json"
curl -s "https://target.firebaseio.com/.json"
```

### Cloud IP Range Identification
```bash
# AWS published IP ranges
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json | \
  jq -r '.prefixes[] | select(.region=="us-east-1") | .ip_prefix'

# Azure published IP ranges
curl -sL https://www.microsoft.com/en-us/download/details.aspx?id=56519
# Download ServiceTags_Public JSON and parse

# GCP published IP ranges
dig TXT _cloud-netblocks.googleusercontent.com +short
# Resolve each included SPF range

# Check if a target IP belongs to a cloud provider
whois 52.94.76.10 | grep -iE '(org-name|orgname|netname)'
# Amazon → AWS, Microsoft → Azure, Google → GCP
```

### Subdomain Takeover Detection
```bash
# Check for dangling CNAME records
cat all_subdomains.txt | while read sub; do
  cname=$(dig CNAME "$sub" +short)
  if [ -n "$cname" ]; then
    # Check if CNAME target resolves
    ip=$(dig +short "$cname")
    [ -z "$ip" ] && echo "POTENTIAL TAKEOVER: $sub → $cname (NXDOMAIN)"
  fi
done

# Automated takeover detection
# subjack — fast subdomain takeover scanner
subjack -w all_subdomains.txt -t 50 -timeout 30 -o takeover_results.txt -ssl

# nuclei with takeover templates
nuclei -l all_subdomains.txt -t /root/nuclei-templates/http/takeovers/ -o takeovers.txt

# Fingerprints indicating takeover potential:
# "There isn't a GitHub Pages site here" → GitHub Pages
# "NoSuchBucket" → S3
# "The specified bucket does not exist" → S3
# "Fastly error: unknown domain" → Fastly
# "No such app" → Heroku
# "NXDOMAIN" on CNAME to *.azurewebsites.net → Azure
```

---

## WAF/CDN Fingerprinting

### WAF Detection and Identification
```bash
# wafw00f — primary WAF detection
wafw00f http://target -a            # aggressive mode
wafw00f http://target -v            # verbose output

# Manual header-based detection
curl -sI http://target | grep -iE '(cf-ray|server: cloudflare)'           # Cloudflare
curl -sI http://target | grep -iE '(x-amz|x-amzn|server: awselb)'        # AWS WAF/ALB
curl -sI http://target | grep -iE '(x-akamai|akamai)'                    # Akamai
curl -sI http://target | grep -iE '(x-sucuri|server: sucuri)'            # Sucuri
curl -sI http://target | grep -iE '(x-cdn|x-iinfo|incap_ses|visid_incap)' # Imperva/Incapsula

# Cookie-based detection
curl -sI http://target | grep -i 'set-cookie'
# __cfduid / cf_clearance → Cloudflare
# incap_ses_ / visid_incap_ → Imperva
# BigipServer → F5 BIG-IP
# citrix_ns → Citrix NetScaler
# ts= / TSPD_ → Imperva (TransparentProxy)

# Trigger WAF with malicious payload and inspect response
curl -s "http://target/?id=1' OR 1=1--" -o /dev/null -w '%{http_code}'  # SQLi trigger
curl -s "http://target/?q=<script>alert(1)</script>" -o /dev/null -w '%{http_code}'  # XSS trigger
# 403/406/429 with distinctive body → WAF blocking
```

### Finding Origin IP Behind CDN
```bash
# Method 1: Historical DNS (pre-CDN IP)
# SecurityTrails → DNS History → look at A records from years ago
# ViewDNS.info → IP History

# Method 2: Email headers — send email that triggers bounce/reply
# Examine Received: headers for origin IP
# Subscribe to newsletter, request password reset, etc.

# Method 3: Non-CDN subdomains
for sub in mail ftp cpanel webmail direct origin smtp pop imap dev staging; do
  ip=$(dig +short ${sub}.target.com | head -1)
  [ -n "$ip" ] && echo "${sub}.target.com → $ip"
done

# Method 4: Certificate search on Censys/Shodan
shodan search 'ssl.cert.subject.CN:target.com' --fields ip_str,port
censys search 'services.tls.certificates.leaf.names: target.com' | jq -r '.[] | .ip'

# Method 5: SPF record leaks origin IP
dig target.com TXT +short | grep spf
# "v=spf1 ip4:203.0.113.10" → origin web server IP

# Method 6: Content matching
# Find a unique string on target.com, search Shodan/Censys for it
shodan search 'http.html:"Unique Footer Text 2025 Target Corp"'

# Method 7: XML-RPC/webhook callback
# If WordPress: trigger XML-RPC pingback to your server, source IP = origin
# If any SSRF exists: callback to your listener shows origin IP

# Verify origin IP once found
curl -sI -H 'Host: target.com' http://203.0.113.10/
# Should return same content as target.com through CDN
```

### WAF-Specific Bypass Considerations
```
Cloudflare:
  - Uses cf-ray header, __cfduid cookie
  - Under-attack mode adds JS challenge
  - Bypass: find origin IP, use direct IP with Host header
  - Rate limiting often per-IP, rotate sources

AWS WAF:
  - Paired with ALB/CloudFront
  - Rules are regex-based, test case variations
  - X-Forwarded-For sometimes trusted internally
  - Bypass: unicode normalization, chunked encoding

Akamai:
  - Bot Manager detects automation fingerprints
  - Use legitimate User-Agent strings
  - Slow request rate to avoid behavior detection
  - Bypass: HTTP/2, realistic headers, session cookies

ModSecurity:
  - CRS (Core Rule Set) is most common
  - Paranoia levels 1-4 (higher = stricter)
  - Bypass: double URL encoding, multipart form boundaries
  - Bypass: using synonyms (UNION → /*!UNION*/)

Imperva/Incapsula:
  - Sets incap_ses and visid_incap cookies
  - JavaScript challenge on first visit
  - Bypass: solve JS challenge, maintain session
  - Direct IP access if origin found

Generic bypass techniques:
  - HTTP parameter pollution (HPP): ?id=1&id=2
  - Unicode/UTF-8 encoding of payloads
  - Chunked Transfer-Encoding manipulation
  - Null bytes: %00 insertion
  - HTTP method switching: GET → POST
  - Content-Type manipulation
  - Newline injection in headers
```
