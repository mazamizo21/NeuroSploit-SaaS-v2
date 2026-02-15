# Web Recon Reference

## Content Discovery

### Directory Brute-Force
```bash
# Gobuster — fast, Go-based
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt -t 50 \
  -o gobuster_dirs.txt -x php,html,txt,bak

# ffuf — flexible fuzzer
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -mc 200,301,302,403 -o ffuf_dirs.json -of json

# dirsearch — Python, feature-rich
dirsearch -u http://target -e php,html,js,txt,bak -x 400,404 -t 50 --format json -o dirsearch.json

# feroxbuster — recursive, Rust-based
feroxbuster -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 3 -o ferox.txt

# Recursive discovery pattern
# 1. First pass: common.txt → find directories
# 2. Second pass: fuzz each discovered directory
# 3. Look for backup files: .bak, .old, .swp, ~, .orig
```

### Wordlist Selection
```
/usr/share/wordlists/dirb/common.txt              # 4,614 — quick scan
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt  # 30,000 — thorough
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  # 220,546 — comprehensive
/usr/share/seclists/Discovery/Web-Content/big.txt  # 20,469 — files
/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt  # case-insensitive
```

### File Discovery
```bash
# Backup files
ffuf -u http://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt \
  -mc 200 -e .bak,.old,.swp,.orig,.save,.tmp

# Config files
ffuf -u http://target/FUZZ -w config_files.txt -mc 200
# Check: .htaccess, web.config, robots.txt, sitemap.xml, crossdomain.xml
# Check: .env, .git/config, .svn/entries, .DS_Store, composer.json, package.json

# Source code exposure
curl -s http://target/.git/HEAD          # git repo exposed?
curl -s http://target/.svn/entries       # SVN exposed?
curl -s http://target/.env               # environment variables?
```

---

## Parameter Discovery

### Arjun
```bash
# GET parameter discovery
arjun -u http://target/endpoint -oJ params.json

# POST parameter discovery
arjun -u http://target/endpoint -m POST -oJ params_post.json

# JSON body
arjun -u http://target/api/endpoint -m JSON -oJ params_json.json

# Custom headers
arjun -u http://target/endpoint -H "Authorization: Bearer TOKEN"

# Use custom wordlist
arjun -u http://target/endpoint -w /path/to/params_wordlist.txt
```

### ParamSpider
```bash
# Mine parameters from web archives
paramspider -d target.com -o params.txt
# Output: URLs with parameters found in Wayback Machine

# Combine with gau for more coverage
gau target.com | grep '=' | qsreplace 'FUZZ' | sort -u > fuzz_params.txt
```

### Wayback Machine Mining
```bash
# Get all known URLs
waybackurls target.com | sort -u > wayback_urls.txt

# Filter for parameterized URLs
cat wayback_urls.txt | grep '=' | sort -u > parameterized_urls.txt

# Extract unique parameters
cat parameterized_urls.txt | grep -oP '\?[^&]+|&[^&]+' | \
  cut -d= -f1 | tr -d '?&' | sort -u > unique_params.txt

# gau — multi-source URL aggregation
gau target.com --subs --providers wayback,commoncrawl,otx | sort -u > all_urls.txt
gau target.com | grep -E '\.(js|json|xml|config|env|bak)$' | sort -u > interesting_files.txt
```

---

## API Endpoint Enumeration

### Discovery Methods
```bash
# Check common API paths
for path in api v1 v2 v3 graphql swagger.json openapi.json api-docs; do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://target/$path)
  echo "$path → $code"
done

# Fuzz API endpoints
ffuf -u http://target/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403 -o api_enum.json -of json

# Check HTTP methods on discovered endpoints
for endpoint in $(cat api_endpoints.txt); do
  for method in GET POST PUT DELETE PATCH OPTIONS; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X $method http://target$endpoint)
    [ "$code" != "405" ] && echo "$method $endpoint → $code"
  done
done
```

### GraphQL Enumeration
```bash
# Introspection query
curl -s -X POST http://target/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'

# Check common GraphQL paths
# /graphql, /graphiql, /v1/graphql, /api/graphql, /query

# Tools: graphql-voyager, InQL (Burp extension)
```

### Swagger/OpenAPI Discovery
```bash
# Common Swagger paths
curl -s http://target/swagger.json
curl -s http://target/swagger/v1/swagger.json
curl -s http://target/api-docs
curl -s http://target/openapi.json
curl -s http://target/v2/api-docs       # Spring Boot
curl -s http://target/api/swagger.json
```

---

## JavaScript Analysis

### LinkFinder
```bash
# Extract endpoints from JS files
linkfinder -i http://target -o cli
linkfinder -i http://target/static/app.js -o cli

# Output to HTML report
linkfinder -i http://target -o results.html

# Analyze local JS file
linkfinder -i /path/to/downloaded.js -o cli
```

### JS File Collection
```bash
# Find JS files from known URLs
gau target.com | grep '\.js$' | sort -u > jsfiles.txt

# Download and analyze
cat jsfiles.txt | while read url; do
  echo "=== $url ==="
  curl -s "$url" | grep -oE '(https?://[^\s"]+|/api/[^\s"]+|/v[0-9]/[^\s"]+)' | sort -u
done

# Search for secrets in JS
cat jsfiles.txt | while read url; do
  curl -s "$url" | grep -oiE \
    '(api[_-]?key|token|secret|password|auth|credential)["\s]*[:=]["\s]*[^"\s,;]+' 
done
```

### Secret Patterns in JS
```
API keys:     /[a-zA-Z0-9]{32,}/
AWS keys:     /AKIA[0-9A-Z]{16}/
JWT tokens:   /eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/
Internal URLs: /https?:\/\/(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)[^\s"]+/
```

---

## Technology Fingerprinting

### WhatWeb
```bash
# Aggressive scan
whatweb -a 3 -v http://target

# Scan multiple targets
whatweb -a 3 -i urls.txt --log-json whatweb.json

# Key fingerprints: CMS, framework, server, language, JS libraries
```

### httpx Tech Detection
```bash
echo http://target | httpx -tech-detect -status-code -title -content-length -web-server
cat urls.txt | httpx -tech-detect -json -o httpx_results.json
```

### Manual Fingerprinting
```bash
# HTTP headers
curl -sI http://target | grep -iE '(server|x-powered|x-aspnet|x-generator)'

# Cookie names reveal frameworks
# PHPSESSID → PHP,  JSESSIONID → Java,  ASP.NET_SessionId → .NET
# connect.sid → Express,  _rails_session → Rails

# Error pages
curl -s http://target/nonexistent_page_12345 | head -20
# Default error pages reveal server/framework

# robots.txt and sitemap.xml
curl -s http://target/robots.txt
curl -s http://target/sitemap.xml
```
