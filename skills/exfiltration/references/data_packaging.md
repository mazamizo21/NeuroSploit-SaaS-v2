# Data Packaging for Exfiltration

## Overview
Before exfiltration, data must be compressed, encrypted, and encoded appropriately
for the chosen transfer channel. Proper packaging reduces transfer size, protects
data confidentiality, and enables compatibility with text-based channels.

## Packaging Pipeline
```
Raw Data → Compress → Encrypt → Encode (optional) → Split (optional) → Exfiltrate
```

## Step 1: Compression
```bash
# tar + gzip (most common)
tar -czf data.tar.gz /path/to/loot/

# tar + bzip2 (better compression, slower)
tar -cjf data.tar.bz2 /path/to/loot/

# tar + xz (best compression, slowest)
tar -cJf data.tar.xz /path/to/loot/

# zip (cross-platform, built-in encryption)
zip -r -9 data.zip /path/to/loot/

# zip with password (weak encryption but convenient)
zip -r -e -P "$PASSWORD" data.zip /path/to/loot/

# 7zip (best compression + strong AES-256)
7z a -p"$PASSWORD" -mhe=on data.7z /path/to/loot/

# Compress single file
gzip -9 data.txt        # → data.txt.gz
xz -9 data.txt          # → data.txt.xz
```

## Step 2: Encryption
```bash
# AES-256-CBC with OpenSSL (recommended)
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in data.tar.gz -out data.enc -k "$PASSPHRASE"

# Decrypt
openssl enc -aes-256-cbc -d -pbkdf2 -iter 100000 \
    -in data.enc -out data.tar.gz -k "$PASSPHRASE"

# AES-256-GCM (authenticated encryption)
openssl enc -aes-256-gcm -salt -pbkdf2 \
    -in data.tar.gz -out data.enc -k "$PASSPHRASE"

# GPG symmetric encryption
gpg --symmetric --cipher-algo AES256 --batch --passphrase "$PASSPHRASE" data.tar.gz
# → data.tar.gz.gpg

# GPG asymmetric (requires attacker's public key)
gpg --encrypt --recipient attacker@pgp.key data.tar.gz

# Generate random passphrase
PASSPHRASE=$(openssl rand -hex 32)
echo "$PASSPHRASE" > /tmp/.key  # secure this!
```

## Step 3: Encoding
```bash
# Base64 (for text-based channels: HTTP, email, DNS TXT)
base64 data.enc > data.b64
base64 -d data.b64 > data.enc

# Base64 single line (no wrapping)
base64 -w 0 data.enc > data.b64

# Hex encoding (for DNS subdomain exfil)
xxd -p data.enc > data.hex
xxd -p -r data.hex > data.enc

# URL-safe Base64 (for URL parameters)
base64 -w 0 data.enc | tr '+/' '-_' > data.urlb64

# Uuencode (legacy but sometimes useful)
uuencode data.enc data.enc > data.uu
uudecode data.uu
```

## Step 4: Splitting / Chunking (T1030)
```bash
# Split by size (for chunked transfer)
split -b 512k data.enc chunk_       # 512KB chunks
split -b 1m data.enc chunk_         # 1MB chunks
split -b 60 data.hex dns_chunk_     # 60-byte chunks for DNS labels

# Split by line count
split -l 1000 data.b64 b64_chunk_

# Split with numeric suffixes
split -b 512k -d -a 4 data.enc chunk_  # chunk_0000, chunk_0001, ...

# Count chunks
ls chunk_* | wc -l

# Reassemble on attacker side
cat chunk_* > reassembled.enc

# Verify integrity
md5sum data.enc
md5sum reassembled.enc
# SHA-256 for stronger verification
sha256sum data.enc
```

## Integrity Verification
```bash
# Generate checksums before exfil
sha256sum data.enc > checksums.txt
md5sum data.enc >> checksums.txt

# Generate per-chunk checksums
for chunk in chunk_*; do
    sha256sum "$chunk" >> chunk_checksums.txt
done

# Exfil the checksum file separately
# Verify on attacker side after reassembly
sha256sum -c checksums.txt
```

## Size Estimation
```bash
# Check sizes at each stage
du -sh /path/to/loot/          # raw data
ls -lh data.tar.gz             # compressed
ls -lh data.enc                # encrypted (similar to compressed)
ls -lh data.b64                # base64 (~33% larger than binary)
ls -lh data.hex                # hex (~100% larger than binary)
echo "Chunks: $(ls chunk_* | wc -l)"
```

## Quick One-Liner Packaging
```bash
# Compress + encrypt + base64 in one pipeline
tar -czf - /path/to/loot/ | \
    openssl enc -aes-256-cbc -salt -pbkdf2 -k "$KEY" | \
    base64 -w 0 > exfil_ready.b64

# Reverse on attacker side
base64 -d exfil_ready.b64 | \
    openssl enc -aes-256-cbc -d -pbkdf2 -k "$KEY" | \
    tar -xzf -
```

## Packaging for Specific Channels
| Channel  | Recommended Format     | Notes                          |
|----------|------------------------|--------------------------------|
| HTTPS    | Binary (.enc)          | No encoding needed, POST body  |
| DNS      | Hex (.hex), chunked    | 60 chars per label max         |
| ICMP     | Binary (.enc), chunked | 1400 bytes per packet          |
| Email    | Base64, attached       | Attachment or inline base64    |
| Cloud    | Binary (.enc)          | Direct upload, no encoding     |
| Stego    | Binary, size-limited   | Must fit in carrier file       |
| HTTP hdr | Base64, small chunks   | ~500 bytes per header value    |
