# Web Defacement Proof Guide

## Overview
Web defacement demonstrates write access to web-served content. In penetration testing,
the goal is to prove the capability exists, capture evidence, and immediately restore
the original content. Minimal changes preferred over dramatic alterations.

## ⚠️ Safety Rules
- **ALWAYS backup before modifying** — hash the original for integrity verification
- **Restore IMMEDIATELY** after capturing evidence — seconds, not minutes
- **Coordinate timing** with client if the site is public-facing
- **Prefer HTML comments** over visible changes when possible

## Minimal Proof (Preferred)
```bash
# Backup and hash original
cp /var/www/html/index.html /var/www/html/index.html.pentest_bak
ORIG_HASH=$(sha256sum /var/www/html/index.html | awk '{print $1}')
echo "Original hash: $ORIG_HASH"

# Insert invisible HTML comment (least disruptive)
sed -i '1i<!-- PENTEST-PROOF: Write access confirmed by [TESTER] at $(date -u +%Y-%m-%dT%H:%M:%SZ) -->' \
    /var/www/html/index.html

# Capture evidence
curl -s http://localhost/ | head -5  # shows the comment
echo "Defacement proof injected (HTML comment only)"

# Restore immediately
cp /var/www/html/index.html.pentest_bak /var/www/html/index.html
RESTORED_HASH=$(sha256sum /var/www/html/index.html | awk '{print $1}')
[ "$ORIG_HASH" = "$RESTORED_HASH" ] && echo "VERIFIED: Original restored" || echo "WARNING: Hash mismatch!"
```

## Visible Proof (When Authorized)
```bash
# Backup original
cp /var/www/html/index.html /var/www/html/.index.html.bak.$(date +%s)

# Create visible but professional proof page
cat > /var/www/html/index.html << 'DEFACED'
<!DOCTYPE html>
<html>
<head><title>Penetration Test - Defacement Proof</title></head>
<body style="background:#1a1a2e;color:#e94560;font-family:monospace;text-align:center;padding:50px">
  <h1>⚠️ PENETRATION TEST ⚠️</h1>
  <h2>Web Defacement Capability Confirmed</h2>
  <div style="background:#16213e;padding:20px;margin:20px auto;max-width:600px;border:2px solid #e94560">
    <p><strong>This is an authorized security assessment.</strong></p>
    <p>Write access to web root has been demonstrated.</p>
    <p>The original page has been backed up and will be restored immediately.</p>
    <hr style="border-color:#e94560">
    <p>Tester: [NAME] | Engagement: [ID]</p>
  </div>
</body>
</html>
DEFACED

# Screenshot evidence (use curl or browser screenshot)
curl -s http://localhost/ > /tmp/defacement_evidence.html

# IMMEDIATELY restore
cp /var/www/html/.index.html.bak.* /var/www/html/index.html
echo "Original page restored"
```

## CMS-Specific Defacement
```bash
# WordPress — modify via database (if DB access achieved)
mysql -h target -u wp_user -p'password' wordpress \
    -e "UPDATE wp_posts SET post_content='PENTEST PROOF' WHERE ID=1;"
# Screenshot, then restore:
mysql -h target -u wp_user -p'password' wordpress \
    -e "UPDATE wp_posts SET post_content='$ORIGINAL_CONTENT' WHERE ID=1;"

# WordPress — modify via wp-cli
wp post update 1 --post_content="PENTEST PROOF" --path=/var/www/html
wp post update 1 --post_content="$ORIGINAL" --path=/var/www/html

# Modify via API (if API write access)
curl -X PUT http://target/wp-json/wp/v2/pages/1 \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"content":"PENTEST PROOF"}'
```

## Evidence Checklist
- [ ] Original page hash recorded
- [ ] Backup created before modification
- [ ] Screenshot/curl of original page saved
- [ ] Modification applied and captured
- [ ] Screenshot/curl of modified page saved
- [ ] Original restored immediately
- [ ] Restored hash matches original hash
- [ ] Backup files cleaned up

## Reporting Template
```
Finding: Web Defacement Capability
Severity: High
MITRE: T1491.002 - External Defacement

Access Method: [how write access was achieved]
Web Root: [path]
Evidence: [screenshots attached]
Duration of Modification: [X seconds]
Restoration: Verified (hash match confirmed)

Recommendation:
- Restrict write access to web root directories
- Implement file integrity monitoring (AIDE, Tripwire, OSSEC)
- Use immutable infrastructure / read-only containers
- Deploy WAF with file modification detection
```
