# Web Defacement Proof

## Scenario
Write access to web root, authorized to demonstrate defacement capability.

## Step 1: Backup Original
```bash
root@target:~# cp /var/www/html/index.html /var/www/html/index.html.bak
root@target:~# sha256sum /var/www/html/index.html
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1  /var/www/html/index.html

root@target:~# curl -s http://localhost/ | head -3
<!DOCTYPE html>
<html><head><title>MegaCorp Portal</title></head>
<body><h1>Welcome to MegaCorp</h1>
```

## Step 2: Insert Proof Banner
```bash
root@target:~# sed -i '1i<!-- PENTEST: Web defacement capability demonstrated by TazoSploit on 2025-01-15 -->' /var/www/html/index.html

root@target:~# curl -s http://localhost/ | head -3
<!-- PENTEST: Web defacement capability demonstrated by TazoSploit on 2025-01-15 -->
<!DOCTYPE html>
<html><head><title>MegaCorp Portal</title></head>
```

## Step 3: Screenshot Evidence
```bash
# Page still functional with proof banner in source
root@target:~# curl -s http://localhost/ > /tmp/defaced_page.html
root@target:~# echo "Defacement proof captured at $(date)" >> /tmp/defacement_evidence.txt
```

## Step 4: IMMEDIATELY Restore
```bash
root@target:~# cp /var/www/html/index.html.bak /var/www/html/index.html
root@target:~# sha256sum /var/www/html/index.html
a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1  /var/www/html/index.html
# Hash matches original ✅

root@target:~# curl -s http://localhost/ | head -3
<!DOCTYPE html>
<html><head><title>MegaCorp Portal</title></head>
<body><h1>Welcome to MegaCorp</h1>
# Original content restored ✅
```

## Step 5: Cleanup
```bash
root@target:~# rm /var/www/html/index.html.bak
```

## Evidence
- Original page hash: a1b2c3d4...
- Proof inserted: HTML comment in page source
- Restored hash matches original: a1b2c3d4... ✅
- Total modification time: ~10 seconds
- Demonstrates: write access to web root = ability to deface any page
- Remediation: file integrity monitoring (AIDE/Tripwire), read-only web root, WAF
