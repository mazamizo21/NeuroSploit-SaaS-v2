# Safe Scanning Practices

## Rate Limiting by Target Type

| Target Type | Max Rate | Threads | Timeout | Retries |
|-------------|----------|---------|---------|---------|
| **Lab** | Unlimited | 50 | 10s | 3 |
| **External (authorized)** | 50 req/s | 10 | 30s | 2 |
| **External (careful)** | 10 req/s | 5 | 60s | 1 |
| **Production** | 5 req/s | 3 | 60s | 1 |

## Scanner Configuration by Target

### Nuclei
```bash
# Lab target (fast)
nuclei -u http://target -severity critical,high,medium -rate-limit 0 -concurrency 50

# External target (safe)
nuclei -u http://target -severity critical,high -rate-limit 50 -concurrency 10 \
  -timeout 30 -retries 2

# Exclude destructive templates
nuclei -u http://target -exclude-tags dos,fuzz -severity critical,high
```

### Nmap
```bash
# Lab (aggressive)
nmap --script vuln -sV -T4 -p- target

# External (conservative)
nmap --script "safe and vuln" -sV -T3 --max-rate 100 -p <known_ports> target

# Never on external:
# -T5 (insane timing), --script exploit, -sS without permission
```

### SQLMap
```bash
# Safe mode (for initial detection)
sqlmap -u "url" --batch --level 1 --risk 1 --safe-url="http://target/" --safe-freq=3

# Aggressive (lab only)
sqlmap -u "url" --batch --level 5 --risk 3

# Always use --batch to avoid interactive prompts hanging the agent
```

## Scan Order (Minimize Impact)
1. **Passive checks first** — headers, version detection, SSL config
2. **Safe active checks** — nuclei safe templates, nmap default scripts
3. **Targeted vuln checks** — specific CVE scripts based on detected versions
4. **Aggressive checks last** — brute force, fuzzing, exploitation attempts

## Error Handling
| Error | Meaning | Action |
|-------|---------|--------|
| HTTP 429 | Rate limited | Reduce rate by 50%, add delay |
| HTTP 503 | Service overloaded | Stop scan, wait 60s, resume slower |
| Connection refused | Port closed/filtered | Skip this port, move on |
| Timeout | Service slow/down | Increase timeout, reduce concurrency |
| SSL handshake error | TLS mismatch | Try `--ssl` flag or specific TLS version |

## Evidence Preservation
Every scan MUST save:
1. **Command used** — exact command line with all flags
2. **Scan config** — rate, threads, templates, scope
3. **Start/end time** — for audit trail
4. **Output files** — JSON preferred over text
5. **Error log** — any failures or skipped checks

```bash
# Good pattern: save all outputs
nuclei -u http://target -o nuclei_output.json -jsonl 2>nuclei_errors.log
nmap --script vuln -oA scan_results target 2>nmap_errors.log
```
