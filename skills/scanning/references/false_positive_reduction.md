# False Positive Reduction

## The 5-Step Validation Protocol
Every scanner finding MUST pass before becoming a reported vulnerability:

### Step 1: Reproduce
```bash
# Replay the exact request the scanner made
curl -v -s "http://target/path?param=payload"
# Check: does the response actually show the vulnerability?
```

### Step 2: Version Verify
```bash
# Confirm the service version is actually vulnerable
# Scanner may detect "IIS 10" but IIS 10 spans many builds
curl -sI http://target/ | grep -i server
nmap -sV -p <port> <target> --version-intensity 9
```

### Step 3: Cross-Validate
Run a second tool to confirm:
```bash
# Nuclei found XSS? Verify with curl:
curl -s "http://target/search?q=<script>alert(1)</script>" | grep "<script>alert"

# Nmap found MS17-010? Verify with crackmapexec:
crackmapexec smb target

# SQLMap found injection? Verify data extraction:
sqlmap -u "..." --dbs --batch
```

### Step 4: Context Check
- Is this a default page/error page that's harmless?
- Is there a WAF that the scanner didn't detect?
- Is the "vulnerability" actually an intentional feature?
- Is the version string spoofed/modified?

### Step 5: Impact Assessment
- What can an attacker actually DO with this?
- Is it exploitable remotely without authentication?
- What data/access does exploitation provide?

## Scanner-Specific False Positives

### Nuclei
| Template | False Positive Indicator | Verify With |
|----------|------------------------|-------------|
| `git-config` | 404/403 returned but matched heuristic | `curl -s target/.git/HEAD` must return `ref:` |
| `open-redirect` | Parameter reflected but not redirected | Follow redirect manually |
| `tech-detect` | CSS/JS loaded from CDN, not the target | Check response origin |
| `exposed-panels` | Login page exists != vulnerable | Check for default creds |
| `info-disclosure` | Server header != actual version | Cross-reference with behavior |

### Nmap NSE
| Script | False Positive Indicator | Verify With |
|--------|------------------------|-------------|
| `smb-vuln-ms17-010` | "Could not determine if vulnerable" | `crackmapexec smb target` |
| `http-vuln-*` | Script error or timeout | Manual curl request |
| `ssh2-enum-algos` | Weak algo listed but disabled | `ssh -v target` actual negotiation |

### SQLMap
| Indicator | Likely False Positive | Verify |
|-----------|----------------------|--------|
| "Parameter appears injectable" but no data | Heuristic match only | Try `--dbs` extraction |
| Time-based blind detected | Could be server latency | Test with different delay values |
| Boolean-based blind | Custom error handling | Compare true/false responses manually |

### Nikto
| Finding | Often False | Verify |
|---------|------------|--------|
| "Server version disclosed" | Informational, not a vuln | Check if version is actually outdated |
| "X-Frame-Options missing" | Common, low impact | Only high if login/sensitive pages |
| "OSVDB-*" references | Many are ancient and irrelevant | Check CVE mapping |

## Severity Overrides
Downgrade when:
- Finding requires authentication to exploit
- Finding requires specific configuration that isn't present
- Impact is limited to information disclosure only
- Exploitation requires social engineering + technical chain

Upgrade when:
- Finding is pre-authentication
- Finding leads to RCE or data exfiltration
- Multiple low/medium findings chain into high impact
- Finding affects a known-sensitive service (auth, payments, admin)
