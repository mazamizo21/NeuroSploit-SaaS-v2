# Subdomain Enumeration Example

## Step 1: Passive Discovery
```bash
$ subfinder -d megacorp.com -all -o subs_passive.txt
               __    _____           __
   _______  __/ /_  / __(_)___  ____/ /__  _____
  / ___/ / / / __ \/ /_/ / __ \/ __  / _ \/ ___/
 (__  ) /_/ / /_/ / __/ / / / / /_/ /  __/ /
/____/\__,_/_.___/_/ /_/_/ /_/\__,_/\___/_/  v2.6.4

[INF] Loading provider config from /root/.config/subfinder/provider-config.yaml
[INF] Enumerating subdomains for megacorp.com
www.megacorp.com
mail.megacorp.com
vpn.megacorp.com
dev.megacorp.com
staging.megacorp.com
api.megacorp.com
portal.megacorp.com
owa.megacorp.com
autodiscover.megacorp.com
ftp.megacorp.com
git.megacorp.com
jenkins.megacorp.com
[INF] Found 12 subdomains for megacorp.com in 8 seconds
```

## Step 2: Certificate Transparency
```bash
$ curl -s 'https://crt.sh/?q=%.megacorp.com&output=json' | jq -r '.[].name_value' | sort -u
*.megacorp.com
api.megacorp.com
dev.megacorp.com
internal.megacorp.com
mail.megacorp.com
staging.megacorp.com
test.megacorp.com
vpn.megacorp.com
www.megacorp.com
```

## Step 3: Verify Live Hosts
```bash
$ cat subs_passive.txt | httpx -silent -status-code -title -o live_subs.txt
https://www.megacorp.com [200] [MegaCorp - Enterprise Solutions]
https://mail.megacorp.com [302] [Outlook Web App]
https://vpn.megacorp.com [200] [GlobalProtect Portal]
https://dev.megacorp.com [403] [403 Forbidden]
https://api.megacorp.com [200] [API Documentation]
https://portal.megacorp.com [200] [MegaCorp Portal Login]
https://jenkins.megacorp.com [200] [Dashboard [Jenkins]]
http://staging.megacorp.com [200] [MegaCorp Staging]
```

## Key Findings
- **jenkins.megacorp.com** — Jenkins dashboard exposed, potential RCE via Script Console
- **staging.megacorp.com** — HTTP only (no TLS), likely less hardened
- **dev.megacorp.com** — 403 but exists, may have accessible paths
- **api.megacorp.com** — API docs exposed, enumerate endpoints

## Next Steps
→ **scanning skill**: nuclei on all live hosts
→ **exploitation skill**: Check Jenkins for unauthenticated Script Console
→ **reconnaissance**: gobuster/ffuf on dev.megacorp.com for accessible paths
