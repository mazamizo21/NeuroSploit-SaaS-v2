# Artifact Cleanup Reference

Post-engagement cleanup checklist. Remove all traces of testing activity.
Cross-reference: persistence skill cleanup steps, log_clearing references.

> **MITRE:** T1070.004 (File Deletion), T1070.003 (Clear Command History), T1070.009 (Clear Persistence)
> **Warning:** Log gaps and missing artifacts are themselves IoCs. Clean surgically, not broadly.

---

## 1. Shell History — T1070.003

**Linux:**
```bash
# Prevent history in current session
unset HISTFILE; export HISTSIZE=0; set +o history

# Clean history files
for f in ~/.bash_history ~/.zsh_history ~/.python_history ~/.node_repl_history \
  ~/.mysql_history ~/.psql_history ~/.lesshst ~/.viminfo; do > "$f" 2>/dev/null; done
rm -f ~/.vim/undo/*

# Surgical: remove only specific lines instead of blanking
# sed -i '/specific_command/d' ~/.bash_history
```

**Windows:**
```powershell
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force
doskey /reinstall
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\*" -Force
Remove-Item "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force
```

## 2. Temp Files & Dropped Tools — T1070.004

**Linux:**
```bash
rm -rf /tmp/.hidden/ /tmp/payload* /tmp/linpeas* /tmp/pspy*
rm -rf /var/tmp/exploit* /dev/shm/.* /dev/shm/payload*
find /tmp /var/tmp /dev/shm -mmin -60 -type f 2>/dev/null  # audit recent files
```

**Windows:**
```cmd
del /f /q %TEMP%\payload* %TEMP%\*.exe %TEMP%\*.ps1
del /f /q C:\ProgramData\update\*
rd /s /q %TEMP%\exploit_output
```

## 3. Network Artifacts

**Linux:**
```bash
ip neigh flush all                              # ARP cache
systemd-resolve --flush-caches 2>/dev/null      # DNS cache
ip route del 10.0.0.0/8 via 192.168.1.1 2>/dev/null  # routing entries added
iptables -D INPUT -p tcp --dport 4444 -j ACCEPT 2>/dev/null  # firewall rules
ss -tlnp | grep -E '4444|8080|9001'             # verify no lingering listeners
```

**Windows:**
```cmd
arp -d *
ipconfig /flushdns
netsh advfirewall firewall delete rule name="UpdateHelper"
netstat -ano | findstr "4444 8080 9001"
```

## 4. Process Artifacts

**Linux:**
```bash
pkill -f beacon.sh; pkill -f '/usr/lib/update-helper'
kill -9 $(cat /tmp/.pid 2>/dev/null) 2>/dev/null
rm -f /tmp/.pid /var/run/update-helper.pid
ps aux | grep -E 'beacon|payload|update-helper|nc -l'  # verify
```

**Windows:**
```powershell
Stop-Process -Name "svc" -Force
taskkill /F /IM svc.exe
wmic startup where "name='UpdateHelper'" delete
```

## 5. File System — T1070.004

**Linux:**
```bash
rm -f /usr/lib/update-helper/svc /opt/.svc/callback.sh
rm -rf /usr/lib/update-helper/
rm -f /var/www/html/wp-content/plugins/update-helper/*  # webshells
rm -f /tmp/*.elf /tmp/*.o /tmp/exploit
shred -vfzu /tmp/sensitive_output.txt  # secure delete
```

**Windows:**
```powershell
Remove-Item "C:\ProgramData\update\*" -Force -Recurse
# Overwrite-then-delete:
$f="C:\Temp\sensitive.txt"; [IO.File]::WriteAllBytes($f,(New-Object byte[] (Get-Item $f).Length)); Remove-Item $f -Force
```

## 6. Credential Artifacts

```bash
# Linux
rm -f /tmp/hashes.txt /tmp/shadow_copy /tmp/creds*
shred -vfzu /tmp/ntds.dit 2>/dev/null
xclip -selection clipboard < /dev/null 2>/dev/null  # clear clipboard
```
```powershell
# Windows
echo off | clip
cmdkey /list   # review cached creds
cmdkey /delete:targetname
Remove-Item C:\Temp\keylog* -Force
```

## 7. Registry Cleanup (Windows) — T1112

```cmd
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateHelper /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v UpdateHelper /f
:: CRITICAL: restore Winlogon if modified
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit /t REG_SZ /d "C:\Windows\system32\userinit.exe," /f
:: COM hijack keys
reg delete "HKCU\Software\Classes\CLSID\{TARGET-CLSID}" /f
```

## 8. Service & Task Cleanup — T1070.009

**Linux:**
```bash
systemctl stop update-helper.service && systemctl disable update-helper.service
rm /etc/systemd/system/update-helper.service /etc/systemd/system/update-helper.timer
systemctl daemon-reload
crontab -l | grep -v "beacon.sh" | crontab -
rm -f /etc/cron.d/update-check
atrm $(atq | awk '{print $1}')  # remove at jobs
rm /etc/init.d/update-helper && update-rc.d update-helper remove
sed -i '/update-helper/d' /etc/rc.local
```

**Windows:**
```cmd
schtasks /delete /tn "Microsoft\Windows\UpdateOrchestrator\UpdateCheck" /f
sc stop UpdateSvc && sc delete UpdateSvc
```
```powershell
# WMI cleanup
Get-WMIObject -Namespace root\Subscription -Class __EventFilter | Where {$_.Name -eq "CoreFilter"} | Remove-WMIObject
Get-WMIObject -Namespace root\Subscription -Class CommandLineEventConsumer | Where {$_.Name -eq "CoreConsumer"} | Remove-WMIObject
Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding | Remove-WMIObject
```

## 9. SSH Cleanup

```bash
# Remove added authorized_keys entries (edit file, remove attacker key line)
ssh-keygen -R target_ip  # clean known_hosts on attacker machine
shred -vfzu ~/.ssh/pentest_key 2>/dev/null  # remove generated keys
```

## 10. User Account Cleanup

```bash
userdel -r backdoor_user 2>/dev/null && groupdel backdoor_group 2>/dev/null
rm /etc/sudoers.d/backdoor
```
```cmd
net user backdoor_user /delete
net localgroup Administrators backdoor_user /delete
```

## 11. Log Entry Cleanup

> Surgical cleaning only — blanking logs is an obvious IoC. Cross-reference log_clearing references.

```bash
sed -i '/attacker_ip/d' /var/log/auth.log
sed -i '/update-helper/d' /var/log/syslog
# Binary logs (wtmp):
utmpdump /var/log/wtmp | grep -v "attacker_user" | utmpdump -r > /tmp/wtmp_clean && mv /tmp/wtmp_clean /var/log/wtmp
```
```cmd
:: Windows — surgical removal preferred, full clear is last resort
wevtutil cl Security
```

## 12. Firewall Rule Cleanup

```bash
iptables -D INPUT -p tcp --dport 4444 -j ACCEPT
iptables -D INPUT -p tcp --dport 8080 -j ACCEPT
iptables-save > /etc/iptables/rules.v4
```
```cmd
netsh advfirewall firewall delete rule name="AllowUpdate"
```

## 13. Verification Checklist

```bash
# Linux — run after cleanup
crontab -l                                       # no rogue entries
systemctl list-unit-files | grep update          # no rogue services
ps aux | grep -E 'beacon|payload|update-helper'  # no rogue processes
find /tmp /var/tmp /dev/shm -mmin -120 -type f   # no recent temp files
cat ~/.bash_history | tail -20                    # history cleaned
ss -tlnp                                          # no rogue listeners
ls -la ~/.ssh/authorized_keys                     # no added keys
```
```cmd
:: Windows — run after cleanup
schtasks /query | findstr /i "update"
sc query state= all | findstr "UpdateSvc"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
netstat -ano | findstr "LISTENING"
```

**Key principle:** Evidence of cleanup is itself an IoC. Clean surgically, not broadly. Document your cleanup steps for the engagement report.
