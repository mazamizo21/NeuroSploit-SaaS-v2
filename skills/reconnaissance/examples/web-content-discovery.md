# Web Content Discovery Example

## Command
```bash
$ gobuster dir -u http://10.10.10.75 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -x php,html,txt -o dirs.txt
```

## Output
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
[+] Status codes:            200,204,301,302,307,401,403
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster
===============================================================
/index.php            (Status: 200) [Size: 11321]
/admin                (Status: 301) [Size: 311] [--> http://10.10.10.75/admin/]
/uploads              (Status: 301) [Size: 313] [--> http://10.10.10.75/uploads/]
/login.php            (Status: 200) [Size: 2847]
/config.php           (Status: 200) [Size: 0]
/register.php         (Status: 200) [Size: 3102]
/api                  (Status: 301) [Size: 309] [--> http://10.10.10.75/api/]
/robots.txt           (Status: 200) [Size: 47]
/backup               (Status: 301) [Size: 312] [--> http://10.10.10.75/backup/]
/.htaccess            (Status: 403) [Size: 277]
/server-status        (Status: 403) [Size: 277]
/phpmyadmin           (Status: 301) [Size: 316] [--> http://10.10.10.75/phpmyadmin/]
/cron.php             (Status: 200) [Size: 0]
Progress: 120000 / 120004 (100.00%)
===============================================================
Finished
===============================================================
```

## Analysis
```bash
# Check robots.txt
$ curl -s http://10.10.10.75/robots.txt
User-agent: *
Disallow: /admin/
Disallow: /backup/

# Check backup directory
$ curl -s http://10.10.10.75/backup/
<title>Index of /backup</title>
<a href="db_backup.sql">db_backup.sql</a>    2024-12-01 03:00  1.2M
<a href="site.tar.gz">site.tar.gz</a>        2024-12-01 03:00  4.5M

# Check for parameters on login
$ curl -s http://10.10.10.75/login.php | grep -oP 'name="[^"]*"'
name="username"
name="password"
name="csrf_token"
```

## Key Findings
- **/backup/** — Database backup and site archive exposed! (CRITICAL)
- **/phpmyadmin/** — Database management interface accessible
- **/admin/** — Admin panel, test for auth bypass
- **/uploads/** — File upload directory, check write access
- **/api/** — API endpoint, enumerate and test
- **login.php** — Has username/password params → SQLi testing target

## Next Steps
→ **collection skill**: Download db_backup.sql for credential extraction
→ **exploitation skill**: Test login.php for SQLi
→ **scanning skill**: nuclei on discovered endpoints
→ **exploitation skill**: Test /uploads for file upload bypass
