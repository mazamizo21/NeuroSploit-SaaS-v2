# DBMS Fingerprinting — Complete Guide

## Goals
- Identify the backend DBMS type and version
- Use multiple fingerprinting methods for confidence
- Non-destructive identification only

## Method 1: Error Message Analysis

### MySQL / MariaDB
```
You have an error in your SQL syntax; check the manual...
Unknown column 'X' in 'where clause'
Duplicate entry 'X' for key 'PRIMARY'
```

### PostgreSQL
```
ERROR:  syntax error at or near "X"
ERROR:  invalid input syntax for type integer: "X"
ERROR:  column "X" does not exist
```

### Microsoft SQL Server
```
Unclosed quotation mark after the character string 'X'
Conversion failed when converting the nvarchar value 'X' to data type int
Invalid column name 'X'
Incorrect syntax near 'X'
```

### Oracle
```
ORA-01756: quoted string not properly terminated
ORA-00933: SQL command not properly ended
ORA-01789: query block has incorrect number of result columns
```

### SQLite
```
near "X": syntax error
unrecognized token: "X"
SELECTs to the left and right of UNION do not have the same number of result columns
```

## Method 2: Version Functions

| DBMS | Version Query | Example Output |
|------|------|------|
| MySQL | `SELECT @@version` | `8.0.32` |
| MariaDB | `SELECT @@version` | `10.11.2-MariaDB` |
| PostgreSQL | `SELECT version()` | `PostgreSQL 15.3 on x86_64-pc-linux...` |
| MSSQL | `SELECT @@version` | `Microsoft SQL Server 2019 (RTM)...` |
| Oracle | `SELECT banner FROM v$version` | `Oracle Database 19c Enterprise...` |
| SQLite | `SELECT sqlite_version()` | `3.40.1` |

## Method 3: Behavioral Tests

### String Concatenation
| Test | MySQL | PG | MSSQL | Oracle | SQLite |
|------|-------|-----|-------|--------|--------|
| `'a'\|\|'b'` | `0` (numeric) | `ab` | error | `ab` | `ab` |
| `CONCAT('a','b')` | `ab` | `ab` | error | `ab` | error |
| `'a'+'b'` | `0` | error | `ab` | error | error |

### Math Operations
```sql
-- MySQL-specific: @@version works
SELECT @@version;         -- Returns version string

-- PostgreSQL: current_database() exists
SELECT current_database();  -- Returns db name

-- MSSQL: DB_NAME() exists
SELECT DB_NAME();          -- Returns db name

-- Oracle: requires FROM dual
SELECT 1;                  -- Error in Oracle (needs FROM dual)
SELECT 1 FROM dual;        -- Works in Oracle (and MySQL)
```

### Limiting Results
| DBMS | Limit Syntax |
|------|------|
| MySQL, PostgreSQL, SQLite | `LIMIT 1` or `LIMIT 1 OFFSET 0` |
| MSSQL | `TOP 1` |
| Oracle | `WHERE ROWNUM <= 1` or `FETCH FIRST 1 ROWS ONLY` (12c+) |

### Comment Styles
| DBMS | Single Line | Multi Line | Conditional |
|------|------|------|------|
| MySQL | `-- ` or `#` | `/* */` | `/*! ... */` |
| PostgreSQL | `-- ` | `/* */` | N/A |
| MSSQL | `-- ` | `/* */` | N/A |
| Oracle | `-- ` | `/* */` | N/A |
| SQLite | `-- ` | `/* */` | N/A |

## Method 4: Technology Stack Inference
| Stack | Likely DBMS |
|------|------|
| PHP + Apache | MySQL / MariaDB |
| PHP + WordPress | MySQL |
| Python + Django | PostgreSQL (default) |
| Python + Flask | SQLite (dev), PostgreSQL (prod) |
| ASP.NET + IIS | Microsoft SQL Server |
| Java + Tomcat | MySQL, PostgreSQL, or Oracle |
| Ruby on Rails | PostgreSQL (default) |
| Node.js + Express | MongoDB (check NoSQL), PostgreSQL, MySQL |

## Evidence Checklist
- [ ] DBMS type identified (high/medium/low confidence)
- [ ] Version string (if obtained)
- [ ] Source of identification (error message, version query, behavioral test)
- [ ] Technology stack observations that support identification
