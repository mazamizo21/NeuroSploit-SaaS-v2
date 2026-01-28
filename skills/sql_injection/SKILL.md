# SQL Injection Skill

## Overview
Exploiting SQL injection vulnerabilities to extract, modify, or delete database contents, and potentially achieve remote code execution.

## Methodology

### 1. SQL Injection Detection
- Identify injection points in GET/POST parameters, cookies, headers
- Test for error-based, union-based, boolean-based, time-based, and stacked queries
- Determine database type (MySQL, PostgreSQL, SQL Server, Oracle, SQLite)

### 2. Exploitation - Error-Based
- Extract database information via error messages
- Database version identification
- Table/column name extraction

### 3. Exploitation - Union-Based
- Determine number of columns with ORDER BY
- Extract data using UNION SELECT
- Extract database structure (tables, columns, data)

### 4. Exploitation - Boolean-Based
- Extract data bit-by-bit based on TRUE/FALSE responses
- Useful for blind SQL injection

### 5. Exploitation - Time-Based
- Extract data using timing delays
- Useful for blind SQL injection when boolean extraction not possible

### 6. Advanced Exploitation
- File read/write operations (MySQL LOAD_FILE, INTO OUTFILE)
- Privilege escalation to DBA
- Stored procedure execution (xp_cmdshell, sys_exec)
- Second-order SQL injection

### 7. Automated Tool Usage
- Use sqlmap for comprehensive exploitation
- Customize sqlmap for specific databases
- Bypass WAF filters with tamper scripts

## MITRE ATT&CK Mappings
- T1190 - Exploit Public-Facing Application
- T1055 - Process Injection
- T1566.001 - Spearphishing Link (SQLi via phishing)

## Tools Available
- sqlmap: Automated SQL injection and database takeover tool
- bbqsql: Blind SQL injection exploitation framework
- sqlninja: SQL injection exploitation tool for SQL Server
- havij: Automated SQL injection tool
- commix: Automated all-in-one OS command injection and exploitation tool

## Evidence Collection
1. Database schema (tables, columns)
2. Extracted data (users, passwords, sensitive information)
3. Database credentials
4. Shell/webshell uploaded to server
5. Privilege escalation results

## Success Criteria
- SQL injection vulnerability confirmed
- Database type and version identified
- At least one table extracted with meaningful data
- Credentials extracted if present
- Remote command execution achieved if possible
- All evidence documented
