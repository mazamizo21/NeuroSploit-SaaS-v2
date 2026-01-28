# Cross-Site Scripting (XSS) Skill

## Overview
Exploiting cross-site scripting vulnerabilities to execute arbitrary JavaScript in victim browsers, leading to session hijacking, credential theft, and malicious actions.

## Methodology

### 1. XSS Detection
- Identify injection points in reflected, stored, and DOM-based XSS
- Test all input vectors: GET/POST parameters, cookies, headers, URL fragments
- Determine XSS type: Reflected, Stored, or DOM-based

### 2. Reflected XSS Exploitation
- Craft payloads to execute JavaScript in context
- Bypass basic filters: encoding, alternative methods
- Test for payload length limitations

### 3. Stored XSS Exploitation
- Identify persistent injection points
- Test payload persistence
- Exploit to affect multiple users

### 4. DOM-Based XSS Exploitation
- Identify vulnerable JavaScript sinks
- Exploit client-side vulnerabilities
- Test in various browsers

### 5. XSS Payload Development
- Cookie/session theft: `document.cookie`
- Credential capture: Fake login forms
- Keylogging: JavaScript keylogger
- Screenshot capture: html2canvas
- Browser history: `window.history`

### 6. Advanced Techniques
- BeEF (Browser Exploitation Framework) integration
- XSS phishing and social engineering
- XSS worms (self-propagating XSS)
- Bypass WAF with obfuscation techniques

### 7. Automated Scanning
- Use XSStrike for advanced XSS detection
- Use Xsser for automated exploitation
- Use Burp Suite's Scanner

## MITRE ATT&CK Mappings
- T1190 - Exploit Public-Facing Application
- T1189 - Drive-by Compromise
- T1203 - Exploitation for Client Execution
- T1059.007 - JavaScript (XSS payload execution)

## Tools Available
- XSStrike: Advanced XSS detection and exploitation tool
- Xsser: Cross-site scripting framework
- dalfox: Fast XSS parameter scanner and analysis tool
- BeEF: Browser Exploitation Framework
- burpsuite: Web application security testing platform

## Evidence Collection
1. Proof-of-concept XSS payloads
2. Screenshots of successful XSS execution
3. Captured cookies/sessions
4. Browser console output
5. BeEF hook browser screenshots
6. WAF bypass payloads

## Success Criteria
- XSS vulnerability confirmed (at least one type)
- Proof-of-concept payload demonstrated
- At least one session/credential captured if possible
- BeEF hook deployed successfully if applicable
- All XSS vectors documented
