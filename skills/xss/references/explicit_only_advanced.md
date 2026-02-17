# XSS Explicit-Only Advanced Actions

## Scope Gate
These actions require explicit authorization. Do NOT perform on external targets without written approval.

## Cookie Theft & Session Hijacking
- Extracting document.cookie and sending to external server
- Using stolen session cookies to impersonate users
**Authorization required:** Must specify scope (which users, which cookies)

## Credential Harvesting
- Injecting fake login forms
- Keylogging user input
- Phishing via XSS
**Authorization required:** Must specify acceptable social engineering scope

## Account Takeover Actions
- Changing victim's email or password via CSRF
- Creating admin accounts
- Modifying user roles/permissions
**Authorization required:** Must specify which actions and which users

## Data Exfiltration
- Reading sensitive page content
- Extracting API responses
- Downloading files via victim's session
**Authorization required:** Must specify data types and sensitivity limits

## Browser Exploitation
- BeEF hook injection
- Webcam/microphone access attempts
- Geolocation capture
**Authorization required:** Must specify exploitation depth

## Network Reconnaissance via XSS
- Internal network scanning from victim's browser
- Port scanning internal hosts
- Accessing internal services via victim's network position
**Authorization required:** Must specify internal scope boundaries

## Stored XSS Persistence
- Injecting payloads that persist and affect multiple users
- Self-propagating XSS (worms)
**Authorization required:** EXTREME CAUTION — affects all users who view the page

## Evidence Guidelines
- Capture proof of execution only (alert/console.log)
- Do not collect real user data without authorization
- Clean up stored XSS payloads after testing
- Document the scope of authorization before proceeding
