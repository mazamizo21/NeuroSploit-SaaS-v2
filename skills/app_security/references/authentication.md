# Authentication Deep Dive

## Checks
1. Validate MFA enforcement on privileged roles and sensitive flows.
2. Confirm lockout and rate limiting on login and password reset endpoints.
3. Verify password policy strength, reuse limits, and reset flow protections.
4. Check for user enumeration via error messages or timing differences.
5. Validate session creation only after successful authentication.
6. Confirm SSO/SAML/OIDC configuration consistency with tenant policy.

## Evidence Capture
1. Auth policy summary and observed controls (MFA, lockout, password rules).
2. Login and reset endpoint behavior with rate-limit evidence.
3. Error message or timing evidence for enumeration risks.
