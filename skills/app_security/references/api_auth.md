# API Authentication and Authorization

## Checks
1. Validate JWT signature verification, algorithm enforcement, and expiration handling.
2. Confirm OAuth scope enforcement and token audience checks.
3. Verify API key permissions are least-privilege.
4. Confirm token revocation or rotation behavior for compromised credentials.
5. Validate mTLS or HMAC signatures where applicable.
6. Ensure error handling does not leak token validation details.

## Evidence Capture
1. Auth scheme summaries and validation outcomes.
2. Token scope and audience validation evidence.
3. API key permission evidence and denied access examples.
