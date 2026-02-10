# Session Handling Deep Dive

## Checks
1. Validate cookie flags (HttpOnly, Secure, SameSite) and domain/path scope.
2. Confirm session rotation on login and privilege changes.
3. Verify session invalidation on logout and password reset.
4. Check idle timeout and absolute session lifetime enforcement.
5. Validate refresh token usage and rotation if applicable.
6. Confirm CSRF protections on state-changing actions.

## Evidence Capture
1. Cookie attribute evidence and session lifetime behavior.
2. Token rotation evidence before and after privilege changes.
3. Logout and reset invalidation evidence (old token rejection).
