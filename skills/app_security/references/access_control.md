# Access Control Deep Dive

## Checks
1. Validate role-based access control enforcement across endpoints and roles.
2. Check for IDOR patterns with read-only requests and safe object IDs.
3. Confirm least-privilege authorization for sensitive actions (admin, billing, data export).
4. Validate function-level authorization on non-UI endpoints and hidden routes.
5. Confirm tenant boundary enforcement for multi-tenant data access.
6. Verify error handling does not leak authorization logic.

## Evidence Capture
1. Endpoint access results by role with request/response pairs.
2. Object ID comparisons showing allowed vs denied access.
3. Authorization decision evidence (status codes, error messages, audit logs if available).
