# Input Validation Deep Dive

## Checks
1. Identify reflected inputs and missing validation on parameters.
2. Use safe, non-destructive payloads for validation.
3. Verify server-side validation for client-controlled fields.
4. Check file upload restrictions (type, size, extension) without uploading active content.
5. Validate content-type handling and JSON schema enforcement.
6. Confirm canonicalization and encoding normalization before validation.

## Evidence Capture
1. Input vectors and validation outcomes.
2. Request/response evidence for server-side validation errors.
3. File upload policy evidence (allowed types, size limits).
