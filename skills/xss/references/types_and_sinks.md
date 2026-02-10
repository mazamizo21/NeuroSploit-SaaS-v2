# XSS Types and Sinks

## Goals
1. Identify reflected, stored, and DOM-based XSS.
2. Map sinks and input sources.
3. Record context and encoding requirements.

## Safe Checks
1. Use non-destructive payloads.
2. Validate sink context (HTML, attribute, JS, URL).
3. Record parameter source (query, body, header, fragment).

## Evidence Checklist
1. Injection point and type.
2. Sink and context details.
3. Payload and response evidence (redacted if needed).
