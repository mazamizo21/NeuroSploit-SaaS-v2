# Safe SQLi Payloads

## Goals
- Use low-impact payloads that avoid data modification.
- Reduce risk of service disruption.

## Safe Patterns
- Boolean checks: `1 AND 1=1` / `1 AND 1=2`
- Error-based detection with benign expressions
- Time-based checks with minimal delay (2-3s)

## Avoid
- Stacked queries that modify data
- Large UNION-based extraction on external targets
- File read/write functions unless explicitly authorized

## Evidence Checklist
- Payloads used (redacted)
- Response indicators (status, length, time)

