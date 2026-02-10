# SQL Injection Detection and Validation

## Goals
- Confirm injection points with low-impact tests.
- Identify injection type and DBMS safely.

## Safe Checks
- Use boolean or error-based tests with minimal changes.
- Use small delays for time-based checks (2-3 seconds).
- Prefer read-only queries and parameterized probes.

## Indicators to Record
- Parameter and HTTP method
- Injection type (boolean, error, union, time)
- DBMS fingerprint hints

## Evidence Checklist
- Request/response pairs
- Injection confirmation note

