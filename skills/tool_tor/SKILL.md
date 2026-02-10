# Tool: Tor

## Overview
Use Tor only when explicitly authorized for routing through anonymizing networks.

## Scope Rules
1. Operate only on explicitly in-scope targets (or approved scope expansion).
2. External targets require explicit authorization for execution/abuse steps.
3. Prefer read-only validation before any execution.

## Methodology
1. Verify policy allows Tor usage and log the authorization.
2. Run Tor with explicit config paths and minimal services.
3. Route specific tools via SOCKS proxy rather than system-wide changes.

## Deep Dives
Load references as needed:
1. ../toolcards/tor.md
2. references/advanced.md

## Evidence Collection
1. tor log output
1. evidence.json with config and routing usage

## Success Criteria
- Tool used within scope to validate the intended path.
- Evidence captured with minimal impact.
