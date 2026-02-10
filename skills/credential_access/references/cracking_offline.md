# Offline Cracking Guidance

## Goals
1. Validate password strength offline and safely.
2. Avoid online guessing unless explicitly authorized.
3. Record hash types and authorization scope.

## Safe Checks
1. Use `hashcat --show` or `john --show` on authorized hash sets.
2. Prefer wordlists and rules over brute-force.

## Evidence Checklist
1. Hash type identification.
2. Count of recovered passwords (redacted).
3. Hash source and scope approval reference.
