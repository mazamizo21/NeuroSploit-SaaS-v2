# SSH Host Keys and Fingerprints

## Goals
1. Capture host key fingerprints and key types.
2. Track key changes across scans.
3. Record host key length and algorithm.

## Safe Checks
1. Use `ssh-keyscan` to collect host keys.
2. Avoid repeated connection attempts.

## Evidence Checklist
1. Host key fingerprints by type.
2. Timestamp and target identity.
3. Key lengths and algorithms.
