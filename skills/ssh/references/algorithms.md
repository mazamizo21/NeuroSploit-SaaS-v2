# SSH Algorithms Review

## Goals
1. Identify key exchange, cipher, and MAC algorithms.
2. Flag weak or deprecated algorithms.
3. Record preferred algorithms and ordering.

## Safe Checks
1. Use `nmap --script ssh2-enum-algos`.
2. Record supported algorithms without attempting authentication.

## Indicators to Record
1. Deprecated ciphers (e.g., `3des`, `arcfour`).
2. Weak MACs or SHA1-only options.
3. Legacy KEX algorithms.
4. Absence of modern algorithms (chacha20, curve25519).

## Evidence Checklist
1. Script output captured.
2. Summary of supported algorithms.
3. Notes on weak or missing modern algorithms.
