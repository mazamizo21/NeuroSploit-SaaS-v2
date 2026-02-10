# Protocol and Cipher Support

## Goals
1. Enumerate supported TLS protocol versions.
2. Identify weak or deprecated cipher suites.
3. Record preferred cipher ordering.

## Safe Checks
1. `sslscan --no-colour host:443`
2. `nmap --script ssl-enum-ciphers`

## Indicators to Record
1. TLS 1.0 or 1.1 enabled.
2. Weak ciphers (3DES, RC4, NULL).
3. Insecure renegotiation support.
4. Preference for weak ciphers over strong ones.

## Evidence Checklist
1. Protocol list and cipher samples.
2. Notes on weak cipher presence.
3. Preferred cipher ordering evidence.
