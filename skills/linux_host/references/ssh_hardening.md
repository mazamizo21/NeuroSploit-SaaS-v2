# SSH Hardening Checklist

## Checks
1. Root login disabled (`PermitRootLogin no`).
2. Password authentication disabled or MFA enforced.
3. Strong ciphers, MACs, and KEX algorithms configured.
4. `MaxAuthTries` and `LoginGraceTime` reduced.
5. `AllowUsers` or `AllowGroups` used for access control.
6. Forwarding disabled if not required (`AllowTcpForwarding`, `X11Forwarding`).
7. Session timeouts configured (`ClientAliveInterval`, `ClientAliveCountMax`).

## Evidence Capture
1. SSH configuration excerpts and effective settings.
2. Evidence of applied access controls or MFA configuration.
