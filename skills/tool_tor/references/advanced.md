# Advanced Techniques

## SocksPort
- `SocksPort` opens a SOCKS listener (default 9050). Set it to 0 to disable.
- Keep SocksPort bound to localhost unless explicitly authorized; SOCKS is unauthenticated.

## Isolation Flags
- Use SocksPort isolation flags to separate streams by client address, SOCKS auth, destination address, and port.
