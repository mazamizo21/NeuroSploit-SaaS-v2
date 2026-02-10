# Advanced Techniques

## TCP-LISTEN & Forking
- `TCP-LISTEN:<port>` listens and accepts a TCP connection; it blocks until a client connects.
- Use `fork` to handle multiple connections, and keep `backlog`/`max-children` conservative.

## Diagnostics
- Use debug flags when troubleshooting relay behavior, and capture logs for evidence.
