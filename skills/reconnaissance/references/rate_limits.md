# Rate Limits and Safety

## Goals
1. Minimize impact on target systems.
2. Avoid triggering defensive controls.
3. Record throttling behavior and adjust safely.

## Safe Practices
1. Use conservative scan timing (`-T2` or `-T3`) and low retry counts on external targets.
2. Prefer passive sources before active probing.
3. Reduce scope before increasing rate or concurrency.
4. Respect `Retry-After` and 429/503 responses.

## Evidence Checklist
1. Rate limit settings, timing profile, and retry settings.
2. Any throttling observed (429/503, TCP RST, ICMP unreachable).
3. Backoff actions taken and resulting behavior.
