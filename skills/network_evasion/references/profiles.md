# Network Profiling and Rate Control (Authorized)

## Baseline Profiles
1. External safe default: `-T2`, `--max-retries 2`, `--max-rate 50`.
2. Internal safe default: `-T3`, `--max-retries 2`, `--max-rate 200`.
3. High-sensitivity: `-T1`, `--max-retries 1`, `--max-rate 10`.
4. Always start low and increase only after confirming stability.

## Safe Adjustments
1. Increase delays before concurrency.
2. Prefer backoff instead of bypass or evasion.
3. Respect `Retry-After` headers and 429 responses.
4. Reduce scan scope before increasing rate.

## Evidence Capture
1. Timing profile and rate settings used.
2. Observed latency, jitter, and packet loss.
3. Throttling signals such as 429/503, TCP RST, or ICMP unreachable.
4. Capture references: pcap filename, tcpdump filters, and timestamps.

## Profile Record Template
Use key: value lines so `summarize_network_profile.py` can parse.
target: example.com
timing_profile: T2
max_rate: 50
max_retries: 2
latency_ms_p50: 42
latency_ms_p95: 120
packet_loss_pct: 0
rate_limit_detected: no
notes: Observed occasional 429s on /api/v1.
