# Testing Guide - Docker Environment

## Important: All Tests Run Inside Docker

TazoSploit is a ** application** that runs entirely in Docker containers. All testing must be performed inside the Docker environment, not on the host machine.

---

## Prerequisites

1. **Docker containers must be running:**
```bash
docker-compose up -d
```

2. **Verify containers are running:**
```bash
docker ps | grep tazosploit
```

You should see:
- `tazosploit-kali` - Main Kali Linux executor container
- Other containers as needed

---

## Running Tests

### Option 1: Use the Test Script (Recommended)

```bash
./scripts/test_in_docker.sh
```

This script:
1. Checks if Docker container is running
2. Copies test files to container
3. Runs tests inside container
4. Reports results

### Option 2: Manual Docker Exec

```bash
# Copy test file to container
docker cp tests/test_new_features.py tazosploit-kali:/pentest/

# Run tests inside container
docker exec tazosploit-kali python3 /pentest/test_new_features.py
```

### Option 3: Interactive Shell

```bash
# Enter container
docker exec -it tazosploit-kali bash

# Inside container, run tests
cd /pentest
python3 test_new_features.py
```

---

## Test Suite: test_new_features.py

### Tests Included:

1. **Authorization Framework** - Verifies LLM bypass techniques
2. **Prohibited Behaviors** - Checks explicit prohibitions
3. **Failure Recovery** - Validates tool alternatives
4. **CVE Lookup** - Tests CVE database integration
5. **Session Persistence** - Verifies save/resume functionality
6. **Multi-Model Support** - Tests LLM provider abstraction
7. **Integration** - End-to-end feature integration

### Expected Results:

```
============================================================
RESULTS: 6/7 tests passed (85.7%)
============================================================

✅ PASS: Authorization Framework
✅ PASS: Prohibited Behaviors
✅ PASS: Failure Recovery
⚠️  PARTIAL: CVE Lookup (API works, format issue)
✅ PASS: Session Persistence
✅ PASS: Multi-Model Support
✅ PASS: Integration
```

---

## Testing New Features

### 1. Test Authorization Framework

```bash
docker exec tazosploit-kali python3 -c "
from dynamic_agent import DynamicAgent
agent = DynamicAgent()
prompt = agent.conversation[0]['content']
assert 'AUTHORIZED penetration testing' in prompt
print('✅ Authorization framework present')
"
```

### 2. Test CVE Lookup

```bash
docker exec tazosploit-kali python3 /opt/open-interpreter/cve_lookup.py CVE-2021-44228
```

Expected output:
- CVE information
- Severity and CVSS score
- Available exploits from searchsploit

### 3. Test Session Persistence

```bash
# Start a test session
docker exec tazosploit-kali python3 /opt/open-interpreter/dynamic_agent.py \
  --target http://test.local \
  --objective "Test session" \
  --max-iterations 2

# Check session files
docker exec tazosploit-kali ls -la /pentest/logs/session_*.json
```

### 4. Test Multi-Model Support

```bash
docker exec tazosploit-kali python3 -c "
from llm_providers import auto_detect_provider
provider = auto_detect_provider()
print(f'Detected: {provider.get_provider_name()}')
"
```

---

## Integration Testing

### Full E2E Test with Vulnerable App

```bash
# 1. Start vulnerable app (DVNA)
docker-compose up -d dvna

# 2. Run integration test
docker exec -e TEST_TARGET=http://dvna:9090 \
  tazosploit-kali python3 /opt/open-interpreter/test_full_integration.py

# 3. View results
docker exec tazosploit-kali cat /pentest/logs/agent_report_*.json | jq '.'
```

---

## Viewing Logs

### LLM Interactions
```bash
docker exec tazosploit-kali cat /pentest/logs/llm_interactions.jsonl
```

### Command Executions
```bash
docker exec tazosploit-kali cat /pentest/logs/agent_executions.jsonl
```

### Agent Logs
```bash
docker exec tazosploit-kali cat /pentest/logs/dynamic_agent.log
```

### Session Files
```bash
docker exec tazosploit-kali ls -la /pentest/logs/session_*.json
```

---

## Troubleshooting

### Container Not Running
```bash
# Check container status
docker ps -a | grep tazosploit

# Start containers
docker-compose up -d

# View logs
docker-compose logs tazosploit-kali
```

### Permission Issues
```bash
# Fix permissions inside container
docker exec tazosploit-kali chmod -R 777 /pentest/logs
```

### Missing Dependencies
```bash
# Install dependencies inside container
docker exec tazosploit-kali pip3 install httpx requests
```

### Test File Not Found
```bash
# Copy test file to container
docker cp tests/test_new_features.py tazosploit-kali:/pentest/
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: E2E Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Start Docker containers
        run: docker-compose up -d
      
      - name: Wait for containers
        run: sleep 10
      
      - name: Run tests
        run: ./scripts/test_in_docker.sh
      
      - name: Stop containers
        run: docker-compose down
```

---

## Performance Testing

### Measure Agent Performance

```bash
docker exec tazosploit-kali python3 /opt/open-interpreter/dynamic_agent.py \
  --target http://dvna:9090 \
  --objective "Complete security audit" \
  --max-iterations 10 \
  --llm-provider auto
```

Metrics to track:
- Total iterations
- Successful executions
- Failed executions
- LLM tokens used
- Total duration

---

## Best Practices

1. **Always test in Docker** - Never run tests on host machine
2. **Use test script** - `./scripts/test_in_docker.sh` for consistency
3. **Check logs** - Review logs after each test run
4. **Clean up** - Remove old session files periodically
5. **Monitor resources** - Watch Docker container resource usage

---

## Quick Reference

```bash
# Run all tests
./scripts/test_in_docker.sh

# Run specific test
docker exec tazosploit-kali python3 /pentest/test_new_features.py

# Test CVE lookup
docker exec tazosploit-kali python3 /opt/open-interpreter/cve_lookup.py CVE-2021-44228

# View logs
docker exec tazosploit-kali cat /pentest/logs/dynamic_agent.log

# Interactive shell
docker exec -it tazosploit-kali bash
```

---

## Summary

- ✅ All tests run inside Docker containers
- ✅ Use `./scripts/test_in_docker.sh` for automated testing
- ✅ Logs stored in `/pentest/logs/` inside container
- ✅ Session files persist across container restarts
- ✅ Integration tests use Docker networking

**Never run tests locally** - TazoSploit is a  application that requires the Docker environment.
