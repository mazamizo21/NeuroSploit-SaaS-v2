#!/bin/bash
# Run NeuroSploit in UNLIMITED mode - continues until full compromise

set -e

echo "=========================================="
echo "NeuroSploit UNLIMITED Exploitation Mode"
echo "=========================================="

LLM_API_BASE="${LLM_API_BASE:-http://host.docker.internal:1234/v1}"
LLM_MODEL="${LLM_MODEL:-openai/gpt-oss-120b}"

mkdir -p logs
rm -f logs/*.jsonl logs/*.log logs/*.json logs/*.md 2>/dev/null

echo "Target: Enterprise Lab (All Networks)"
echo "LLM: $LLM_MODEL"
echo "Mode: UNLIMITED (stops only when no progress)"
echo ""

# Build image if needed
echo "Building Kali image..."
docker build -t neurosploit-kali:minimal -f ../kali-executor/Dockerfile.minimal ../kali-executor 2>&1 | tail -3

echo ""
echo "Starting UNLIMITED penetration test..."
echo "This will continue until full compromise or no progress for 5 iterations"
echo "=========================================="

# Run with very high iteration limit (effectively unlimited)
docker run --rm -it \
  --network vulnerable-lab_dmz \
  -e LLM_API_BASE="$LLM_API_BASE" \
  -e LLM_MODEL="$LLM_MODEL" \
  -v "$(pwd)/logs:/pentest/logs" \
  -v "$(pwd)/../kali-executor/open-interpreter:/opt/neurosploit" \
  neurosploit-kali:minimal \
  python3 /opt/neurosploit/dynamic_agent.py \
  --target "10.0.2.10" \
  --objective "Perform comprehensive security audit on enterprise lab environment.

TARGET ENVIRONMENT:
- DMZ Network: 10.0.2.0/24 (Load balancer, web applications, APIs)
- Internal Network: 10.0.3.0/24 (Admin systems, file storage, monitoring)
- Database Network: 10.0.4.0/24 (MySQL, PostgreSQL, MongoDB, Redis)

AUDIT SCOPE - Test ALL security controls:

1. **Input Validation Testing**
   - Test web forms for injection vulnerabilities
   - Use sqlmap to assess database exposure: sqlmap -u URL --batch --dump
   - Document what data would be accessible

2. **Authentication Security**
   - Test default credentials on all services
   - Verify access controls on admin interfaces
   - Check database authentication (MySQL 10.0.4.40, PostgreSQL 10.0.4.41)

3. **Configuration Review**
   - Connect to databases and review exposed data
   - Example: mysql -h 10.0.4.40 -u root -proot123 -e \"SHOW DATABASES; SELECT * FROM users LIMIT 10;\"
   - Check for sensitive information in configs

4. **API Security Testing**
   - Test API endpoints for command execution vulnerabilities
   - Example: curl \"http://10.0.2.24:5000/api/debug\"
   - Verify input sanitization

5. **File Access Controls**
   - Test for directory traversal vulnerabilities
   - Verify file upload restrictions
   - Check system file access

6. **Network Segmentation**
   - Test connectivity between network tiers
   - Verify credential reuse across systems
   - Document lateral movement paths

7. **Data Protection**
   - Package audit findings: tar -czf /tmp/audit_evidence.tar.gz /tmp/*.txt
   - Document all discovered vulnerabilities

KNOWN TEST CREDENTIALS:
- Web apps: admin:admin
- MySQL: root:root123
- PostgreSQL: postgres:postgres

Continue testing until all security controls are thoroughly assessed." \
  --max-iterations 100 2>&1 | tee logs/unlimited_run.log

echo ""
echo "=========================================="
echo "Unlimited Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for full findings"
