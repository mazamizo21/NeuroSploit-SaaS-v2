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
  --objective "FULL COMPROMISE REQUIRED. You must exploit ACTUAL VULNERABILITIES, not just credentials.

TARGET ENVIRONMENT:
- DMZ: 10.0.2.0/24 (Load balancer, DVWA, DVNA, JuiceShop, WebGoat, Vulnerable API)
- Internal: 10.0.3.0/24 (Admin panel, File server, Elasticsearch, Kibana)
- Database: 10.0.4.0/24 (MySQL, PostgreSQL, MongoDB, Redis)

EXPLOITATION REQUIREMENTS (ALL MUST BE COMPLETED):

1. **SQL Injection Exploitation**
   - Use sqlmap to DUMP databases (not just detect)
   - Extract ALL tables with sensitive data
   - Save dumps to /tmp/sqli_dumps/

2. **Command Injection**
   - Find and exploit command injection vulnerabilities
   - Execute system commands (id, whoami, uname -a)
   - Read /etc/passwd, /etc/shadow if possible

3. **File Upload to RCE**
   - Upload webshell to vulnerable upload endpoints
   - Execute commands through webshell
   - Establish persistence

4. **Database Direct Access**
   - Connect to MySQL (10.0.4.40:3306) with root:root123
   - Connect to PostgreSQL (10.0.4.41:5432) with postgres:postgres
   - Dump ALL databases and tables
   - Extract credit cards, SSNs, passwords

5. **Lateral Movement**
   - Use found credentials to access other hosts
   - SSH to jumphost (10.0.3.31:2222) with admin:admin123
   - Access admin panel (10.0.3.32:80)
   - Mount file shares

6. **Data Exfiltration**
   - Package ALL obtained data into /tmp/FULL_COMPROMISE.tar.gz
   - Include: database dumps, config files, /etc/passwd, credentials

7. **Privilege Escalation**
   - Find SUID binaries
   - Check sudo permissions
   - Attempt to get root access

STOP CONDITIONS:
- Only stop when ALL 7 requirements are met
- OR no successful exploitation for 5 consecutive iterations

KNOWN ENTRY POINTS:
- DVWA: 10.0.2.20 (admin:admin)
- Vulnerable API: 10.0.2.24:5000 (/api/debug, /api/exec endpoints)
- MySQL: 10.0.4.40 (root:root123)
- PostgreSQL: 10.0.4.41 (postgres:postgres)

BEGIN EXPLOITATION NOW." \
  --max-iterations 100 2>&1 | tee logs/unlimited_run.log

echo ""
echo "=========================================="
echo "Unlimited Test Complete"
echo "=========================================="
echo "Logs: ./logs/"
echo "Check logs/COMPREHENSIVE_REPORT_*.md for full findings"
