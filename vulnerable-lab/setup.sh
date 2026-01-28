#!/bin/bash
# TazoSploit Enterprise Vulnerable Lab Setup Script

set -e

echo "=========================================="
echo "TazoSploit Enterprise Vulnerable Lab"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Docker and Docker Compose found${NC}"

# Create required directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p samba/shared samba/confidential
mkdir -p admin-panel/uploads
mkdir -p logs
mkdir -p postgres/init

# Create fake confidential files
echo -e "${YELLOW}Creating fake sensitive data...${NC}"

cat > samba/confidential/aws_credentials.txt << 'EOF'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY
region = us-west-2
EOF

cat > samba/confidential/passwords.txt << 'EOF'
=== INTERNAL PASSWORD LIST - CONFIDENTIAL ===

Domain Admin: administrator / P@ssw0rd2024!
SQL Server: sa / SqlServer123!
Backup Account: backup_svc / Backup2024#
Service Account: svc_deploy / Deploy!ng123

Database Credentials:
- MySQL Root: root / root123
- PostgreSQL: postgres / postgres
- MongoDB: (no auth required)

SSH Keys Location: /home/admin/.ssh/
VPN Config: \\fileserver\confidential\vpn\

DO NOT SHARE THIS FILE
EOF

cat > samba/confidential/network_diagram.txt << 'EOF'
=== INTERNAL NETWORK DIAGRAM ===

External: 10.0.1.0/24
  - Firewall: 10.0.1.1
  
DMZ: 10.0.2.0/24
  - Load Balancer: 10.0.2.10
  - Web Servers: 10.0.2.20-24
  
Internal: 10.0.3.0/24
  - File Server: 10.0.3.30
  - Jump Host: 10.0.3.31
  - Admin Panel: 10.0.3.32
  - Elasticsearch: 10.0.3.50
  
Database: 10.0.4.0/24
  - MySQL: 10.0.4.40
  - PostgreSQL: 10.0.4.41
  - MongoDB: 10.0.4.42
  - Redis: 10.0.4.43

Firewall Rules: ALLOW ALL (for testing)
EOF

cat > samba/shared/welcome.txt << 'EOF'
Welcome to the Company File Server!

Please store your files in the appropriate folders.
Contact IT for access to confidential shares.

- IT Department
EOF

# Create PostgreSQL init script
cat > postgres/init/01-init.sql << 'EOF'
-- PostgreSQL Initialization
CREATE DATABASE secrets;
\c secrets

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    service VARCHAR(100),
    api_key VARCHAR(255),
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO api_keys (service, api_key) VALUES
('stripe', 'sk_test_FAKE_KEY_FOR_TESTING_ONLY'),
('sendgrid', 'SG_FAKE_KEY_FOR_TESTING_ONLY'),
('twilio', 'SK_FAKE_KEY_FOR_TESTING_ONLY'),
('aws', 'FAKE_AWS_KEY_FOR_TESTING');

CREATE TABLE users_backup (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50),
    password_hash VARCHAR(255),
    email VARCHAR(100)
);

INSERT INTO users_backup VALUES
(1, 'admin', 'admin123', 'admin@company.local'),
(2, 'root', 'toor', 'root@company.local');
EOF

echo -e "${GREEN}✓ Sensitive data files created${NC}"

# Check if lab is already running
if docker ps | grep -q "ns-"; then
    echo -e "${YELLOW}Lab containers already running. Stopping...${NC}"
    docker-compose -f docker-compose.enterprise.yml down
fi

# Start the lab
echo -e "${YELLOW}Starting Enterprise Vulnerable Lab...${NC}"
echo "This may take a few minutes on first run..."

docker-compose -f docker-compose.enterprise.yml up -d

# Wait for services to be ready
echo -e "${YELLOW}Waiting for services to initialize...${NC}"
sleep 10

# Check service status
echo ""
echo "=========================================="
echo "LAB STATUS"
echo "=========================================="

check_service() {
    local name=$1
    local port=$2
    if nc -z localhost $port 2>/dev/null; then
        echo -e "${GREEN}✓ $name (port $port)${NC}"
    else
        echo -e "${RED}✗ $name (port $port)${NC}"
    fi
}

check_service "Load Balancer" 80
check_service "HAProxy Stats" 8404
check_service "DVWA" 8081
check_service "DVNA" 9091
check_service "Juice Shop" 3000
check_service "WebGoat" 8082
check_service "Vulnerable API" 5000
check_service "Admin Panel" 8888
check_service "MySQL" 3306
check_service "PostgreSQL" 5432
check_service "MongoDB" 27017
check_service "Redis" 6379
check_service "Elasticsearch" 9200
check_service "Kibana" 5601

echo ""
echo "=========================================="
echo "ACCESS URLS"
echo "=========================================="
echo "Load Balancer:    http://localhost:80"
echo "HAProxy Stats:    http://localhost:8404/stats"
echo "DVWA:             http://localhost:8081"
echo "DVNA:             http://localhost:9091"
echo "Juice Shop:       http://localhost:3000"
echo "WebGoat:          http://localhost:8082/WebGoat"
echo "Vulnerable API:   http://localhost:5000"
echo "Admin Panel:      http://localhost:8888"
echo "Kibana:           http://localhost:5601"
echo ""
echo "=========================================="
echo "DEFAULT CREDENTIALS"
echo "=========================================="
echo "Most services:    admin / admin123"
echo "MySQL root:       root / root123"
echo "PostgreSQL:       postgres / postgres"
echo ""
echo -e "${GREEN}Lab is ready for testing!${NC}"
echo ""
echo "To run TazoSploit against this lab:"
echo "  ./run-test.sh"
