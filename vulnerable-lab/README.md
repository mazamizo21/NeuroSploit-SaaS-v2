# NeuroSploit Enterprise Vulnerable Lab

Comprehensive multi-tier vulnerable environment for intense penetration testing.

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL NETWORK (10.0.1.0/24)               │
│                                                                     │
│  ┌─────────────┐                              ┌─────────────────┐   │
│  │ Kali        │                              │ Internet        │   │
│  │ Attacker    │◄────────────────────────────►│ (Your Host)     │   │
│  │ 10.0.1.100  │                              │                 │   │
│  └─────────────┘                              └─────────────────┘   │
│         │                                                           │
└─────────┼───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    FIREWALL (10.0.1.1 / 10.0.2.1 / 10.0.3.1)        │
│                        Alpine + iptables + NAT                       │
└─────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        DMZ NETWORK (10.0.2.0/24)                    │
│                                                                     │
│  ┌─────────────────┐                                                │
│  │ Load Balancer   │  HAProxy - Stats exposed (no auth)             │
│  │ 10.0.2.10       │  Port 80, 443, 8404                            │
│  └────────┬────────┘                                                │
│           │                                                         │
│  ┌────────┴────────┬────────────────┬────────────────┐              │
│  │                 │                │                │              │
│  ▼                 ▼                ▼                ▼              │
│ ┌─────────┐  ┌─────────┐    ┌─────────┐      ┌─────────┐           │
│ │ DVWA    │  │ DVNA    │    │ Juice   │      │ WebGoat │           │
│ │ PHP     │  │ Node.js │    │ Shop    │      │ Java    │           │
│ │ :8081   │  │ :9091   │    │ :3000   │      │ :8082   │           │
│ └─────────┘  └─────────┘    └─────────┘      └─────────┘           │
│                                                                     │
│  ┌─────────────────┐                                                │
│  │ Vulnerable API  │  SQLi, CMDi, SSRF, IDOR, XXE                   │
│  │ 10.0.2.24:5000  │                                                │
│  └─────────────────┘                                                │
└─────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      INTERNAL NETWORK (10.0.3.0/24)                 │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                  │
│  │ File Server │  │ Jump Host   │  │ Admin Panel │                  │
│  │ Samba       │  │ SSH         │  │ PHP         │                  │
│  │ 10.0.3.30   │  │ 10.0.3.31   │  │ 10.0.3.32   │                  │
│  │ :445, :139  │  │ :2222       │  │ :80         │                  │
│  └─────────────┘  └─────────────┘  └─────────────┘                  │
│                                                                     │
│  ┌─────────────────────────────────────────────────┐                │
│  │ Monitoring: Elasticsearch (10.0.3.50:9200)      │                │
│  │            Kibana (10.0.3.51:5601)              │                │
│  └─────────────────────────────────────────────────┘                │
└─────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      DATABASE NETWORK (10.0.4.0/24)                 │
│                                                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐  │
│  │ MySQL       │  │ PostgreSQL  │  │ MongoDB     │  │ Redis     │  │
│  │ 10.0.4.40   │  │ 10.0.4.41   │  │ 10.0.4.42   │  │ 10.0.4.43 │  │
│  │ :3306       │  │ :5432       │  │ :27017      │  │ :6379     │  │
│  │ root:root123│  │ postgres:   │  │ No Auth    │  │ No Auth   │  │
│  └─────────────┘  │ postgres    │  └─────────────┘  └───────────┘  │
│                   └─────────────┘                                   │
└─────────────────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

```bash
# Navigate to the vulnerable lab directory
cd vulnerable-lab

# Create required directories
mkdir -p samba/shared samba/confidential admin-panel/uploads

# Add some fake confidential files
echo "SECRET: AWS Access Key: AKIAIOSFODNN7EXAMPLE" > samba/confidential/aws_keys.txt
echo "Password List: admin:admin123, root:toor" > samba/confidential/passwords.txt

# Start the lab
docker-compose -f docker-compose.enterprise.yml up -d

# Check status
docker-compose -f docker-compose.enterprise.yml ps
```

## 🎯 Attack Scenarios

### Scenario 1: External to DMZ
1. Scan the firewall (10.0.1.1)
2. Discover load balancer stats page (no auth)
3. Enumerate web applications through LB
4. Exploit DVWA/DVNA/JuiceShop vulnerabilities

### Scenario 2: DMZ to Internal (Lateral Movement)
1. Exploit vulnerable API (command injection)
2. Discover internal network (10.0.3.0/24)
3. Access file server with default creds
4. Extract confidential documents

### Scenario 3: Internal to Database (Privilege Escalation)
1. Find database credentials in config files
2. Connect to MySQL with weak credentials
3. Dump sensitive data (credit cards, SSNs)
4. Access all databases via backup user

### Scenario 4: Full Kill Chain
1. **Recon**: nmap the external network
2. **Initial Access**: Exploit DVWA SQLi
3. **Execution**: Command injection via vulnerable API
4. **Persistence**: Create SSH backdoor on jumphost
5. **Privilege Escalation**: Use found creds for root access
6. **Credential Access**: Dump MySQL users table
7. **Discovery**: Map internal network
8. **Lateral Movement**: SSH to other hosts with creds
9. **Collection**: Dump all databases
10. **Exfiltration**: Package and extract data

## 🔓 Default Credentials

| Service | Username | Password | Notes |
|---------|----------|----------|-------|
| DVWA | admin | admin | Web login |
| MySQL | root | root123 | Full access |
| MySQL | backup | backup123 | All DBs |
| PostgreSQL | postgres | postgres | Default |
| MongoDB | - | - | No auth |
| Redis | - | - | No auth |
| File Server | admin | admin123 | SMB |
| Jump Host | admin | admin123 | SSH |
| Admin Panel | admin | admin123 | PHP |
| API | admin | admin123 | /api/login |

## 🛠️ Vulnerable Services Summary

| Service | Vulnerabilities |
|---------|-----------------|
| **HAProxy** | Stats page without auth, backend enumeration |
| **DVWA** | SQLi, XSS, CSRF, Command Injection, File Upload |
| **DVNA** | NoSQL Injection, SSRF, XXE, SSTI |
| **Juice Shop** | 100+ vulnerabilities (OWASP Top 10) |
| **WebGoat** | Educational vulnerabilities |
| **Vulnerable API** | SQLi, CMDi, SSRF, IDOR, XXE, Info Disclosure |
| **Admin Panel** | Auth bypass, LFI, RCE, File Upload |
| **File Server** | Weak credentials, sensitive file exposure |
| **MySQL** | Weak passwords, sensitive data, backup user |
| **Elasticsearch** | No authentication, data exposure |

## 📊 Port Mapping

| External Port | Internal Service | Network |
|---------------|------------------|---------|
| 80, 443 | Load Balancer | DMZ |
| 8404 | HAProxy Stats | DMZ |
| 8081 | DVWA | DMZ |
| 9091 | DVNA | DMZ |
| 3000 | Juice Shop | DMZ |
| 8082 | WebGoat | DMZ |
| 5000 | Vulnerable API | DMZ |
| 8888 | Admin Panel | Internal |
| 445, 139 | File Server | Internal |
| 2223 | Jump Host SSH | Internal |
| 3306 | MySQL | Database |
| 5432 | PostgreSQL | Database |
| 27017 | MongoDB | Database |
| 6379 | Redis | Database |
| 9200 | Elasticsearch | Internal |
| 5601 | Kibana | Internal |

## 🧪 Testing with NeuroSploit

```bash
# Run full enterprise pentest
docker run --rm -it \
  --network vulnerable-lab_external \
  -e LLM_API_BASE="http://host.docker.internal:1234/v1" \
  -e LLM_MODEL="openai/gpt-oss-120b" \
  -v $(pwd)/logs:/pentest/logs \
  neurosploit-kali:minimal \
  python3 /opt/neurosploit/dynamic_agent.py \
  --target "10.0.1.1" \
  --objective "Perform a full enterprise penetration test. Start with the firewall, discover the DMZ services, exploit web vulnerabilities, pivot to internal network, access databases, and extract all sensitive data. Follow the complete MITRE ATT&CK kill chain." \
  --max-iterations 50
```

## 🧹 Cleanup

```bash
# Stop and remove all containers
docker-compose -f docker-compose.enterprise.yml down -v

# Remove networks
docker network prune -f
```

## ⚠️ Warning

This lab contains intentionally vulnerable services. **DO NOT** expose to the internet or use in production environments.
