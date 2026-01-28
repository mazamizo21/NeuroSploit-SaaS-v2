# Phase 3: Advanced Features + Testing

## Overview

Combine advanced AI/ML features with comprehensive testing to ensure production readiness.

**Timeline:** 3-4 weeks  
**Status:** Planning

---

## Part A: Advanced Features

### 3.1 Real-Time Graph Updates

**Goal:** Live attack graph updates as findings are discovered during pentest execution.

**Architecture:**
```
Kali Executor → Redis Pub/Sub → Control Plane → WebSocket → Frontend
     ↓
  Finding Created
     ↓
  Publish "finding.created" event
     ↓
  Graph Service updates graph incrementally
     ↓
  Push update to connected clients
```

**Implementation:**

**1. Redis Pub/Sub for Events**
```python
# control-plane/services/event_service.py
class EventService:
    def __init__(self, redis_client):
        self.redis = redis_client
        self.pubsub = redis_client.pubsub()
    
    async def publish_finding_created(self, job_id: UUID, finding: dict):
        """Publish finding created event"""
        await self.redis.publish(
            f"job:{job_id}:findings",
            json.dumps({
                "event": "finding.created",
                "job_id": str(job_id),
                "finding": finding,
                "timestamp": datetime.utcnow().isoformat()
            })
        )
    
    async def subscribe_to_job(self, job_id: UUID):
        """Subscribe to job events"""
        self.pubsub.subscribe(f"job:{job_id}:findings")
        async for message in self.pubsub.listen():
            if message["type"] == "message":
                yield json.loads(message["data"])
```

**2. Incremental Graph Updates**
```python
# control-plane/services/attack_graph_service.py
class AttackGraphService:
    async def update_graph_incremental(
        self,
        job_id: UUID,
        new_finding: dict
    ) -> dict:
        """
        Add new finding to existing graph without rebuilding
        
        1. Load existing graph from database
        2. Create new nodes/edges for finding
        3. Update graph structure
        4. Recalculate affected paths
        5. Save changes
        """
        # Load existing graph
        graph = await self.load_graph(job_id)
        
        # Create new nodes
        new_nodes = self._create_nodes_from_finding(new_finding)
        new_edges = self._create_edges_from_finding(new_finding, graph)
        
        # Add to graph
        graph["nodes"].extend(new_nodes)
        graph["edges"].extend(new_edges)
        
        # Recalculate paths involving new nodes
        affected_paths = self._recalculate_paths(graph, new_nodes)
        
        return {
            "new_nodes": new_nodes,
            "new_edges": new_edges,
            "affected_paths": affected_paths
        }
```

**3. WebSocket Endpoint**
```python
# control-plane/api/routers/websocket.py
from fastapi import WebSocket, WebSocketDisconnect

@router.websocket("/ws/jobs/{job_id}/graph")
async def graph_updates_websocket(
    websocket: WebSocket,
    job_id: UUID
):
    """WebSocket for real-time graph updates"""
    await websocket.accept()
    
    try:
        # Subscribe to job events
        async for event in event_service.subscribe_to_job(job_id):
            if event["event"] == "finding.created":
                # Update graph incrementally
                update = await attack_graph_service.update_graph_incremental(
                    job_id,
                    event["finding"]
                )
                
                # Send to client
                await websocket.send_json({
                    "type": "graph.update",
                    "data": update
                })
    
    except WebSocketDisconnect:
        pass
```

**Benefits:**
- See attack surface expand in real-time
- Immediate visibility into new attack paths
- No need to refresh or rebuild graph
- Better UX for security teams

---

### 3.2 Attack Simulation (What-If Scenarios)

**Goal:** Simulate potential attacks to understand risk before they happen.

**Use Cases:**
1. "What if this vulnerability is exploited?"
2. "What if we patch this vulnerability?"
3. "What if attacker gains access to this host?"
4. "What attack paths would be eliminated by this control?"

**Implementation:**

**1. Simulation Engine**
```python
# control-plane/services/simulation_service.py
class SimulationService:
    def simulate_exploit(
        self,
        graph: dict,
        vulnerability_node_id: str
    ) -> dict:
        """
        Simulate exploiting a vulnerability
        
        Returns:
        - New nodes created (access gained)
        - New edges created (new paths)
        - Risk score change
        - Affected critical paths
        """
        # Clone graph for simulation
        sim_graph = copy.deepcopy(graph)
        
        # Find vulnerability node
        vuln_node = self._find_node(sim_graph, vulnerability_node_id)
        
        # Create exploit node
        exploit_node = {
            "id": f"sim-exploit-{uuid4()}",
            "type": "exploit",
            "name": f"Simulated: {vuln_node['name']}",
            "risk_score": 90,
            "metadata": {"simulated": True}
        }
        
        # Add to graph
        sim_graph["nodes"].append(exploit_node)
        
        # Create edge
        sim_graph["edges"].append({
            "source": vulnerability_node_id,
            "target": exploit_node["id"],
            "type": "exploits",
            "impact": "critical"
        })
        
        # Find what this exploit could access
        target_host = vuln_node["metadata"].get("target")
        if target_host:
            # Add access to host
            access_node = {
                "id": f"sim-access-{uuid4()}",
                "type": "access",
                "name": f"Access to {target_host}",
                "risk_score": 85
            }
            sim_graph["nodes"].append(access_node)
            sim_graph["edges"].append({
                "source": exploit_node["id"],
                "target": access_node["id"],
                "type": "grants_access",
                "impact": "critical"
            })
        
        # Calculate impact
        original_risk = self._calculate_graph_risk(graph)
        simulated_risk = self._calculate_graph_risk(sim_graph)
        
        return {
            "simulation_type": "exploit",
            "target_node": vulnerability_node_id,
            "new_nodes": [exploit_node, access_node],
            "new_edges": sim_graph["edges"][-2:],
            "risk_increase": simulated_risk - original_risk,
            "original_risk": original_risk,
            "simulated_risk": simulated_risk
        }
    
    def simulate_patch(
        self,
        graph: dict,
        vulnerability_node_id: str
    ) -> dict:
        """
        Simulate patching a vulnerability
        
        Returns:
        - Paths eliminated
        - Risk score reduction
        - Critical paths affected
        """
        sim_graph = copy.deepcopy(graph)
        
        # Remove vulnerability node and connected edges
        sim_graph["nodes"] = [
            n for n in sim_graph["nodes"] 
            if n["id"] != vulnerability_node_id
        ]
        sim_graph["edges"] = [
            e for e in sim_graph["edges"]
            if e["source"] != vulnerability_node_id and e["target"] != vulnerability_node_id
        ]
        
        # Calculate impact
        original_paths = AttackGraphService.find_all_paths(graph, ...)
        simulated_paths = AttackGraphService.find_all_paths(sim_graph, ...)
        
        eliminated_paths = len(original_paths) - len(simulated_paths)
        
        return {
            "simulation_type": "patch",
            "target_node": vulnerability_node_id,
            "paths_eliminated": eliminated_paths,
            "risk_reduction": original_risk - simulated_risk,
            "recommendation": "HIGH PRIORITY" if eliminated_paths > 5 else "MEDIUM PRIORITY"
        }
    
    def simulate_control(
        self,
        graph: dict,
        control_type: str,
        control_location: str
    ) -> dict:
        """
        Simulate adding a security control
        
        Control types:
        - firewall: Block network access
        - waf: Block web attacks
        - ids: Detect attacks
        - segmentation: Network isolation
        """
        # Implementation varies by control type
        pass
```

**2. Simulation API**
```python
# control-plane/api/routers/simulations.py
@router.post("/jobs/{job_id}/simulate/exploit")
async def simulate_exploit(
    job_id: UUID,
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Simulate exploiting a vulnerability"""
    graph = await attack_graph_service.get_graph(job_id)
    result = simulation_service.simulate_exploit(graph, vulnerability_id)
    return result

@router.post("/jobs/{job_id}/simulate/patch")
async def simulate_patch(
    job_id: UUID,
    vulnerability_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Simulate patching a vulnerability"""
    graph = await attack_graph_service.get_graph(job_id)
    result = simulation_service.simulate_patch(graph, vulnerability_id)
    return result

@router.post("/jobs/{job_id}/simulate/control")
async def simulate_control(
    job_id: UUID,
    control: ControlSimulation,
    db: AsyncSession = Depends(get_db)
):
    """Simulate adding a security control"""
    graph = await attack_graph_service.get_graph(job_id)
    result = simulation_service.simulate_control(
        graph,
        control.type,
        control.location
    )
    return result
```

**Benefits:**
- Understand attack impact before it happens
- Prioritize patches based on risk reduction
- Evaluate security controls before deployment
- Data-driven security decisions

---

### 3.3 Machine Learning Path Prediction

**Goal:** Predict likely attack paths based on historical data and attacker behavior.

**Approach:**

**1. Data Collection**
```python
# Collect training data from historical pentests
training_data = {
    "features": [
        "vulnerability_severity",
        "cvss_score",
        "exploit_availability",
        "target_criticality",
        "network_position",
        "service_type",
        "patch_age_days"
    ],
    "labels": [
        "was_exploited",  # Binary: 0 or 1
        "led_to_critical_asset"  # Binary: 0 or 1
    ]
}
```

**2. Model Training**
```python
# control-plane/services/ml_prediction_service.py
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

class MLPredictionService:
    def __init__(self):
        self.exploit_model = RandomForestClassifier(n_estimators=100)
        self.critical_path_model = RandomForestClassifier(n_estimators=100)
    
    def train_exploit_prediction(self, historical_data):
        """Train model to predict exploit likelihood"""
        X = historical_data["features"]
        y = historical_data["was_exploited"]
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
        
        self.exploit_model.fit(X_train, y_train)
        accuracy = self.exploit_model.score(X_test, y_test)
        
        return {"accuracy": accuracy}
    
    def predict_exploit_likelihood(self, vulnerability: dict) -> float:
        """Predict probability that vulnerability will be exploited"""
        features = self._extract_features(vulnerability)
        probability = self.exploit_model.predict_proba([features])[0][1]
        return probability
    
    def predict_critical_paths(self, graph: dict) -> List[dict]:
        """Predict most likely attack paths to critical assets"""
        # For each path, calculate likelihood
        paths = AttackGraphService.find_all_paths(graph, ...)
        
        predictions = []
        for path in paths:
            # Extract features from path
            features = self._extract_path_features(path, graph)
            
            # Predict likelihood
            likelihood = self.critical_path_model.predict_proba([features])[0][1]
            
            predictions.append({
                "path": path,
                "likelihood": likelihood,
                "risk_score": AttackGraphService.calculate_path_risk(graph, path)
            })
        
        # Sort by likelihood * risk
        predictions.sort(key=lambda p: p["likelihood"] * p["risk_score"], reverse=True)
        
        return predictions[:10]
```

**3. Prediction API**
```python
@router.get("/jobs/{job_id}/predictions/likely-exploits")
async def predict_likely_exploits(job_id: UUID):
    """Predict which vulnerabilities are most likely to be exploited"""
    vulnerabilities = await get_vulnerabilities(job_id)
    
    predictions = []
    for vuln in vulnerabilities:
        likelihood = ml_service.predict_exploit_likelihood(vuln)
        predictions.append({
            "vulnerability": vuln,
            "exploit_likelihood": likelihood,
            "priority": "CRITICAL" if likelihood > 0.8 else "HIGH" if likelihood > 0.5 else "MEDIUM"
        })
    
    return sorted(predictions, key=lambda p: p["exploit_likelihood"], reverse=True)

@router.get("/jobs/{job_id}/predictions/attack-paths")
async def predict_attack_paths(job_id: UUID):
    """Predict most likely attack paths"""
    graph = await attack_graph_service.get_graph(job_id)
    predictions = ml_service.predict_critical_paths(graph)
    return predictions
```

**Benefits:**
- Focus on vulnerabilities attackers are likely to exploit
- Predict attack paths before they happen
- Data-driven prioritization
- Learn from historical attacks

---

## Part B: Comprehensive Testing

### 3.4 Load Testing

**Goal:** Ensure platform can handle production load.

**Tools:** Locust, k6, Apache JMeter

**Test Scenarios:**

**1. API Load Test**
```python
# tests/load/locustfile.py
from locust import HttpUser, task, between

class TazoSploitUser(HttpUser):
    wait_time = between(1, 3)
    
    def on_start(self):
        # Login and get token
        response = self.client.post("/api/v1/auth/login", json={
            "username": "test@example.com",
            "password": "password"
        })
        self.token = response.json()["access_token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}
    
    @task(3)
    def list_jobs(self):
        """List jobs (common operation)"""
        self.client.get("/api/v1/jobs", headers=self.headers)
    
    @task(2)
    def get_attack_graph(self):
        """Get attack graph (heavy operation)"""
        self.client.get(f"/api/v1/attack-graphs/jobs/{self.job_id}", headers=self.headers)
    
    @task(1)
    def build_attack_graph(self):
        """Build attack graph (expensive operation)"""
        self.client.post(f"/api/v1/attack-graphs/jobs/{self.job_id}/build", headers=self.headers)
    
    @task(2)
    def get_mitre_techniques(self):
        """Get MITRE techniques (cached operation)"""
        self.client.get("/api/v1/mitre/techniques?limit=50", headers=self.headers)
```

**Run Load Test:**
```bash
# Start with 10 users, ramp up to 100
locust -f tests/load/locustfile.py --host=http://localhost:8000 --users=100 --spawn-rate=10
```

**Performance Targets:**
- 1000 requests/second sustained
- <500ms p95 response time
- <1% error rate
- 100 concurrent users

**2. Database Load Test**
```sql
-- Simulate heavy query load
SELECT pg_stat_statements_reset();

-- Run for 5 minutes
-- Monitor slow queries
SELECT query, mean_exec_time, calls
FROM pg_stat_statements
WHERE mean_exec_time > 100
ORDER BY mean_exec_time DESC
LIMIT 20;
```

**3. WebSocket Load Test**
```python
# tests/load/websocket_load.py
import asyncio
import websockets

async def connect_client(client_id):
    uri = f"ws://localhost:8000/ws/jobs/{job_id}/graph"
    async with websockets.connect(uri) as websocket:
        # Receive updates for 60 seconds
        for _ in range(60):
            message = await websocket.recv()
            await asyncio.sleep(1)

# Simulate 50 concurrent WebSocket connections
await asyncio.gather(*[connect_client(i) for i in range(50)])
```

---

### 3.5 Security Audit & Penetration Testing

**Goal:** Identify and fix security vulnerabilities before production.

**Areas to Test:**

**1. Authentication & Authorization**
```
✓ JWT token validation
✓ Token expiration
✓ Refresh token security
✓ Password hashing (bcrypt)
✓ Rate limiting on login
✓ Account lockout after failed attempts
✓ RBAC enforcement
✓ Tenant isolation
```

**2. API Security**
```
✓ SQL injection prevention
✓ XSS prevention
✓ CSRF protection
✓ Input validation
✓ Output encoding
✓ Rate limiting per endpoint
✓ API key security
✓ CORS configuration
```

**3. Infrastructure Security**
```
✓ Docker container security
✓ Network segmentation
✓ Secrets management
✓ Database encryption at rest
✓ TLS/SSL configuration
✓ Firewall rules
✓ Log security
```

**4. Penetration Testing Checklist**
```bash
# OWASP Top 10 Testing
1. Broken Access Control
   - Test tenant isolation
   - Test RBAC bypass
   - Test direct object references

2. Cryptographic Failures
   - Test password storage
   - Test data encryption
   - Test TLS configuration

3. Injection
   - SQL injection
   - Command injection
   - LDAP injection

4. Insecure Design
   - Business logic flaws
   - Missing security controls

5. Security Misconfiguration
   - Default credentials
   - Unnecessary features enabled
   - Error messages leaking info

6. Vulnerable Components
   - Outdated dependencies
   - Known CVEs

7. Authentication Failures
   - Weak passwords
   - Session management
   - Credential stuffing

8. Data Integrity Failures
   - Unsigned/unverified data
   - Insecure deserialization

9. Logging Failures
   - Missing audit logs
   - Log injection

10. SSRF
    - Internal service access
    - Cloud metadata access
```

**Tools:**
- **OWASP ZAP** - Automated security scanning
- **Burp Suite** - Manual penetration testing
- **sqlmap** - SQL injection testing
- **nikto** - Web server scanning
- **nmap** - Network scanning

---

### 3.6 User Acceptance Testing (UAT)

**Goal:** Validate platform meets user needs and expectations.

**Test Users:**
- Security analysts
- Penetration testers
- Security managers
- DevSecOps engineers

**Test Scenarios:**

**1. Pentest Workflow**
```
Scenario: Run a complete pentest
1. Create scope
2. Create job
3. Monitor execution
4. Review findings
5. Build attack graph
6. Identify critical paths
7. Generate report
8. Export results

Success Criteria:
- Complete workflow in <30 minutes
- All features work as expected
- UI is intuitive
- Reports are actionable
```

**2. Team Collaboration**
```
Scenario: Multi-user collaboration
1. Create workspace
2. Add team members
3. Assign roles
4. Comment on findings
5. Track activity
6. Share reports

Success Criteria:
- Real-time updates
- Clear permissions
- Easy communication
```

**3. Continuous Scanning**
```
Scenario: Schedule recurring scans
1. Create scheduled job
2. Set cron schedule
3. Monitor executions
4. Review trend analysis
5. Compare results over time

Success Criteria:
- Jobs run on schedule
- Historical data accessible
- Trends visible
```

**Feedback Collection:**
```
For each scenario:
- Time to complete
- Difficulty rating (1-5)
- Confusion points
- Missing features
- Bug reports
- Improvement suggestions
```

---

## Implementation Timeline

### Week 1: Real-Time Updates
- Redis Pub/Sub setup
- Event service
- Incremental graph updates
- WebSocket endpoint
- Testing

### Week 2: Attack Simulation
- Simulation engine
- Exploit simulation
- Patch simulation
- Control simulation
- API endpoints
- Testing

### Week 3: ML Prediction + Load Testing
- Data collection
- Model training
- Prediction API
- Load test setup
- Performance optimization

### Week 4: Security + UAT
- Security audit
- Penetration testing
- Fix vulnerabilities
- UAT with test users
- Final documentation

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Real-time update latency | <100ms |
| Simulation accuracy | >90% |
| ML prediction accuracy | >80% |
| Load test: RPS | 1000+ |
| Load test: p95 latency | <500ms |
| Security issues found | 0 critical, <5 high |
| UAT satisfaction | >4.5/5 |

---

## Deliverables

1. **Real-Time System**
   - Event service
   - WebSocket API
   - Incremental updates

2. **Simulation Engine**
   - Exploit simulation
   - Patch simulation
   - Control simulation
   - API endpoints

3. **ML Models**
   - Exploit prediction model
   - Path prediction model
   - Training pipeline

4. **Test Reports**
   - Load test results
   - Security audit report
   - Penetration test report
   - UAT feedback summary

5. **Documentation**
   - API documentation
   - User guides
   - Security hardening guide
   - Deployment guide

---

**Next Steps:**
1. Review and approve Phase 3 plan
2. Set up development environment
3. Begin implementation
4. Schedule testing with users
