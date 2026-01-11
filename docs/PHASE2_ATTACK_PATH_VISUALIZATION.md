# Phase 2: Attack Path Visualization

## Overview

Build visual attack graph capabilities to show multi-hop attack chains, helping security teams understand complex attack scenarios and prioritize remediation.

**Timeline:** 2-3 weeks  
**Status:** Planning

---

## Goals

1. **Visual Attack Graphs**: Interactive diagrams showing attack progression
2. **Multi-Hop Chains**: Identify paths from initial access to critical assets
3. **Risk-Based Prioritization**: Highlight highest-risk attack paths
4. **MITRE ATT&CK Mapping**: Show techniques used in each step
5. **Critical Asset Protection**: Focus on paths leading to crown jewels

---

## Features to Implement

### 2.1 Attack Graph Data Model

**Database Schema:**
```sql
CREATE TABLE attack_nodes (
    id UUID PRIMARY KEY,
    job_id UUID REFERENCES jobs(id),
    node_type VARCHAR(50),  -- host, service, vulnerability, exploit
    name VARCHAR(255),
    description TEXT,
    risk_score INTEGER,
    mitre_techniques JSONB,
    metadata JSONB,
    created_at TIMESTAMP
);

CREATE TABLE attack_edges (
    id UUID PRIMARY KEY,
    job_id UUID REFERENCES jobs(id),
    source_node_id UUID REFERENCES attack_nodes(id),
    target_node_id UUID REFERENCES attack_nodes(id),
    edge_type VARCHAR(50),  -- exploits, accesses, pivots_to
    technique_id VARCHAR(20),  -- MITRE technique
    difficulty VARCHAR(20),  -- easy, medium, hard
    impact VARCHAR(20),  -- low, medium, high, critical
    metadata JSONB,
    created_at TIMESTAMP
);

CREATE TABLE attack_paths (
    id UUID PRIMARY KEY,
    job_id UUID REFERENCES jobs(id),
    name VARCHAR(255),
    start_node_id UUID REFERENCES attack_nodes(id),
    end_node_id UUID REFERENCES attack_nodes(id),
    path_nodes JSONB,  -- Array of node IDs
    total_risk_score INTEGER,
    length INTEGER,  -- Number of hops
    metadata JSONB,
    created_at TIMESTAMP
);

CREATE TABLE critical_assets (
    id UUID PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id),
    name VARCHAR(255),
    asset_type VARCHAR(50),  -- server, database, service, credential
    criticality VARCHAR(20),  -- low, medium, high, critical
    identifiers JSONB,  -- IP, hostname, etc.
    metadata JSONB,
    created_at TIMESTAMP
);
```

**Node Types:**
- `host`: Target machines/servers
- `service`: Running services (SSH, HTTP, etc.)
- `vulnerability`: Discovered vulnerabilities
- `exploit`: Successful exploits
- `credential`: Compromised credentials
- `data`: Sensitive data access

**Edge Types:**
- `exploits`: Vulnerability → Exploit
- `accesses`: Exploit → Host/Service
- `pivots_to`: Host → Host (lateral movement)
- `escalates_to`: User → Admin (privilege escalation)
- `extracts`: Host → Data

---

### 2.2 Attack Graph Builder Service

**File:** `control-plane/services/attack_graph_service.py`

```python
class AttackGraphService:
    """Build attack graphs from pentest findings"""
    
    def build_graph(self, job_id: UUID) -> AttackGraph:
        """
        Build attack graph from job findings
        
        Steps:
        1. Load all findings for job
        2. Create nodes for hosts, services, vulnerabilities
        3. Create edges based on relationships
        4. Calculate risk scores for paths
        5. Identify critical paths
        """
        pass
    
    def find_attack_paths(
        self, 
        graph: AttackGraph, 
        start_node: UUID,
        end_node: UUID,
        max_hops: int = 10
    ) -> List[AttackPath]:
        """Find all paths from start to end node"""
        pass
    
    def calculate_path_risk(self, path: AttackPath) -> int:
        """Calculate risk score for attack path"""
        pass
    
    def identify_critical_paths(
        self,
        graph: AttackGraph,
        critical_assets: List[CriticalAsset]
    ) -> List[AttackPath]:
        """Find paths leading to critical assets"""
        pass
    
    def generate_recommendations(
        self,
        paths: List[AttackPath]
    ) -> List[str]:
        """Generate remediation recommendations"""
        pass
```

---

### 2.3 Graph Visualization API

**File:** `control-plane/api/routers/attack_graphs.py`

**Endpoints:**
```
POST /api/v1/attack-graphs/jobs/{job_id}/build
  - Build attack graph from job findings
  - Returns graph with nodes and edges

GET /api/v1/attack-graphs/jobs/{job_id}
  - Get attack graph for job
  - Returns nodes, edges, paths

GET /api/v1/attack-graphs/jobs/{job_id}/paths
  - Get all attack paths
  - Query params: min_risk, max_hops

GET /api/v1/attack-graphs/jobs/{job_id}/paths/critical
  - Get paths to critical assets
  - Sorted by risk score

GET /api/v1/attack-graphs/jobs/{job_id}/export
  - Export graph in various formats
  - Formats: json, graphml, cytoscape

POST /api/v1/critical-assets
  - Define critical assets for tenant
  - Used to identify high-priority paths

GET /api/v1/critical-assets
  - List tenant's critical assets
```

**Response Format (Graph):**
```json
{
  "job_id": "uuid",
  "nodes": [
    {
      "id": "node-1",
      "type": "host",
      "name": "192.168.1.10",
      "risk_score": 75,
      "mitre_techniques": ["T1190", "T1059"],
      "metadata": {
        "os": "Ubuntu 20.04",
        "open_ports": [22, 80, 443]
      }
    }
  ],
  "edges": [
    {
      "id": "edge-1",
      "source": "node-1",
      "target": "node-2",
      "type": "exploits",
      "technique_id": "T1190",
      "difficulty": "medium",
      "impact": "high"
    }
  ],
  "paths": [
    {
      "id": "path-1",
      "name": "Initial Access → Domain Admin",
      "nodes": ["node-1", "node-2", "node-3"],
      "risk_score": 95,
      "length": 3
    }
  ]
}
```

---

### 2.4 Graph Algorithms

**Path Finding:**
- Dijkstra's algorithm for shortest paths
- All paths enumeration (with max depth)
- Risk-weighted path scoring

**Risk Calculation:**
```python
def calculate_path_risk(path: AttackPath) -> int:
    """
    Path Risk = (Avg Node Risk * 0.4) + 
                (Max Edge Impact * 0.4) + 
                (Path Length Penalty * 0.2)
    
    Longer paths = lower risk (harder to execute)
    Shorter paths = higher risk (easier to execute)
    """
    node_risks = [node.risk_score for node in path.nodes]
    avg_node_risk = sum(node_risks) / len(node_risks)
    
    edge_impacts = {"low": 25, "medium": 50, "high": 75, "critical": 100}
    max_impact = max(edge_impacts[e.impact] for e in path.edges)
    
    # Penalize longer paths (harder to execute)
    length_penalty = max(0, 100 - (path.length * 10))
    
    return int(
        (avg_node_risk * 0.4) + 
        (max_impact * 0.4) + 
        (length_penalty * 0.2)
    )
```

---

### 2.5 Frontend Visualization (Future)

**Libraries to Use:**
- **Cytoscape.js**: Interactive graph visualization
- **D3.js**: Custom visualizations
- **vis.js**: Network diagrams

**Features:**
- Interactive node/edge selection
- Zoom and pan
- Filter by risk level
- Highlight critical paths
- MITRE technique tooltips
- Export to PNG/SVG

---

## Implementation Plan

### Week 1: Data Model & Graph Builder

**Tasks:**
1. Create database models (attack_nodes, attack_edges, attack_paths, critical_assets)
2. Implement AttackGraphService
3. Build graph from findings
4. Implement path finding algorithms

**Deliverables:**
- Database migrations
- AttackGraphService with core methods
- Unit tests

### Week 2: API & Visualization

**Tasks:**
1. Create attack_graphs router
2. Implement all API endpoints
3. Add graph export functionality
4. Critical asset management

**Deliverables:**
- Full API implementation
- Graph export (JSON, GraphML)
- API tests

### Week 3: Advanced Features

**Tasks:**
1. Risk-based path prioritization
2. Automated remediation recommendations
3. Integration with existing reports
4. Performance optimization

**Deliverables:**
- Risk scoring algorithm
- Recommendation engine
- Performance benchmarks

---

## Example Use Cases

### Use Case 1: Find Paths to Domain Admin

```python
# 1. Define critical asset
critical_asset = {
    "name": "Domain Admin Account",
    "asset_type": "credential",
    "criticality": "critical",
    "identifiers": {"username": "administrator"}
}

# 2. Build attack graph
graph = attack_graph_service.build_graph(job_id)

# 3. Find paths to critical asset
paths = attack_graph_service.identify_critical_paths(
    graph, 
    [critical_asset]
)

# 4. Get highest risk path
critical_path = max(paths, key=lambda p: p.risk_score)

# Output:
# Path: External Web Server → SQL Injection → 
#       Database Server → Credential Theft → 
#       Domain Controller → Domain Admin
# Risk Score: 95/100
# Techniques: T1190, T1059, T1003, T1078
```

### Use Case 2: Lateral Movement Analysis

```python
# Find all lateral movement paths
lateral_paths = attack_graph_service.find_paths_by_type(
    graph,
    edge_type="pivots_to"
)

# Identify pivot points (high-value targets for defense)
pivot_nodes = attack_graph_service.find_pivot_nodes(graph)

# Output:
# Pivot Nodes:
# - 192.168.1.50 (connects 3 network segments)
# - 10.0.0.100 (access to 5 critical servers)
```

---

## Success Metrics

| Metric | Target |
|--------|--------|
| Graph build time | <5 seconds for 100 findings |
| Path finding | <1 second for 1000 nodes |
| Critical path identification | 100% accuracy |
| API response time | <500ms |

---

## Integration with Existing Features

### MITRE ATT&CK
- Each edge tagged with technique ID
- Path visualization shows technique progression
- Recommendations based on MITRE mitigations

### Risk Scoring
- Path risk feeds into overall job risk score
- Critical paths increase risk score
- Remediation reduces path risk

### Reports
- Include attack graph in executive summary
- Show top 5 critical paths
- Visual diagram in HTML reports

---

## Future Enhancements (Phase 3+)

1. **Real-time Graph Updates**: Live graph as findings discovered
2. **Attack Simulation**: "What-if" scenarios
3. **Defensive Recommendations**: Where to place controls
4. **Threat Intelligence**: Integrate known attack patterns
5. **Machine Learning**: Predict likely attack paths
6. **Compliance Mapping**: Show paths violating compliance

---

## Technical Considerations

### Performance
- Index on job_id, node_type, edge_type
- Cache graphs for large jobs
- Limit path enumeration depth

### Scalability
- Handle graphs with 10,000+ nodes
- Efficient path finding algorithms
- Pagination for large result sets

### Security
- Tenant isolation for graphs
- Access control for critical assets
- Audit logging for graph access

---

## References

- **MITRE ATT&CK Navigator**: Inspiration for technique visualization
- **BloodHound**: Active Directory attack path analysis
- **Cytoscape**: Graph visualization library
- **NetworkX**: Python graph algorithms

---

**Next Steps:**
1. Review and approve Phase 2 plan
2. Create database migrations
3. Implement AttackGraphService
4. Build API endpoints
5. Test with real pentest data
