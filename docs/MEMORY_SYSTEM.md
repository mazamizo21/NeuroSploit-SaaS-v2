# Memory System Documentation

## Overview

The TazoSploit Memory System provides persistent storage and intelligent retrieval of pentest learnings across sessions. It enables the AI to remember successful techniques, avoid repeating mistakes, and build knowledge about targets over time.

## Architecture

```
memory/
├── memory_store.py              # Enhanced memory store with threat intelligence
├── TARGET_KNOWLEDGE/            # Per-target learnings
│   ├── target1.json
│   ├── target2.json
│   └── ...
├── SESSION_HISTORY/             # Session summaries
│   ├── session1.json
│   ├── session2.json
│   └── ...
├── THREAT_INTEL.md             # Threat intelligence patterns
├── threat_patterns.json         # Cross-target patterns
├── techniques.json             # Technique success/failure rates
└── credentials.json            # Credential reuse patterns
```

## Core Components

### EnhancedMemoryStore

The `EnhancedMemoryStore` class extends the base memory functionality with threat intelligence and learning capabilities.

```python
from memory.memory_store import EnhancedMemoryStore

# Initialize memory store for a target
store = EnhancedMemoryStore(tenant_id="default", target="192.168.1.100")

# Record technique results
store.record_technique("T1190", "SQL Injection", success=True)
store.record_technique("T1068", "Privilege Escalation", success=False)

# Get success rates
rate = store.get_technique_success_rate("T1190")
print(f"Success rate: {rate:.1f}%")

# Get best techniques
best = store.get_best_techniques(limit=5)
for tech in best:
    print(f"{tech.technique_name}: {tech.success_rate:.1f}%")
```

### Threat Patterns

Threat patterns track recurring security issues across multiple targets:

```python
from memory.memory_store import ThreatPattern

# Add a threat pattern
store.add_threat_pattern(
    pattern_type="default_config",
    pattern="MySQL with empty root password",
    description="MySQL instances with default empty root password",
    mitigation="Set strong MySQL root password",
    target="192.168.1.100"
)

# Generate threat intelligence report
report = store.generate_threat_intel_report()
print(report)
```

### Credential Patterns

Track credential reuse and weak password patterns:

```python
# Add credential pattern
store.add_credential_pattern(
    pattern="admin:admin123",
    category="weak",
    target="192.168.1.100"
)

# Add another occurrence on different target
store.add_credential_pattern(
    pattern="admin:admin123",
    category="weak",
    target="192.168.1.101"
)
```

### Target Knowledge

Store target-specific information:

```python
# Update target knowledge
store.update_target_knowledge("os", "Ubuntu 20.04")
store.update_target_knowledge("services", ["Apache 2.4", "MySQL 8.0"])
store.update_target_knowledge("last_scan", "2024-01-28T10:00:00Z")

# Retrieve target knowledge
os_info = store.get_target_knowledge("os")
services = store.get_target_knowledge("services")
all_knowledge = store.get_target_knowledge()
```

## Memory Categories

The memory system uses structured categories for storing different types of information:

### Base Categories (from memory.py)
- `tool_installed`: Tool was installed successfully
- `tool_failed`: Tool failed or doesn't work
- `package_name`: Correct package name for a tool
- `credential_found`: Credentials discovered
- `vulnerability_found`: Vulnerability identified
- `technique_worked`: Attack technique that worked
- `technique_failed`: Attack technique that failed
- `target_info`: Information about the target
- `access_gained`: Access level achieved

### Enhanced Categories (from memory_store.py)
- `threat_pattern`: Recurring security patterns
- `credential_reuse`: Credentials found on multiple targets
- `technique_performance`: Success/failure rates for techniques
- `configuration_drift`: Changes in target configuration

## Integration with DynamicAgent

Memory is integrated into the `DynamicAgent` to provide context from previous sessions:

```python
# In DynamicAgent.run()
if MEMORY_AVAILABLE:
    self.memory_store = EnhancedMemoryStore(tenant_id=tenant_id, target=target)
    
    # Add relevant memories to initial prompt
    memory_context = create_memory_prompt_section(
        self.memory_store,
        context_keywords=[target.split(':')[0], 'credential', 'vulnerability', 'tool']
    )
    if memory_context:
        initial_prompt += f"\n{memory_context}\n\n"
```

## Learning Features

### 1. Technique Success Rate Tracking

The system tracks which techniques work and which don't:

```python
# Record technique attempts
store.record_technique("T1190", "Exploit Public-Facing App", success=True)
store.record_technique("T1190", "Exploit Public-Facing App", success=True)
store.record_technique("T1190", "Exploit Public-Facing App", success=False)

# Success rate: 66.7%
```

### 2. Threat Pattern Detection

Automatically detects patterns across targets:

```python
# System tracks:
# - Default configurations
# - Common vulnerabilities
# - Misconfigurations
# - Credential reuse

# Get patterns with high occurrence
high_occurrence = [p for p in store.threat_patterns if p.occurrences >= 3]
```

### 3. Credential Reuse Analysis

Tracks credentials that appear on multiple targets:

```python
# Get reused credentials
reused = [c for c in store.credential_patterns if c.count > 1]
for cred in reused:
    print(f"{cred.pattern} found on {cred.count} targets")
```

## Session History

Save and retrieve session summaries:

```python
# Save session summary
store.save_session_summary(
    session_id="session_20240128_100000",
    summary={
        "objective": "Complete security assessment",
        "duration": 3600,
        "findings_count": 15,
        "critical_findings": 2,
        "high_findings": 5,
        "tools_used": ["nmap", "sqlmap", "nikto"]
    }
)

# Get session history
history = store.get_session_summaries(target="192.168.1.100", limit=10)
for session in history:
    print(f"{session['session_id']}: {session['summary']['findings_count']} findings")
```

## Threat Intelligence Report

Generate comprehensive threat intelligence reports:

```python
report = store.generate_threat_intel_report()

print(report)
# Output:
# # Threat Intelligence Report
# 
# **Generated**: 2024-01-28T10:00:00Z
# 
# ## High-Occurrence Patterns
# - **default_config**: MySQL instances with default empty root password (5 occurrences)
#   *Mitigation*: Set strong MySQL root password
# 
# ## Credential Patterns
# - **weak**: admin:admin123 (found on 3 targets)
#   *Targets*: 192.168.1.100, 192.168.1.101, 192.168.1.102
# 
# ## Technique Success Rates
# - **SQL Injection**: 85.7% success rate (6/7)
# - **Privilege Escalation**: 40.0% success rate (2/5)
```

## Learning Recommendations

Get AI-driven recommendations based on memory analysis:

```python
recommendations = store.get_learning_recommendations()

for rec in recommendations:
    print(f"- {rec}")

# Output:
# - High-success techniques to prioritize: SQL Injection, XSS Exploitation
# - Common patterns detected across targets: default_config, weak credentials
# - Consider testing these reused credentials: admin:admin123, root:toor
```

## Memory Persistence

Memory is automatically persisted to disk:

- **Base memories**: `memory/tenant_target_memories.json`
- **Threat patterns**: `memory/tenant_threat_patterns.json`
- **Technique records**: `memory/tenant_techniques.json`
- **Credential patterns**: `memory/tenant_credentials.json`
- **Target knowledge**: `memory/TARGET_KNOWLEDGE/target.json`
- **Session history**: `memory/SESSION_HISTORY/session.json`

## Daily Reflection (Self-Improvement Loop)

TazoSploit can distill short-term memory into long-term memory using a daily reflection pass.

Artifacts:
- **Daily logs**: `memory/DAILY/<tenant>_YYYY-MM-DD.md`
- **Long-term memory**: `memory/<tenant>_MEMORY.md`
- **Tool stats**: `memory/<tenant>_tool_stats.json`
- **Reflections**: `memory/REFLECTIONS/<tenant>_YYYY-MM-DD.md`
- **Learning gate**: `memory/BENCHMARKS/learning_gate.json`

Promotion is controlled by the learning gate. If `promote=false`, reflection will skip long-term promotion.

## API Reference

### EnhancedMemoryStore

```python
class EnhancedMemoryStore:
    def __init__(self, tenant_id: str = "default", target: str = None)
    def record_technique(self, technique_id: str, technique_name: str, success: bool)
    def get_technique_success_rate(self, technique_id: str) -> Optional[float]
    def get_best_techniques(self, limit: int = 5) -> List[TechniqueRecord]
    def add_threat_pattern(self, pattern_type: str, pattern: str, description: str, 
                          mitigation: str = None, target: str = None)
    def add_credential_pattern(self, pattern: str, category: str, target: str)
    def update_target_knowledge(self, key: str, value: Any)
    def get_target_knowledge(self, key: str = None) -> Any
    def save_session_summary(self, session_id: str, summary: Dict[str, Any])
    def get_session_summaries(self, target: str = None, limit: int = 10) -> List[Dict]
    def generate_threat_intel_report(self) -> str
    def get_learning_recommendations(self) -> List[str]
```

## Best Practices

1. **Record Both Successes and Failures**: Track all technique attempts for accurate success rates.
2. **Use Consistent Categories**: Follow the standard memory categories for consistency.
3. **Update Target Knowledge**: Store relevant target information as you discover it.
4. **Generate Regular Reports**: Create threat intelligence reports to identify patterns.
5. **Act on Recommendations**: Review and apply learning recommendations to improve efficiency.

## Examples

### Example 1: Learning from a Session

```python
store = EnhancedMemoryStore(tenant_id="default", target="target.com")

# Session completed with these results:
store.record_technique("T1190", "SQL Injection", success=True)
store.record_technique("T1190", "SQL Injection", success=True)
store.record_technique("T1068", "Privilege Escalation", success=False)

store.add_credential_pattern("admin:admin123", "weak", "target.com")
store.add_credential_pattern("admin:password", "weak", "target.com")

store.update_target_knowledge("database", "MySQL 8.0")
store.update_target_knowledge("web_server", "Apache 2.4")

# Get recommendations
recs = store.get_learning_recommendations()
for rec in recs:
    print(rec)
```

### Example 2: Analyzing Cross-Target Patterns

```python
# Initialize store with global target
global_store = EnhancedMemoryStore(tenant_id="default", target="global")

# Patterns are automatically tracked when you add them
# across different targets

# Get high-occurrence patterns
high_patterns = [p for p in global_store.threat_patterns if p.occurrences >= 3]

for pattern in high_patterns:
    print(f"{pattern.pattern_type}: {pattern.occurrences} occurrences")
    print(f"Targets: {', '.join(pattern.targets_affected)}")
```

### Example 3: Session Summaries

```python
# Save session summary
summary = {
    "objective": "Complete security assessment",
    "duration": 7200,  # 2 hours
    "findings": [
        {"severity": "critical", "title": "SQL Injection in login.php"},
        {"severity": "high", "title": "Default admin credentials"}
    ],
    "tools_used": ["nmap", "sqlmap", "nikto"],
    "success": True
}

store.save_session_summary(session_id, summary)

# Retrieve session history for this target
history = store.get_session_summaries(target="target.com")

# Analyze patterns across sessions
for session in history:
    print(f"{session['timestamp']}: {len(session['summary']['findings'])} findings")
```

## Troubleshooting

### Memory Not Persisting

**Problem**: Memories are lost after session ends.

**Solution**:
1. Check that `/pentest/memory` directory is writable
2. Ensure `MEMORY_DIR` environment variable is set correctly
3. Verify file permissions on memory files

### Patterns Not Detected

**Problem**: Repeated patterns aren't being tracked.

**Solution**:
1. Ensure you're calling `add_threat_pattern()` and `add_credential_pattern()`
2. Check that patterns use consistent identifiers
3. Verify the memory store is persisting data between calls

### Success Rates Inaccurate

**Problem**: Technique success rates don't match actual performance.

**Solution**:
1. Ensure you record both successes AND failures
2. Use consistent technique IDs across sessions
3. Check that `record_technique()` is called for every attempt

## Future Enhancements

- Machine learning for pattern prediction
- Automatic correlation of findings across targets
- Shared intelligence between tenants (with consent)
- Visualization of threat patterns
- Integration with external threat feeds
