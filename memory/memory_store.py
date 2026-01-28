#!/usr/bin/env python3
"""
TazoSploit Enhanced Memory Store
Extended memory system with threat intelligence, patterns, and learning.

Enhancements over memory.py:
- Threat intelligence tracking
- Success rate tracking for techniques/tools
- Pattern recognition for credential reuse
- Target-specific knowledge base
- Session history with summaries
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict
from collections import defaultdict

MEMORY_DIR = os.environ.get("MEMORY_DIR", "/pentest/memory")
THREAT_INTEL_FILE = os.path.join(MEMORY_DIR, "THREAT_INTEL.md")
TARGET_KNOWLEDGE_DIR = os.path.join(MEMORY_DIR, "TARGET_KNOWLEDGE")
SESSION_HISTORY_DIR = os.path.join(MEMORY_DIR, "SESSION_HISTORY")


@dataclass
class ThreatPattern:
    """Represents a detected threat pattern"""
    id: str
    pattern_type: str  # credential_reuse, common_vulnerability, default_config, etc.
    pattern: str
    occurrences: int
    last_seen: str
    targets_affected: List[str]
    description: str
    mitigation: Optional[str] = None


@dataclass
class TechniqueRecord:
    """Tracks technique success/failure rates"""
    technique_id: str  # MITRE technique ID or custom ID
    technique_name: str
    success_count: int = 0
    failure_count: int = 0
    last_used: str = None
    success_rate: float = 0.0
    
    def update_success(self):
        self.success_count += 1
        self.last_used = datetime.now(timezone.utc).isoformat()
        self._calculate_rate()
    
    def update_failure(self):
        self.failure_count += 1
        self.last_used = datetime.now(timezone.utc).isoformat()
        self._calculate_rate()
    
    def _calculate_rate(self):
        total = self.success_count + self.failure_count
        self.success_rate = (self.success_count / total * 100) if total > 0 else 0.0


@dataclass
class CredentialPattern:
    """Tracks credential patterns and reuse"""
    pattern: str  # username:password hash, default creds, etc.
    category: str  # default, weak, reused, discovered
    count: int = 0
    targets: List[str] = None
    last_seen: str = None
    
    def __post_init__(self):
        if self.targets is None:
            self.targets = []


class EnhancedMemoryStore:
    """
    Enhanced memory store with threat intelligence and pattern tracking.
    Extends the base memory functionality with learning capabilities.
    """
    
    def __init__(self, tenant_id: str = "default", target: str = None):
        self.tenant_id = tenant_id
        self.target = target or "global"
        self.memory_file = self._get_memory_file()
        self.threat_patterns: List[ThreatPattern] = []
        self.technique_records: Dict[str, TechniqueRecord] = {}
        self.credential_patterns: List[CredentialPattern] = []
        self.target_knowledge: Dict[str, Any] = {}
        
        self._ensure_dirs()
        self._load()
    
    def _ensure_dirs(self):
        """Ensure all required directories exist"""
        for dir_path in [MEMORY_DIR, TARGET_KNOWLEDGE_DIR, SESSION_HISTORY_DIR]:
            os.makedirs(dir_path, exist_ok=True)
    
    def _get_memory_file(self) -> str:
        """Get memory file path"""
        safe_target = hashlib.md5(self.target.encode()).hexdigest()[:12]
        return os.path.join(MEMORY_DIR, f"{self.tenant_id}_{safe_target}_memories.json")
    
    def _load(self):
        """Load all memory data"""
        # Load base memories
        try:
            with open(self.memory_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            data = {}
        
        # Load threat patterns
        threat_file = os.path.join(MEMORY_DIR, f"{self.tenant_id}_threat_patterns.json")
        try:
            with open(threat_file, 'r') as f:
                pattern_data = json.load(f)
                self.threat_patterns = [ThreatPattern(**p) for p in pattern_data.get("patterns", [])]
        except (json.JSONDecodeError, FileNotFoundError):
            self.threat_patterns = []
        
        # Load technique records
        technique_file = os.path.join(MEMORY_DIR, f"{self.tenant_id}_techniques.json")
        try:
            with open(technique_file, 'r') as f:
                tech_data = json.load(f)
                self.technique_records = {
                    tid: TechniqueRecord(**t) 
                    for tid, t in tech_data.get("techniques", {}).items()
                }
        except (json.JSONDecodeError, FileNotFoundError):
            self.technique_records = {}
        
        # Load credential patterns
        cred_file = os.path.join(MEMORY_DIR, f"{self.tenant_id}_credentials.json")
        try:
            with open(cred_file, 'r') as f:
                cred_data = json.load(f)
                self.credential_patterns = [CredentialPattern(**c) for c in cred_data.get("patterns", [])]
        except (json.JSONDecodeError, FileNotFoundError):
            self.credential_patterns = []
        
        # Load target knowledge
        target_file = os.path.join(TARGET_KNOWLEDGE_DIR, f"{self.target}.json")
        try:
            with open(target_file, 'r') as f:
                self.target_knowledge = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            self.target_knowledge = {}
    
    def _save(self):
        """Save all memory data"""
        # Save threat patterns
        threat_file = os.path.join(MEMORY_DIR, f"{self.tenant_id}_threat_patterns.json")
        threat_data = {
            "tenant_id": self.tenant_id,
            "updated": datetime.now(timezone.utc).isoformat(),
            "patterns": [asdict(p) for p in self.threat_patterns]
        }
        with open(threat_file, 'w') as f:
            json.dump(threat_data, f, indent=2)
        
        # Save technique records
        technique_file = os.path.join(MEMORY_DIR, f"{self.tenant_id}_techniques.json")
        technique_data = {
            "tenant_id": self.tenant_id,
            "updated": datetime.now(timezone.utc).isoformat(),
            "techniques": {tid: asdict(t) for tid, t in self.technique_records.items()}
        }
        with open(technique_file, 'w') as f:
            json.dump(technique_data, f, indent=2)
        
        # Save credential patterns
        cred_file = os.path.join(MEMORY_DIR, f"{self.tenant_id}_credentials.json")
        cred_data = {
            "tenant_id": self.tenant_id,
            "updated": datetime.now(timezone.utc).isoformat(),
            "patterns": [asdict(c) for c in self.credential_patterns]
        }
        with open(cred_file, 'w') as f:
            json.dump(cred_data, f, indent=2)
        
        # Save target knowledge
        target_file = os.path.join(TARGET_KNOWLEDGE_DIR, f"{self.target}.json")
        with open(target_file, 'w') as f:
            self.target_knowledge["updated"] = datetime.now(timezone.utc).isoformat()
            json.dump(self.target_knowledge, f, indent=2)
    
    def record_technique(self, technique_id: str, technique_name: str, success: bool):
        """Record technique success or failure for learning"""
        if technique_id not in self.technique_records:
            self.technique_records[technique_id] = TechniqueRecord(
                technique_id=technique_id,
                technique_name=technique_name
            )
        
        if success:
            self.technique_records[technique_id].update_success()
        else:
            self.technique_records[technique_id].update_failure()
        
        self._save()
    
    def get_technique_success_rate(self, technique_id: str) -> Optional[float]:
        """Get success rate for a technique"""
        record = self.technique_records.get(technique_id)
        return record.success_rate if record else None
    
    def get_best_techniques(self, limit: int = 5) -> List[TechniqueRecord]:
        """Get top-performing techniques by success rate"""
        sorted_records = sorted(
            self.technique_records.values(),
            key=lambda r: (r.success_rate, r.success_count),
            reverse=True
        )
        # Filter to techniques with at least one success and multiple uses
        qualified = [r for r in sorted_records if r.success_count > 0 and (r.success_count + r.failure_count) > 1]
        return qualified[:limit]
    
    def add_threat_pattern(self, pattern_type: str, pattern: str, description: str, 
                          mitigation: str = None, target: str = None):
        """Add or update a threat pattern"""
        pattern_id = hashlib.md5(f"{pattern_type}:{pattern}".encode()).hexdigest()[:16]
        
        existing = next((p for p in self.threat_patterns if p.id == pattern_id), None)
        
        if existing:
            existing.occurrences += 1
            existing.last_seen = datetime.now(timezone.utc).isoformat()
            if target and target not in existing.targets_affected:
                existing.targets_affected.append(target)
        else:
            new_pattern = ThreatPattern(
                id=pattern_id,
                pattern_type=pattern_type,
                pattern=pattern,
                occurrences=1,
                last_seen=datetime.now(timezone.utc).isoformat(),
                targets_affected=[target] if target else [],
                description=description,
                mitigation=mitigation
            )
            self.threat_patterns.append(new_pattern)
        
        self._save()
    
    def add_credential_pattern(self, pattern: str, category: str, target: str):
        """Add or update a credential pattern"""
        existing = next((c for c in self.credential_patterns if c.pattern == pattern), None)
        
        if existing:
            existing.count += 1
            existing.last_seen = datetime.now(timezone.utc).isoformat()
            if target not in existing.targets:
                existing.targets.append(target)
        else:
            new_pattern = CredentialPattern(
                pattern=pattern,
                category=category,
                count=1,
                targets=[target],
                last_seen=datetime.now(timezone.utc).isoformat()
            )
            self.credential_patterns.append(new_pattern)
        
        self._save()
    
    def update_target_knowledge(self, key: str, value: Any):
        """Update target-specific knowledge"""
        self.target_knowledge[key] = {
            "value": value,
            "updated": datetime.now(timezone.utc).isoformat()
        }
        self._save()
    
    def get_target_knowledge(self, key: str = None) -> Any:
        """Get target knowledge"""
        if key:
            entry = self.target_knowledge.get(key, {})
            return entry.get("value")
        return self.target_knowledge
    
    def save_session_summary(self, session_id: str, summary: Dict[str, Any]):
        """Save session summary to session history"""
        session_file = os.path.join(SESSION_HISTORY_DIR, f"{session_id}.json")
        
        summary_data = {
            "session_id": session_id,
            "tenant_id": self.tenant_id,
            "target": self.target,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": summary
        }
        
        with open(session_file, 'w') as f:
            json.dump(summary_data, f, indent=2)
    
    def get_session_summaries(self, target: str = None, limit: int = 10) -> List[Dict]:
        """Get session summaries, optionally filtered by target"""
        summaries = []
        
        try:
            for filename in os.listdir(SESSION_HISTORY_DIR):
                if not filename.endswith('.json'):
                    continue
                
                with open(os.path.join(SESSION_HISTORY_DIR, filename), 'r') as f:
                    data = json.load(f)
                
                if target and data.get("target") != target:
                    continue
                
                summaries.append(data)
        except FileNotFoundError:
            pass
        
        # Sort by timestamp descending
        summaries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return summaries[:limit]
    
    def generate_threat_intel_report(self) -> str:
        """Generate a threat intelligence report"""
        lines = ["# Threat Intelligence Report\n"]
        lines.append(f"**Generated**: {datetime.now(timezone.utc).isoformat()}\n")
        
        lines.append("## High-Occurrence Patterns")
        sorted_patterns = sorted(self.threat_patterns, key=lambda p: p.occurrences, reverse=True)
        for pattern in sorted_patterns[:10]:
            lines.append(f"- **{pattern.pattern_type}**: {pattern.description} ({pattern.occurrences} occurrences)")
            if pattern.mitigation:
                lines.append(f"  *Mitigation*: {pattern.mitigation}")
        
        lines.append("\n## Credential Patterns")
        for cred in sorted(self.credential_patterns, key=lambda c: c.count, reverse=True)[:10]:
            lines.append(f"- **{cred.category}**: {cred.pattern} (found on {cred.count} targets)")
            if cred.targets:
                lines.append(f"  *Targets*: {', '.join(cred.targets[:5])}")
        
        lines.append("\n## Technique Success Rates")
        best_techniques = self.get_best_techniques()
        for tech in best_techniques:
            lines.append(f"- **{tech.technique_name}**: {tech.success_rate:.1f}% success rate "
                        f"({tech.success_count}/{tech.success_count + tech.failure_count})")
        
        return "\n".join(lines)
    
    def get_learning_recommendations(self) -> List[str]:
        """Get learning recommendations based on memory analysis"""
        recommendations = []
        
        # Recommend high-success techniques
        best_techniques = self.get_best_techniques(limit=3)
        if best_techniques:
            recommendations.append(
                f"High-success techniques to prioritize: "
                f"{', '.join(t.technique_name for t in best_techniques)}"
            )
        
        # Warn about frequent patterns
        frequent_patterns = [p for p in self.threat_patterns if p.occurrences >= 3]
        if frequent_patterns:
            recommendations.append(
                f"Common patterns detected across targets: "
                f"{', '.join(p.pattern_type for p in frequent_patterns)}"
            )
        
        # Suggest credential testing
        reused_creds = [c for c in self.credential_patterns if c.count > 1]
        if reused_creds:
            recommendations.append(
                f"Consider testing these reused credentials: "
                f"{', '.join(c.pattern for c in reused_creds[:3])}"
            )
        
        return recommendations


# Initialize threat intelligence markdown
def initialize_threat_intel():
    """Initialize THREAT_INTEL.md if it doesn't exist"""
    if not os.path.exists(THREAT_INTEL_FILE):
        content = """# Threat Intelligence

This file contains threat intelligence patterns and analysis for pentesting engagements.

## Pattern Categories

### Credential Patterns
- **Default Credentials**: Default username/password combinations for common services
- **Weak Passwords**: Commonly used weak passwords discovered
- **Reused Credentials**: Credentials found on multiple systems

### Common Vulnerabilities
- **Unpatched Services**: Services with known CVEs
- **Misconfigurations**: Security misconfigurations across targets
- **Default Configurations**: Services running with default settings

### Technique Patterns
- **Successful Techniques**: Attack techniques with high success rates
- **Failed Techniques**: Techniques that consistently fail
- **Tool Effectiveness**: Performance of specific tools

## Analysis Guidelines

1. Track patterns across multiple targets
2. Calculate success rates for techniques
3. Identify common misconfigurations
4. Monitor credential reuse patterns
5. Update threat intelligence after each engagement

## Updates

Updated after each pentest engagement with:
- New patterns discovered
- Technique performance metrics
- Credential analysis
- Recommendations for future engagements
"""
        with open(THREAT_INTEL_FILE, 'w') as f:
            f.write(content)
        return True
    return False


if __name__ == "__main__":
    # Test enhanced memory store
    initialize_threat_intel()
    store = EnhancedMemoryStore(tenant_id="test", target="test-target")
    
    # Record some test data
    store.record_technique("T1190", "Exploit Public-Facing App", True)
    store.record_technique("T1190", "Exploit Public-Facing App", True)
    store.record_technique("T1190", "Exploit Public-Facing App", False)
    store.record_technique("T1068", "Privilege Escalation", False)
    
    store.add_credential_pattern("admin:admin123", "weak", "test-target")
    store.add_credential_pattern("admin:admin123", "weak", "other-target")
    
    store.add_threat_pattern(
        "default_config",
        "MySQL with empty root password",
        "MySQL instances with default empty root password",
        "Set strong MySQL root password",
        "test-target"
    )
    
    print(store.generate_threat_intel_report())
    print("\n\nRecommendations:")
    for rec in store.get_learning_recommendations():
        print(f"- {rec}")
