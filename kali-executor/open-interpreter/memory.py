#!/usr/bin/env python3
"""
TazoSploit Persistent Memory System
Lightweight memory storage for AI agent to remember important learnings across sessions.

Design principles:
1. AI decides what to remember (not every step)
2. Memories are scoped per tenant/target
3. Stored as JSON for simplicity (no external DB needed)
4. Retrieves relevant memories based on context
5. Prevents duplicate/redundant memories
"""

import os
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict

MEMORY_DIR = os.environ.get("MEMORY_DIR", "/pentest/memory")


@dataclass
class Memory:
    """A single memory entry"""
    id: str
    timestamp: str
    category: str  # tool_learned, vulnerability_found, credential_obtained, technique_worked, technique_failed
    content: str
    context: Dict[str, Any]  # target, tool, etc.
    importance: str  # high, medium, low
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Memory':
        return cls(**data)


class MemoryStore:
    """
    Persistent memory storage for AI agent.
    Memories are stored per-tenant and per-target for multi-tenant .
    """
    
    def __init__(self, tenant_id: str = "default", target: str = None):
        self.tenant_id = tenant_id
        self.target = target or "global"
        self.memory_file = self._get_memory_file()
        self.memories: List[Memory] = []
        self._ensure_dir()
        self._load()
    
    def _ensure_dir(self):
        """Ensure memory directory exists"""
        os.makedirs(MEMORY_DIR, exist_ok=True)
    
    def _get_memory_file(self) -> str:
        """Get memory file path for this tenant/target"""
        # Sanitize target for filename
        safe_target = hashlib.md5(self.target.encode()).hexdigest()[:12]
        return os.path.join(MEMORY_DIR, f"{self.tenant_id}_{safe_target}_memories.json")
    
    def _load(self):
        """Load memories from file"""
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, 'r') as f:
                    data = json.load(f)
                    self.memories = [Memory.from_dict(m) for m in data.get("memories", [])]
            except (json.JSONDecodeError, KeyError):
                self.memories = []
    
    def _save(self):
        """Save memories to file"""
        data = {
            "tenant_id": self.tenant_id,
            "target": self.target,
            "updated": datetime.now(timezone.utc).isoformat(),
            "memories": [m.to_dict() for m in self.memories]
        }
        with open(self.memory_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _generate_id(self, content: str) -> str:
        """Generate unique ID for memory"""
        return hashlib.md5(f"{content}{datetime.now().isoformat()}".encode()).hexdigest()[:16]
    
    def _is_duplicate(self, content: str, category: str) -> bool:
        """Check if similar memory already exists"""
        content_lower = content.lower()
        for mem in self.memories:
            if mem.category == category:
                # Check for similar content (simple similarity)
                if content_lower in mem.content.lower() or mem.content.lower() in content_lower:
                    return True
        return False
    
    def add(self, category: str, content: str, context: Dict = None, importance: str = "medium") -> Optional[Memory]:
        """
        Add a new memory if it's not a duplicate.
        Returns the memory if added, None if duplicate.
        """
        if self._is_duplicate(content, category):
            return None
        
        memory = Memory(
            id=self._generate_id(content),
            timestamp=datetime.now(timezone.utc).isoformat(),
            category=category,
            content=content,
            context=context or {},
            importance=importance
        )
        
        self.memories.append(memory)
        self._save()
        return memory
    
    def get_by_category(self, category: str) -> List[Memory]:
        """Get all memories of a specific category"""
        return [m for m in self.memories if m.category == category]
    
    def get_relevant(self, keywords: List[str] = None, limit: int = 10) -> List[Memory]:
        """Get relevant memories based on keywords"""
        if not keywords:
            # Return most recent high-importance memories
            sorted_mems = sorted(
                self.memories, 
                key=lambda m: (m.importance == "high", m.timestamp),
                reverse=True
            )
            return sorted_mems[:limit]
        
        # Score memories by keyword matches
        scored = []
        for mem in self.memories:
            score = 0
            content_lower = mem.content.lower()
            for kw in keywords:
                if kw.lower() in content_lower:
                    score += 1
            if score > 0:
                scored.append((score, mem))
        
        # Sort by score, then importance
        scored.sort(key=lambda x: (x[0], x[1].importance == "high"), reverse=True)
        return [m for _, m in scored[:limit]]
    
    def get_all(self) -> List[Memory]:
        """Get all memories"""
        return self.memories
    
    def clear(self):
        """Clear all memories"""
        self.memories = []
        self._save()
    
    def format_for_prompt(self, memories: List[Memory] = None, max_chars: int = 2000) -> str:
        """Format memories for inclusion in AI prompt"""
        if memories is None:
            memories = self.get_relevant(limit=10)
        
        if not memories:
            return ""
        
        lines = ["**REMEMBERED FROM PREVIOUS SESSIONS:**"]
        char_count = len(lines[0])
        
        for mem in memories:
            line = f"- [{mem.category}] {mem.content}"
            if char_count + len(line) > max_chars:
                break
            lines.append(line)
            char_count += len(line)
        
        return "\n".join(lines)


# Memory categories for pentesting
MEMORY_CATEGORIES = {
    "tool_installed": "Tool was installed successfully",
    "tool_failed": "Tool failed or doesn't work",
    "package_name": "Correct package name for a tool",
    "credential_found": "Credentials discovered",
    "vulnerability_found": "Vulnerability identified",
    "technique_worked": "Attack technique that worked",
    "technique_failed": "Attack technique that failed",
    "target_info": "Information about the target",
    "access_gained": "Access level achieved",
}


def create_memory_prompt_section(store: MemoryStore, context_keywords: List[str] = None) -> str:
    """
    Create a memory section for the AI prompt.
    Called at the start of each iteration to provide context.
    """
    relevant = store.get_relevant(keywords=context_keywords, limit=10)
    if not relevant:
        return ""
    
    return store.format_for_prompt(relevant)


# AI instruction for memory management
MEMORY_INSTRUCTION = """
**MEMORY MANAGEMENT:**
You can save important learnings that will persist across sessions.
Use this format in your response when you learn something valuable:

[REMEMBER: category] content

Categories:
- package_name: "mysql client package is mariadb-client"
- tool_installed: "installed hydra successfully"
- credential_found: "admin:password works for DVWA"
- vulnerability_found: "SQL injection in login.php"
- technique_worked: "hydra http-post-form syntax: ..."
- technique_failed: "sqlmap didn't work on this target"
- target_info: "DVWA v1.10 running on Apache"

Only save VALUABLE information, not every step.
"""
