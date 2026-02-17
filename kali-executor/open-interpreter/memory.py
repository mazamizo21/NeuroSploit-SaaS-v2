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
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, asdict

MEMORY_DIR = os.environ.get("MEMORY_DIR", "/pentest/memory")
DAILY_DIR = os.path.join(MEMORY_DIR, "DAILY")
SESSION_HISTORY_DIR = os.path.join(MEMORY_DIR, "SESSION_HISTORY")
LONG_TERM_SUFFIX = "_MEMORY.md"
TOOL_STATS_SUFFIX = "_tool_stats.json"
MEMORY_PROMOTION_MODE = os.environ.get("MEMORY_PROMOTION_MODE", "reflect").lower()


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
        """Ensure memory directories exist"""
        os.makedirs(MEMORY_DIR, exist_ok=True)
        os.makedirs(DAILY_DIR, exist_ok=True)
        os.makedirs(SESSION_HISTORY_DIR, exist_ok=True)
    
    def _get_memory_file(self) -> str:
        """Get memory file path for this tenant/target"""
        # Sanitize target for filename
        safe_target = hashlib.md5(self.target.encode()).hexdigest()[:12]
        return os.path.join(MEMORY_DIR, f"{self.tenant_id}_{safe_target}_memories.json")

    def _get_daily_file(self, day: datetime) -> str:
        """Get daily memory file path for this tenant"""
        day_str = day.strftime("%Y-%m-%d")
        return os.path.join(DAILY_DIR, f"{self.tenant_id}_{day_str}.md")

    def _get_long_term_file(self) -> str:
        """Get long-term memory file path for this tenant"""
        return os.path.join(MEMORY_DIR, f"{self.tenant_id}{LONG_TERM_SUFFIX}")

    def _get_tool_stats_file(self) -> str:
        """Get tool stats file path for this tenant"""
        return os.path.join(MEMORY_DIR, f"{self.tenant_id}{TOOL_STATS_SUFFIX}")
    
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
        self._append_daily(memory)
        if MEMORY_PROMOTION_MODE == "immediate":
            self._maybe_promote_long_term(memory)
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

    def _append_daily(self, memory: Memory):
        """Append memory entry to daily short-term log"""
        try:
            day_file = self._get_daily_file(datetime.now(timezone.utc))
            line = f"- {memory.timestamp} [{memory.category}] {memory.content}\n"
            with open(day_file, 'a') as f:
                f.write(line)
        except Exception:
            # Short-term logging is best-effort
            pass

    def _maybe_promote_long_term(self, memory: Memory):
        """Promote high-value memories into long-term storage"""
        promote_categories = {
            "credential_found",
            "vulnerability_found",
            "access_gained",
            "technique_worked",
            "technique_failed",
            "package_name",
            "target_info",
        }
        if memory.importance != "high" and memory.category not in promote_categories:
            return

        try:
            long_term_file = self._get_long_term_file()
            entry = f"- [{memory.category}] {memory.content}"
            existing = ""
            if os.path.exists(long_term_file):
                with open(long_term_file, 'r') as f:
                    existing = f.read()
            else:
                with open(long_term_file, 'w') as f:
                    f.write("# Long-Term Memory\n\n")
            if entry.lower() in existing.lower():
                return
            with open(long_term_file, 'a') as f:
                f.write(entry + "\n")
        except Exception:
            # Long-term promotion is best-effort
            pass

    def record_session_summary(self, session_id: str, summary: Dict[str, Any]):
        """Persist a compact session summary for learning"""
        if not session_id:
            return
        try:
            data = {
                "session_id": session_id,
                "tenant_id": self.tenant_id,
                "target": self.target,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
            }
            session_file = os.path.join(
                SESSION_HISTORY_DIR,
                f"{self.tenant_id}_{session_id}.json"
            )
            with open(session_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass

    def promote_memories(self, memories: List[Memory]) -> int:
        """Promote a list of memories to long-term storage"""
        promoted = 0
        for mem in memories:
            before = ""
            long_term_file = self._get_long_term_file()
            try:
                if os.path.exists(long_term_file):
                    with open(long_term_file, 'r') as f:
                        before = f.read()
            except Exception:
                before = ""
            self._maybe_promote_long_term(mem)
            try:
                if os.path.exists(long_term_file):
                    with open(long_term_file, 'r') as f:
                        after = f.read()
                    if after != before:
                        promoted += 1
            except Exception:
                pass
        return promoted

    def update_tool_stats(self, executions: List[Dict[str, Any]]):
        """Update per-tool success stats from execution logs"""
        if not executions:
            return
        stats_file = self._get_tool_stats_file()
        stats = {"updated": None, "tools": {}}
        if os.path.exists(stats_file):
            try:
                with open(stats_file, 'r') as f:
                    stats = json.load(f)
            except Exception:
                stats = {"updated": None, "tools": {}}

        tools = stats.get("tools", {})
        now = datetime.now(timezone.utc).isoformat()
        for ex in executions:
            tool = (ex.get("tool_used") or "").strip()
            if not tool or tool.lower() in {"unknown", "none"}:
                continue
            # Normalize tool name to first token
            tool_key = tool.split()[0].strip().lower()
            if not tool_key:
                continue
            entry = tools.get(tool_key, {
                "success": 0,
                "failure": 0,
                "success_rate": 0.0,
                "last_used": None,
            })
            if ex.get("success"):
                entry["success"] += 1
            else:
                entry["failure"] += 1
            total = entry["success"] + entry["failure"]
            entry["success_rate"] = round((entry["success"] / total) * 100.0, 2) if total else 0.0
            entry["last_used"] = now
            tools[tool_key] = entry

        stats["tools"] = tools
        stats["updated"] = now
        try:
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2)
        except Exception:
            pass

    def get_tool_stats(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Get top tool stats by success rate"""
        stats_file = self._get_tool_stats_file()
        if not os.path.exists(stats_file):
            return []
        try:
            with open(stats_file, 'r') as f:
                data = json.load(f)
            tools = data.get("tools", {})
            items = [
                {"tool": k, **v}
                for k, v in tools.items()
                if isinstance(v, dict)
            ]
            items.sort(key=lambda x: (x.get("success_rate", 0.0), x.get("success", 0)), reverse=True)
            return items[:limit]
        except Exception:
            return []

    def format_tool_stats_for_prompt(self, limit: int = 5) -> str:
        """Format tool stats for prompt inclusion"""
        stats = self.get_tool_stats(limit=limit)
        if not stats:
            return ""
        lines = ["**TOOL PERFORMANCE (from prior runs):**"]
        for item in stats:
            lines.append(
                f"- {item['tool']}: {item.get('success_rate', 0.0)}% success "
                f"({item.get('success', 0)} success / {item.get('failure', 0)} fail)"
            )
        return "\n".join(lines)
    
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
    sections = []

    # Long-term memory (curated, slow-changing)
    long_term = _load_long_term_memory(store, max_lines=40, max_chars=800)
    if long_term:
        sections.append("**LONG-TERM MEMORY:**\n" + long_term)

    # Short-term memory (recent daily log)
    short_term = _load_short_term_memory(store, days=2, max_lines=40, max_chars=800)
    if short_term:
        sections.append("**SHORT-TERM MEMORY (recent):**\n" + short_term)

    # Tool performance stats
    tool_stats = store.format_tool_stats_for_prompt(limit=5)
    if tool_stats:
        sections.append(tool_stats)

    # Structured memories (keyword-based)
    relevant = store.get_relevant(keywords=context_keywords, limit=10)
    if relevant:
        sections.append(store.format_for_prompt(relevant, max_chars=1000))

    return "\n\n".join(sections)


def _load_short_term_memory(store: MemoryStore, days: int = 2, max_lines: int = 40, max_chars: int = 800) -> str:
    """Load recent daily memory entries"""
    lines: List[str] = []
    today = datetime.now(timezone.utc).date()
    for offset in range(days):
        day = datetime.combine(today - timedelta(days=offset), datetime.min.time(), tzinfo=timezone.utc)
        path = store._get_daily_file(day)
        if not os.path.exists(path):
            continue
        try:
            with open(path, 'r') as f:
                day_lines = [ln.strip() for ln in f.readlines() if ln.strip()]
            if day_lines:
                lines.extend(day_lines[-max_lines:])
        except Exception:
            continue

    # Truncate by chars
    trimmed = []
    count = 0
    for ln in lines:
        if count + len(ln) > max_chars:
            break
        trimmed.append(ln)
        count += len(ln)
    return "\n".join(trimmed)


def _load_long_term_memory(store: MemoryStore, max_lines: int = 40, max_chars: int = 800) -> str:
    """Load curated long-term memory"""
    path = store._get_long_term_file()
    if not os.path.exists(path):
        return ""
    try:
        with open(path, 'r') as f:
            lines = [ln.strip() for ln in f.readlines() if ln.strip()]
    except Exception:
        return ""

    # Keep last lines and trim to chars
    lines = lines[-max_lines:]
    trimmed = []
    count = 0
    for ln in lines:
        if count + len(ln) > max_chars:
            break
        trimmed.append(ln)
        count += len(ln)
    return "\n".join(trimmed)


# AI instruction for memory management
MEMORY_INSTRUCTION = """
**MEMORY MANAGEMENT:**
You can save important learnings that will persist across sessions.
Use this format in your response when you learn something valuable:

[REMEMBER: category] content

Categories:
- package_name: "mysql client package is mariadb-client"
- tool_installed: "installed hydra successfully"
- credential_found: "admin:password works for target login"
- vulnerability_found: "SQL injection in login.php"
- technique_worked: "hydra http-post-form syntax: ..."
- technique_failed: "sqlmap didn't work on this target"
- target_info: "target running Apache 2.4 with PHP 8.1"

Only save VALUABLE information, not every step.
"""
