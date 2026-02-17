"""kali-executor/open-interpreter/tool_usage_tracker.py

Sprint 1: Tool Usage Tracker + Comfort Zone Breaker.

Goal:
- Track which tools the agent actually uses per job.
- Detect "comfort zone" loops (e.g., nmap/curl overuse) and inject a diversity
  prompt before the next LLM call.

Design notes:
- Dependency-light (stdlib only).
- Redis is optional (best-effort).
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

logger = logging.getLogger(__name__)


IGNORED_TOOLS: Set[str] = {
    # shells / runtimes
    "bash",
    "sh",
    "zsh",
    "python",
    "python3",
    # common coreutils / builtins (noise)
    "cat",
    "echo",
    "grep",
    "egrep",
    "fgrep",
    "awk",
    "sed",
    "cut",
    "tr",
    "xargs",
    "head",
    "tail",
    "less",
    "more",
    "tee",
    "find",
    "stat",
    "ls",
    "pwd",
    "id",
    "whoami",
    "uname",
    "date",
    "sleep",
    "true",
    "false",
    "which",
    "whereis",
    "env",
    "export",
    "set",
    "unset",
    "printf",
    "mkdir",
    "touch",
    "chmod",
    "chown",
    "mv",
    "cp",
    "rm",
    "tar",
    "gzip",
    "gunzip",
    "7z",
    "unzip",
    "zip",
}


FINDING_TO_TOOLS: Dict[str, List[str]] = {
    "smb": ["crackmapexec", "netexec", "smbclient", "enum4linux", "impacket-psexec", "impacket-wmiexec"],
    "http": ["ffuf", "gobuster", "wfuzz", "nikto", "nuclei", "sqlmap"],
    "ssh": ["hydra", "medusa", "ssh-audit"],
    "rdp": ["hydra", "crowbar", "xfreerdp"],
    "mssql": ["crackmapexec", "impacket-mssqlclient", "sqsh"],
    "mysql": ["mysql", "hydra", "sqlmap"],
    "postgres": ["psql", "hydra"],
    "ftp": ["ftp", "hydra"],
    "winrm": ["evil-winrm", "crackmapexec", "netexec"],
    "ldap": ["ldapsearch", "crackmapexec", "bloodhound"],
    "cve": ["searchsploit", "msfconsole"],
    "sql": ["sqlmap"],
    "lfi": ["curl", "wget"],
    "rce": ["curl", "python3"],
    "creds": ["crackmapexec", "netexec", "evil-winrm", "impacket-psexec", "impacket-wmiexec"],
}


def _norm_tool(name: str) -> str:
    tool = str(name or "").strip().lower()
    if not tool:
        return ""
    if "/" in tool:
        tool = tool.split("/")[-1]
    return tool


def _iter_finding_texts(findings: Sequence[Any]) -> Iterable[str]:
    for f in findings or []:
        if f is None:
            continue
        if isinstance(f, str):
            yield f
            continue
        if isinstance(f, dict):
            vtype = str(f.get("type") or "")
            target = str(f.get("target") or "")
            details = str(f.get("details") or "")
            blob = " ".join([vtype, target, details]).strip()
            if blob:
                yield blob


class ToolUsageTracker:
    """Track tool usage and generate diversity prompts."""

    def __init__(
        self,
        *,
        redis_client: Any = None,
        job_id: Optional[str] = None,
        min_iterations: int = 20,
        min_unique_tools: int = 4,
        single_tool_hard_limit: int = 8,
        overuse_threshold: int = 6,
    ):
        self.redis = redis_client
        self.job_id = str(job_id or "").strip()
        self.local_usage: Counter[str] = Counter()
        self.redis_key = f"job:{self.job_id}:tool_usage" if self.job_id else ""

        self.min_iterations = int(min_iterations)
        self.min_unique_tools = int(min_unique_tools)
        self.single_tool_hard_limit = int(single_tool_hard_limit)
        self.overuse_threshold = int(overuse_threshold)

    def record(self, tool_name: str) -> None:
        tool = _norm_tool(tool_name)
        if not tool or tool in IGNORED_TOOLS:
            return

        self.local_usage[tool] += 1

        if not self.redis or not self.redis_key:
            return

        try:
            self.redis.hincrby(self.redis_key, tool, 1)
        except Exception as exc:
            logger.debug("tool_usage_redis_record_failed job_id=%s tool=%s err=%s", self.job_id, tool, exc)

    def get_usage(self) -> Dict[str, int]:
        if self.redis and self.redis_key:
            try:
                raw = self.redis.hgetall(self.redis_key) or {}
                out: Dict[str, int] = {}
                for k, v in raw.items():
                    try:
                        out[str(k)] = int(v)
                    except Exception:
                        continue
                if out:
                    return out
            except Exception:
                pass
        return dict(self.local_usage)

    def get_unique_count(self) -> int:
        return len(self.get_usage())

    def should_force_diversity(self, iteration: int) -> bool:
        usage = self.get_usage()
        unique = len(usage)
        if int(iteration or 0) >= self.min_iterations and unique < self.min_unique_tools:
            return True
        for _tool, count in usage.items():
            if int(count or 0) >= self.single_tool_hard_limit:
                return True
        return False

    def get_overused_tools(self, threshold: Optional[int] = None) -> List[str]:
        th = int(self.overuse_threshold if threshold is None else threshold)
        return [t for t, c in self.get_usage().items() if int(c or 0) >= th]

    def get_unused_relevant_tools(self, findings: Sequence[Any]) -> List[str]:
        used = set(self.get_usage().keys())
        recommended: Set[str] = set()

        for text in _iter_finding_texts(findings):
            lower = text.lower()
            for key, tools in FINDING_TO_TOOLS.items():
                if key in lower:
                    recommended.update(tools)

        # Minor heuristics: port-based hints
        for text in _iter_finding_texts(findings):
            lower = text.lower()
            if ":445" in lower or " port 445" in lower:
                recommended.update(FINDING_TO_TOOLS.get("smb", []))
            if any(p in lower for p in (":80", ":443", ":8080", ":8443")):
                recommended.update(FINDING_TO_TOOLS.get("http", []))
            if ":22" in lower or " port 22" in lower:
                recommended.update(FINDING_TO_TOOLS.get("ssh", []))

        out = sorted({t for t in recommended if t and t not in used})
        return out

    def build_diversity_prompt(self, *, iteration: int, phase: str, findings: Sequence[Any]) -> Optional[str]:
        if not self.should_force_diversity(iteration):
            return None

        usage = self.get_usage()
        if not usage:
            return None

        # Top-used tools for readability
        top = sorted(usage.items(), key=lambda kv: (-int(kv[1] or 0), kv[0]))[:10]
        overused = self.get_overused_tools()
        unused = self.get_unused_relevant_tools(findings)

        parts = [
            f"⚠️ TOOL DIVERSITY ALERT (iteration {int(iteration or 0)}, phase={str(phase or '').upper()}):",
            f"Tools used ({len(usage)} unique): " + ", ".join([f"{t}({c})" for t, c in top]),
        ]
        if overused:
            parts.append("OVERUSED (deprioritize): " + ", ".join(sorted(set(overused))[:10]))
        if unused:
            parts.append("RECOMMENDED (try these): " + ", ".join(unused[:8]))
            parts.append("NEXT command MUST use one of: " + ", ".join(unused[:3]))
        elif overused:
            parts.append("NEXT command MUST NOT repeat the most-overused tool.")

        parts.append("Use a different tool family or write a custom script if needed. Do not repeat failed commands verbatim.")
        return "\n".join(parts).strip()
