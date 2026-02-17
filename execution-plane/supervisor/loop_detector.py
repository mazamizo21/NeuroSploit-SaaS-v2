#!/usr/bin/env python3
"""
TazoSploit Supervisor – Loop Detection Engine

Detects when the pentest agent is stuck in repetitive patterns:
  1. Fuzzy command repetition (same tool, slight arg variations)
  2. Noop command sequences (sleep, echo, :, python3 heredocs)
  3. Tool-specific loop patterns (sqlmap URL variations, nmap port variations)
  4. Stagnation patterns (cycling through same commands without progress)

Each detection returns a structured LoopAlert with specific intervention directives.
"""

from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Deque, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Configuration defaults (can be overridden by caller)
# ---------------------------------------------------------------------------

DEFAULT_FUZZY_THRESHOLD = 0.72       # SequenceMatcher ratio to consider "same"
DEFAULT_EXACT_REPEAT_LIMIT = 3       # Exact same command N times → alert
DEFAULT_FUZZY_REPEAT_LIMIT = 4       # Fuzzy-similar command N times → alert
DEFAULT_TOOL_REPEAT_LIMIT = 5        # Same tool N times in window → alert
DEFAULT_HISTORY_WINDOW = 30          # Commands to keep in sliding window
DEFAULT_NOOP_BURST_LIMIT = 3         # Consecutive noops → alert
DEFAULT_CYCLE_WINDOW = 15            # Window for cycle detection
DEFAULT_CYCLE_MIN_UNIQUE = 3         # Min unique commands to form a cycle
DEFAULT_CYCLE_REPEAT_LIMIT = 2       # Full cycles before alert

# ---------------------------------------------------------------------------
# Noop patterns
# ---------------------------------------------------------------------------

NOOP_EXACT = frozenset([
    ":", "true", "false", "sleep", "wait", "date", "id", "pwd",
    "ls", "ls -la", "ls -la /pentest", "whoami", "hostname",
])

NOOP_PREFIXES = (
    "sleep ", "wait ", "echo ", "printf ",
    "cat /pentest/output/", "cat /tmp/",
)

# echo patterns that indicate stalling
STALL_ECHO_WORDS = frozenset([
    "ready", "waiting", "standing by", "idle", "awaiting",
    "done", "complete", "status", "proceeding", "continuing",
    "checking", "preparing", "working", "ok",
])

# Python heredoc that does nothing useful
PYTHON_HEREDOC_RE = re.compile(
    r"python3?\s+(?:-c\s+)?['\"]?(?:<<|.*heredoc|import\s+(?:os|sys|time))",
    re.IGNORECASE,
)
# Commands that just print/import without action
PYTHON_NOOP_PATTERNS = [
    re.compile(r"python3?\s+-c\s+['\"]?(?:pass|import\s+\w+|print)", re.IGNORECASE),
    re.compile(r"python3?\s+<<", re.IGNORECASE),  # heredoc  
]

# ---------------------------------------------------------------------------
# Tool extraction
# ---------------------------------------------------------------------------

# Known pentest tools (used for tool-based grouping)
KNOWN_TOOLS = frozenset([
    "nmap", "masscan", "gobuster", "dirb", "dirsearch", "ffuf", "nikto",
    "whatweb", "nuclei", "amass", "subfinder", "curl", "wget",
    "sqlmap", "commix", "hydra", "medusa", "john", "hashcat",
    "msfconsole", "searchsploit", "crackmapexec", "cme",
    "wfuzz", "feroxbuster", "smbclient", "enum4linux", "rpcclient",
    "wpscan", "joomscan", "droopescan", "dnsrecon", "dnsenum",
    "nc", "ncat", "netcat", "socat", "telnet",
    "dig", "nslookup", "host", "whois",
    "patator", "responder", "impacket", "secretsdump",
    "pg_dump", "mysqldump", "redis-cli", "mongo",
    "python3", "python", "perl", "ruby", "bash", "sh",
])

_TOOL_RE = re.compile(r"^(?:sudo\s+)?(\S+)")


def _extract_tool(cmd: str) -> str:
    """Extract the primary tool/binary name from a command string."""
    cmd = cmd.strip().lower()
    # Handle pipes – take first command
    if "|" in cmd:
        cmd = cmd.split("|")[0].strip()
    # Handle command chains
    if "&&" in cmd:
        cmd = cmd.split("&&")[0].strip()
    if ";" in cmd:
        cmd = cmd.split(";")[0].strip()
    m = _TOOL_RE.match(cmd)
    if not m:
        return "unknown"
    tool = m.group(1).rstrip("/")
    # Normalize paths: /usr/bin/nmap → nmap
    if "/" in tool:
        tool = tool.rsplit("/", 1)[-1]
    return tool


def _extract_target_from_cmd(cmd: str) -> Optional[str]:
    """Try to extract an IP or hostname target from a command."""
    # Match IP addresses
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)', cmd)
    if ip_match:
        return ip_match.group(1)
    # Match URLs
    url_match = re.search(r'https?://([^\s/:]+)', cmd)
    if url_match:
        return url_match.group(1)
    return None


def _normalize(cmd: str) -> str:
    """Whitespace-normalize and lowercase."""
    return " ".join(cmd.strip().split()).lower()


def _fuzzy_match(a: str, b: str, threshold: float = DEFAULT_FUZZY_THRESHOLD) -> bool:
    """Check if two commands are fuzzy-similar above threshold."""
    if a == b:
        return True
    if not a or not b:
        return False
    return SequenceMatcher(None, a, b).ratio() >= threshold


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class LoopAlert:
    """Structured alert returned when a loop pattern is detected."""
    alert_type: str          # fuzzy_repeat | exact_repeat | noop_burst | tool_spam | cycle
    severity: str            # low | medium | high | critical
    message: str             # Human-readable description
    directive: str           # What to tell the agent: "STOP doing X, try Y instead"
    commands_involved: List[str]   # The offending commands
    tool: Optional[str] = None
    count: int = 0
    confidence: float = 0.8

    def to_dict(self) -> Dict:
        return {
            "alert_type": self.alert_type,
            "severity": self.severity,
            "message": self.message,
            "directive": self.directive,
            "commands_involved": self.commands_involved,
            "tool": self.tool,
            "count": self.count,
            "confidence": self.confidence,
        }


@dataclass
class CommandRecord:
    """A single command with metadata."""
    raw: str
    normalized: str
    tool: str
    target: Optional[str]
    timestamp: float
    iteration: int = 0


class LoopDetector:
    """
    Stateful per-job loop detector.

    Usage:
        detector = LoopDetector()
        alerts = detector.ingest(cmd_string, iteration=42)
        for alert in alerts:
            # handle alert
    """

    def __init__(
        self,
        fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD,
        exact_repeat_limit: int = DEFAULT_EXACT_REPEAT_LIMIT,
        fuzzy_repeat_limit: int = DEFAULT_FUZZY_REPEAT_LIMIT,
        tool_repeat_limit: int = DEFAULT_TOOL_REPEAT_LIMIT,
        history_window: int = DEFAULT_HISTORY_WINDOW,
        noop_burst_limit: int = DEFAULT_NOOP_BURST_LIMIT,
        cycle_window: int = DEFAULT_CYCLE_WINDOW,
        cycle_min_unique: int = DEFAULT_CYCLE_MIN_UNIQUE,
        cycle_repeat_limit: int = DEFAULT_CYCLE_REPEAT_LIMIT,
    ) -> None:
        self.fuzzy_threshold = fuzzy_threshold
        self.exact_repeat_limit = exact_repeat_limit
        self.fuzzy_repeat_limit = fuzzy_repeat_limit
        self.tool_repeat_limit = tool_repeat_limit
        self.history_window = history_window
        self.noop_burst_limit = noop_burst_limit
        self.cycle_window = cycle_window
        self.cycle_min_unique = cycle_min_unique
        self.cycle_repeat_limit = cycle_repeat_limit

        self._history: Deque[CommandRecord] = deque(maxlen=history_window)
        self._consecutive_noops: int = 0
        self._noop_total: int = 0

        # Cooldowns: alert_type → last_alert_time
        self._cooldowns: Dict[str, float] = {}
        self.cooldown_seconds: float = 90.0  # Minimum seconds between same alert type

        # Suppression: track which specific patterns we've already alerted on
        # to avoid spamming the same alert repeatedly. Key = (alert_type, tool)
        self._suppressed: Dict[Tuple[str, str], int] = defaultdict(int)
        self.suppress_after: int = 3  # After N alerts of same type+tool, increase cooldown

    def ingest(self, cmd: str, iteration: int = 0) -> List[LoopAlert]:
        """
        Process a new command. Returns list of LoopAlerts (may be empty).
        """
        now = time.time()
        normalized = _normalize(cmd)
        tool = _extract_tool(normalized)
        target = _extract_target_from_cmd(cmd)

        record = CommandRecord(
            raw=cmd,
            normalized=normalized,
            tool=tool,
            target=target,
            timestamp=now,
            iteration=iteration,
        )

        alerts: List[LoopAlert] = []

        # Check noop first
        if self._is_noop(normalized):
            self._consecutive_noops += 1
            self._noop_total += 1
            noop_alert = self._check_noop_burst(record)
            if noop_alert:
                alerts.append(noop_alert)
        else:
            self._consecutive_noops = 0

        # Add to history
        self._history.append(record)

        # Skip further checks for noops (already handled)
        if self._consecutive_noops > 0 and alerts:
            return self._filter_cooled_down(alerts, now)

        # Check exact repetition
        exact = self._check_exact_repeat(record)
        if exact:
            alerts.append(exact)

        # Check fuzzy repetition
        fuzzy = self._check_fuzzy_repeat(record)
        if fuzzy:
            alerts.append(fuzzy)

        # Check tool spam
        tool_alert = self._check_tool_spam(record)
        if tool_alert:
            alerts.append(tool_alert)

        # Check command cycling
        cycle = self._check_cycle()
        if cycle:
            alerts.append(cycle)

        return self._filter_cooled_down(alerts, now)

    # -------------------------------------------------------------------
    # Noop detection
    # -------------------------------------------------------------------

    def _is_noop(self, cmd: str) -> bool:
        """Check if a command is a no-op / stalling command."""
        if not cmd:
            return True

        # Exact match
        if cmd in NOOP_EXACT:
            return True

        # Prefix match
        for prefix in NOOP_PREFIXES:
            if cmd.startswith(prefix):
                # echo with stall words
                if cmd.startswith("echo"):
                    remainder = cmd[4:].strip().strip("'\"").lower()
                    if any(w in remainder for w in STALL_ECHO_WORDS):
                        return True
                    # echo with no meaningful content
                    if len(remainder) < 30 and not any(c in remainder for c in ">|&$`"):
                        return True
                else:
                    return True

        # Python heredoc/noop patterns
        for pat in PYTHON_NOOP_PATTERNS:
            if pat.search(cmd):
                return True

        return False

    def _check_noop_burst(self, record: CommandRecord) -> Optional[LoopAlert]:
        """Alert on consecutive noop commands."""
        if self._consecutive_noops < self.noop_burst_limit:
            return None

        recent_noops = [
            r.raw for r in list(self._history)[-self._consecutive_noops:]
        ]
        # Add current (not yet in history)
        recent_noops.append(record.raw)

        suggestions = self._suggest_alternatives("noop", record.tool)

        return LoopAlert(
            alert_type="noop_burst",
            severity="high" if self._consecutive_noops >= 5 else "medium",
            message=(
                f"Agent has run {self._consecutive_noops + 1} consecutive no-op commands "
                f"({self._noop_total} total). This indicates stalling or confusion."
            ),
            directive=(
                f"STOP running idle/no-op commands like '{record.normalized}'. "
                f"You are wasting iterations. {suggestions}"
            ),
            commands_involved=recent_noops[-5:],
            tool=record.tool,
            count=self._consecutive_noops + 1,
            confidence=0.95,
        )

    # -------------------------------------------------------------------
    # Exact repeat detection
    # -------------------------------------------------------------------

    def _check_exact_repeat(self, record: CommandRecord) -> Optional[LoopAlert]:
        """Detect the exact same command run N+ times in the window."""
        count = sum(
            1 for r in self._history
            if r.normalized == record.normalized
        )

        if count < self.exact_repeat_limit:
            return None

        suggestions = self._suggest_alternatives(record.tool, record.tool)

        return LoopAlert(
            alert_type="exact_repeat",
            severity="high" if count >= 5 else "medium",
            message=(
                f"Exact same command repeated {count} times: '{record.normalized[:100]}'"
            ),
            directive=(
                f"STOP running '{record.normalized[:80]}' — you've done this {count} times "
                f"with the same result. {suggestions}"
            ),
            commands_involved=[record.raw],
            tool=record.tool,
            count=count,
            confidence=0.98,
        )

    # -------------------------------------------------------------------
    # Fuzzy repeat detection
    # -------------------------------------------------------------------

    def _check_fuzzy_repeat(self, record: CommandRecord) -> Optional[LoopAlert]:
        """Detect commands that are fuzzy-similar (same tool, slight variations)."""
        similar: List[CommandRecord] = []

        for r in self._history:
            # Skip exact matches (handled by exact_repeat)
            if r.normalized == record.normalized:
                continue
            # Must be same tool
            if r.tool != record.tool:
                continue
            if _fuzzy_match(r.normalized, record.normalized, self.fuzzy_threshold):
                similar.append(r)

        if len(similar) < self.fuzzy_repeat_limit - 1:  # -1 because current counts
            return None

        variations = list(set(r.raw for r in similar[-4:])) + [record.raw]
        suggestions = self._suggest_alternatives(record.tool, record.tool)

        return LoopAlert(
            alert_type="fuzzy_repeat",
            severity="high",
            message=(
                f"Agent running '{record.tool}' with slight variations {len(similar) + 1} times. "
                f"This is a loop pattern — small URL/arg changes but same fundamental approach."
            ),
            directive=(
                f"STOP running variations of '{record.tool}' commands — you've tried "
                f"{len(similar) + 1} similar variations without success. "
                f"The approach itself is not working. {suggestions}"
            ),
            commands_involved=variations[-5:],
            tool=record.tool,
            count=len(similar) + 1,
            confidence=0.85,
        )

    # -------------------------------------------------------------------
    # Tool spam detection
    # -------------------------------------------------------------------

    def _check_tool_spam(self, record: CommandRecord) -> Optional[LoopAlert]:
        """Detect excessive use of the same tool in the recent window."""
        if record.tool in ("bash", "sh", "python3", "python", "unknown"):
            return None  # Too generic

        recent_tools = [r.tool for r in self._history]
        count = recent_tools.count(record.tool)

        if count < self.tool_repeat_limit:
            return None

        # Calculate what fraction of recent commands used this tool
        ratio = count / max(len(recent_tools), 1)
        if ratio < 0.6:
            return None  # Not dominant enough

        suggestions = self._suggest_alternatives(record.tool, record.tool)

        return LoopAlert(
            alert_type="tool_spam",
            severity="medium",
            message=(
                f"Tool '{record.tool}' used {count} times in last {len(recent_tools)} "
                f"commands ({ratio:.0%} of activity). Consider switching tools."
            ),
            directive=(
                f"You've been using '{record.tool}' excessively ({count} times). "
                f"If it's not producing new results, switch to a different approach. "
                f"{suggestions}"
            ),
            commands_involved=[r.raw for r in list(self._history)[-3:] if r.tool == record.tool],
            tool=record.tool,
            count=count,
            confidence=0.75,
        )

    # -------------------------------------------------------------------
    # Cycle detection
    # -------------------------------------------------------------------

    def _check_cycle(self) -> Optional[LoopAlert]:
        """
        Detect repeating command sequences (cycles).
        e.g., [nmap, gobuster, curl, nmap, gobuster, curl] = cycle of 3
        """
        if len(self._history) < self.cycle_window:
            return None

        recent = [r.tool for r in list(self._history)[-self.cycle_window:]]

        # Try cycle lengths from 2 to half the window
        for cycle_len in range(self.cycle_min_unique, len(recent) // 2 + 1):
            candidate = recent[-cycle_len:]
            repeats = 0
            for i in range(len(recent) - cycle_len, -1, -cycle_len):
                segment = recent[i:i + cycle_len]
                if segment == candidate:
                    repeats += 1
                else:
                    break

            if repeats >= self.cycle_repeat_limit:
                cycle_cmds = [
                    r.raw for r in list(self._history)[-cycle_len:]
                ]
                return LoopAlert(
                    alert_type="cycle",
                    severity="high",
                    message=(
                        f"Detected repeating command cycle of {cycle_len} commands, "
                        f"repeated {repeats} times: {' → '.join(candidate)}"
                    ),
                    directive=(
                        f"STOP cycling through the same {cycle_len}-command sequence "
                        f"({' → '.join(candidate)}). This loop is not producing new results. "
                        f"Pick ONE untried approach and commit to it."
                    ),
                    commands_involved=cycle_cmds,
                    count=repeats,
                    confidence=0.9,
                )

        return None

    # -------------------------------------------------------------------
    # Alternative suggestions
    # -------------------------------------------------------------------

    _TOOL_ALTERNATIVES: Dict[str, List[str]] = {
        # Recon/enum alternatives
        "nmap": [
            "Try manual service probing with nc/curl on discovered ports",
            "Use searchsploit to find exploits for identified services",
            "Attempt default credentials on discovered services",
        ],
        "gobuster": [
            "Try ffuf with a different wordlist or extension set",
            "Manually test interesting paths found so far with curl",
            "Look for parameter fuzzing on discovered endpoints",
        ],
        "dirb": [
            "Switch to feroxbuster with recursive mode",
            "Test discovered paths for injection points",
            "Try wfuzz for parameter discovery",
        ],
        "ffuf": [
            "Switch to parameter fuzzing instead of directory brute-force",
            "Test discovered endpoints for SQL injection or command injection",
            "Try authenticated endpoints if any credentials were found",
        ],
        "nikto": [
            "Try nuclei with specific vulnerability templates",
            "Manually test the vulnerabilities nikto identified",
            "Focus on exploiting a specific vulnerability instead of scanning",
        ],
        "curl": [
            "If testing for injection, try sqlmap --forms on the URL",
            "Try commix for command injection testing",
            "Upload a webshell if file upload is available",
        ],
        # Exploit alternatives
        "sqlmap": [
            "Try manual SQL injection with different payloads",
            "Test other injection points (headers, cookies, POST params)",
            "Move to a different vulnerability type entirely (RCE, LFI, SSRF)",
        ],
        "hydra": [
            "Try a smaller, targeted wordlist based on discovered usernames",
            "Check for default credentials specific to the service",
            "Look for authentication bypass vulnerabilities instead",
        ],
        "searchsploit": [
            "Download and adapt a specific exploit rather than searching more",
            "Check exploit-db online for more recent exploits",
            "Try to manually exploit the vulnerability based on the advisory",
        ],
        # Generic
        "noop": [
            "Pick a specific target and vulnerability to exploit",
            "Review your findings so far and attack the most promising one",
            "Try credential stuffing, file upload, or command injection",
        ],
    }

    def _suggest_alternatives(self, context: str, tool: str) -> str:
        """Generate specific alternative suggestions based on the tool being overused."""
        alts = self._TOOL_ALTERNATIVES.get(tool, [])
        if not alts:
            alts = self._TOOL_ALTERNATIVES.get(context, [])
        if not alts:
            alts = [
                "Try a completely different tool or technique",
                "Review discovered services and attempt exploitation",
                "Focus on the most promising vulnerability found so far",
            ]

        # Pick top 2 suggestions
        suggestions = alts[:2]
        return "Instead: " + "; ".join(suggestions) + "."

    # -------------------------------------------------------------------
    # Cooldown filtering
    # -------------------------------------------------------------------

    def _filter_cooled_down(self, alerts: List[LoopAlert], now: float) -> List[LoopAlert]:
        """Remove alerts that fired too recently."""
        filtered: List[LoopAlert] = []
        for alert in alerts:
            key = (alert.alert_type, alert.tool or "")
            last_ts = self._cooldowns.get(alert.alert_type, 0)

            # Increase cooldown if we've been suppressing this pattern
            suppression_count = self._suppressed[key]
            effective_cooldown = self.cooldown_seconds * (1 + suppression_count * 0.5)
            # Cap at 10 minutes
            effective_cooldown = min(effective_cooldown, 600)

            if now - last_ts < effective_cooldown:
                continue

            self._cooldowns[alert.alert_type] = now
            self._suppressed[key] += 1
            filtered.append(alert)

        return filtered

    # -------------------------------------------------------------------
    # Stats / introspection
    # -------------------------------------------------------------------

    @property
    def total_commands(self) -> int:
        return len(self._history)

    @property
    def total_noops(self) -> int:
        return self._noop_total

    @property
    def consecutive_noops(self) -> int:
        return self._consecutive_noops

    def get_tool_distribution(self) -> Dict[str, int]:
        """Return how many times each tool was used in the current window."""
        dist: Dict[str, int] = defaultdict(int)
        for r in self._history:
            dist[r.tool] += 1
        return dict(dist)

    def get_recent_targets(self) -> Set[str]:
        """Return unique targets seen in command history."""
        targets: Set[str] = set()
        for r in self._history:
            if r.target:
                targets.add(r.target)
        return targets

    def reset(self) -> None:
        """Clear all state."""
        self._history.clear()
        self._consecutive_noops = 0
        self._noop_total = 0
        self._cooldowns.clear()
        self._suppressed.clear()
