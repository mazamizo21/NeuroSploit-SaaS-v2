#!/usr/bin/env python3
"""
TazoSploit Supervisor Service — Enhanced v2

Phase 1 (original):
  - Subscribe to Redis job output stream
  - Emit structured events (iteration, command, warnings)
  - Maintain lightweight heuristics for stalling / noop loops / repeated commands

Phase 2 (enhancements):
  1. Advanced Loop Detection — fuzzy matching, cycle detection, tool spam detection
  2. Exploit Quality Scoring — score each exploitation attempt, alert on shallow attacks
  3. Resource Monitoring — Docker memory tracking, OOM prevention
  4. Multi-Target Progress Tracking — ensure coverage across all targets
  5. Smarter Escalation — phase-aware, depth-aware intervention
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import signal
import time
import shlex
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Set, Tuple

import httpx
import redis.asyncio as redis
import structlog
import docker

try:
    from aiohttp import web
    AIOHTTP_AVAILABLE = True
except Exception:
    AIOHTTP_AVAILABLE = False

# Import enhanced modules
from .loop_detector import LoopDetector, LoopAlert
from .resource_monitor import ResourceMonitor, ResourceAlert

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

EVENT_LIST_MAX = int(os.getenv("SUPERVISOR_EVENT_LIST_MAX", "1000"))
EVENT_TTL_SECONDS = int(os.getenv("SUPERVISOR_EVENT_TTL_SECONDS", "86400"))

ALERT_STALL_SECONDS = int(os.getenv("SUPERVISOR_ALERT_STALL_SECONDS", "300"))
ALERT_NOOP_THRESHOLD = int(os.getenv("SUPERVISOR_ALERT_NOOP_THRESHOLD", "3"))
ALERT_REPEAT_THRESHOLD = int(os.getenv("SUPERVISOR_ALERT_REPEAT_THRESHOLD", "2"))
ALERT_COOLDOWN_SECONDS = int(os.getenv("SUPERVISOR_ALERT_COOLDOWN_SECONDS", "120"))
FINDINGS_STALL_SECONDS = int(os.getenv("SUPERVISOR_FINDINGS_STALL_SECONDS", "900"))

STATS_POLL_SECONDS = int(os.getenv("SUPERVISOR_STATS_POLL_SECONDS", "20"))
ACTIVE_WINDOW_SECONDS = int(os.getenv("SUPERVISOR_ACTIVE_WINDOW_SECONDS", "3600"))

SCAN_LOOP_WINDOW = int(os.getenv("SUPERVISOR_SCAN_LOOP_WINDOW", "20"))
SCAN_LOOP_ENUM_RATIO = float(os.getenv("SUPERVISOR_SCAN_LOOP_ENUM_RATIO", "0.7"))
SCAN_LOOP_MIN_COMMANDS = int(os.getenv("SUPERVISOR_SCAN_LOOP_MIN_COMMANDS", "12"))
SCAN_LOOP_EXPLOIT_GRACE_SECONDS = int(os.getenv("SUPERVISOR_SCAN_LOOP_EXPLOIT_GRACE_SECONDS", "180"))

HEALTH_PORT = int(os.getenv("SUPERVISOR_HEALTH_PORT", "9012"))

SUPERVISOR_LLM_MODE = os.getenv("SUPERVISOR_LLM_MODE", "stub").lower()  # disabled|stub|live
SUPERVISOR_LLM_PROVIDER = os.getenv("SUPERVISOR_LLM_PROVIDER", "anthropic").lower()
SUPERVISOR_LLM_API_BASE = os.getenv("SUPERVISOR_LLM_API_BASE", "https://api.anthropic.com")
SUPERVISOR_LLM_API_KEY = os.getenv("SUPERVISOR_LLM_API_KEY") or os.getenv("ANTHROPIC_API_KEY", "")
SUPERVISOR_ANTHROPIC_VERSION = os.getenv("SUPERVISOR_ANTHROPIC_VERSION", "2023-06-01")
SUPERVISOR_TRIAGE_MODEL = os.getenv("SUPERVISOR_TRIAGE_MODEL", os.getenv("LLM_MODEL", "")).strip()
SUPERVISOR_ESCALATION_MODEL = os.getenv("SUPERVISOR_ESCALATION_MODEL", "").strip()
SUPERVISOR_LLM_TIMEOUT_SECONDS = int(os.getenv("SUPERVISOR_LLM_TIMEOUT_SECONDS", "90"))
SUPERVISOR_LLM_MAX_TOKENS = int(os.getenv("SUPERVISOR_LLM_MAX_TOKENS", "800"))
SUPERVISOR_LLM_PROXY_TOKEN = os.getenv("SUPERVISOR_LLM_PROXY_TOKEN", "").strip()
if not SUPERVISOR_LLM_PROXY_TOKEN:
    SUPERVISOR_LLM_PROXY_TOKEN = os.getenv("LLM_PROXY_TOKEN", "").strip()
SUPERVISOR_LLM_PROVIDER_OVERRIDE = os.getenv("SUPERVISOR_LLM_PROVIDER_OVERRIDE", "").strip()

SUPERVISOR_AUDIT_ALERT_TYPES = set(
    t.strip()
    for t in os.getenv(
        "SUPERVISOR_AUDIT_ALERT_TYPES",
        "stalled,noop_loop,repeated_command,no_new_findings,stalling,scan_loop,"
        "loop_detected,exploit_quality_low,resource_warning,target_neglect,"
        "recon_stagnation,shallow_exploitation",
    ).split(",")
    if t.strip()
)
SUPERVISOR_AUDIT_MAX_PER_JOB = int(os.getenv("SUPERVISOR_AUDIT_MAX_PER_JOB", "10"))
SUPERVISOR_AUDIT_COOLDOWN_SECONDS = int(os.getenv("SUPERVISOR_AUDIT_COOLDOWN_SECONDS", "120"))

SUPERVISOR_ACTIONS_ENABLED = os.getenv("SUPERVISOR_ACTIONS_ENABLED", "true").lower() in ("1", "true", "yes")
SUPERVISOR_ACTIONS_DRY_RUN = os.getenv("SUPERVISOR_ACTIONS_DRY_RUN", "false").lower() in ("1", "true", "yes")
SUPERVISOR_ACTION_COOLDOWN_SECONDS = int(os.getenv("SUPERVISOR_ACTION_COOLDOWN_SECONDS", "120"))
SUPERVISOR_ACTION_MAX_PER_JOB = int(os.getenv("SUPERVISOR_ACTION_MAX_PER_JOB", "10"))
SUPERVISOR_HINT_PATH_TEMPLATE = os.getenv(
    "SUPERVISOR_HINT_PATH_TEMPLATE",
    "/pentest/output/{job_id}/supervisor_hints.jsonl",
)
SUPERVISOR_ENABLED_CACHE_SECONDS = int(os.getenv("SUPERVISOR_ENABLED_CACHE_SECONDS", "5"))
SUPERVISOR_ENABLED_DEFAULT = os.getenv("SUPERVISOR_ENABLED_DEFAULT", "true").lower() in ("1", "true", "yes")

# --- Phase 2: New configuration ---
# Exploit quality scoring
EXPLOIT_QUALITY_LOW_THRESHOLD = float(os.getenv("SUPERVISOR_EXPLOIT_QUALITY_LOW", "0.3"))
EXPLOIT_QUALITY_WINDOW = int(os.getenv("SUPERVISOR_EXPLOIT_QUALITY_WINDOW", "10"))

# Multi-target tracking
TARGET_COVERAGE_CHECK_RATIO = float(os.getenv("SUPERVISOR_TARGET_COVERAGE_CHECK_RATIO", "0.25"))
TARGET_COVERAGE_MIN_TOUCHED = float(os.getenv("SUPERVISOR_TARGET_COVERAGE_MIN_TOUCHED", "0.50"))

# Smarter escalation
RECON_STAGNATION_RATIO = float(os.getenv("SUPERVISOR_RECON_STAGNATION_RATIO", "0.30"))
SHALLOW_EXPLOIT_MIN_FINDINGS = int(os.getenv("SUPERVISOR_SHALLOW_EXPLOIT_MIN_FINDINGS", "2"))

# Resource monitoring
RESOURCE_MONITOR_ENABLED = os.getenv("SUPERVISOR_RESOURCE_MONITOR_ENABLED", "true").lower() in ("1", "true", "yes")
RESOURCE_LOG_INTERVAL_ITERS = int(os.getenv("SUPERVISOR_RESOURCE_LOG_INTERVAL_ITERS", "10"))


# ----------------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------------

logging.basicConfig(level=LOG_LEVEL)
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger()

# ----------------------------------------------------------------------------
# Parsing helpers
# ----------------------------------------------------------------------------

LOG_LINE_RE = re.compile(r"^\[(?P<ts>[^\]]+)\] \[(?P<level>[A-Z]+)\] (?P<msg>.*)$")
ITERATION_RE = re.compile(r"^=== Iteration (?P<current>\d+)/(?P<total>\d+) ===$")
EXEC_RE = re.compile(r"^Executing \[(?P<exec_type>[^\]]+)\]: (?P<cmd>.+)$")

NOOP_COMMANDS = [':', 'sleep', 'wait', 'true', 'date', 'id', 'pwd', 'ls -la /pentest']
STALL_ECHO_PATTERNS = ['ready', 'waiting', 'standing by', 'idle', 'awaiting', 'done', 'complete', 'status']

ENUM_COMMAND_MARKERS = [
    "nmap", "masscan", "gobuster", "dirb", "dirsearch", "ffuf", "nikto",
    "whatweb", "nuclei", "amass", "subfinder", "assetfinder", "curl ",
    "dig ", "nslookup", "host ", "dnsrecon", "dnsenum", "whois",
    "nc -v", "nc -z", "telnet ",
]
EXPLOIT_COMMAND_MARKERS = [
    "sqlmap", "commix", "msfconsole", "searchsploit", "metasploit",
    "hydra", "medusa", "patator", "john", "hashcat", "crackmapexec",
    "pg_dump", "mysqldump", "reverse shell", "shell.php", "nc -e", "bash -i",
]
INJECTION_MARKERS = ["' or", "or 1=1", "union", "sleep(", "benchmark(", "--", "/*", "*/", "%27", "%3d"]

# --- Phase 2: Exploit quality scoring markers ---
# High-quality exploit indicators (actual exploitation success signals)
EXPLOIT_SUCCESS_MARKERS = [
    "shell obtained", "reverse shell", "meterpreter", "session opened",
    "credentials found", "password:", "dumping", "pg_dump", "mysqldump",
    "file uploaded", "webshell", "shell.php", "cmd.php",
    "root@", "uid=0", "nt authority\\system",
    "flag{", "ctf{", "proof.txt",
    "data extracted", "rows affected", "entries found",
    "hash:", "ntlm:", "$1$", "$6$", "$2a$", "$2b$",
]

# Low-quality "exploitation" indicators (recon disguised as exploitation)
EXPLOIT_FAKE_MARKERS = [
    "scanning", "enumerating", "checking", "testing connection",
    "error:", "connection refused", "timeout", "not found",
    "404", "403", "500 internal server error",
    "no results", "0 results", "nothing found",
    "health check", "status check", "verifying",
]

# Commands that represent real exploitation attempts (not just recon)
REAL_EXPLOIT_COMMANDS = [
    "sqlmap", "commix", "hydra", "medusa", "john", "hashcat",
    "msfconsole", "crackmapexec", "nc -e", "bash -i",
    "pg_dump", "mysqldump", "secretsdump",
    "upload", "webshell", "reverse_shell",
]

# Commands that are recon even if they look active
RECON_DISGUISED_COMMANDS = [
    "nmap -sV", "nmap -A", "nmap --script",  # nmap scripts are still recon
    "nikto", "whatweb", "wpscan --enumerate",
    "searchsploit",  # searching != exploiting
    "nuclei",  # scanning != exploiting
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_int(value: Optional[str], default: int = 0) -> int:
    try:
        return int(value) if value is not None else default
    except Exception:
        return default


def _normalize_cmd(cmd: str) -> str:
    return " ".join((cmd or "").strip().split()).lower()


def _is_noop_command(cmd: str) -> bool:
    cmd_lower = _normalize_cmd(cmd)
    if not cmd_lower:
        return False
    for noop in NOOP_COMMANDS:
        if cmd_lower == noop or cmd_lower.startswith(noop + " "):
            return True
    if cmd_lower.startswith("echo") and any(pat in cmd_lower for pat in STALL_ECHO_PATTERNS):
        return True
    if cmd_lower.startswith("cat /pentest/output/"):
        return True
    return False


def _classify_cmd_intent(cmd: str) -> str:
    """Return exploit|enum|other based on simple heuristics."""
    cmd_lower = _normalize_cmd(cmd)
    if not cmd_lower:
        return "other"

    if "curl " in cmd_lower:
        if any(m in cmd_lower for m in INJECTION_MARKERS) or "-f " in cmd_lower or "multipart/form-data" in cmd_lower:
            return "exploit"
        return "enum"

    if any(m in cmd_lower for m in EXPLOIT_COMMAND_MARKERS):
        return "exploit"
    if any(m in cmd_lower for m in ENUM_COMMAND_MARKERS):
        return "enum"
    return "other"


def _extract_target(cmd: str) -> Optional[str]:
    """Extract IP address or hostname from a command."""
    # Match IP addresses
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', cmd)
    if ip_match:
        return ip_match.group(1)
    # Match URLs
    url_match = re.search(r'https?://([^\s/:]+)', cmd)
    if url_match:
        return url_match.group(1)
    return None


def _parse_log_line(line: str) -> Dict[str, Optional[str]]:
    m = LOG_LINE_RE.match(line)
    if not m:
        return {"ts": None, "level": None, "msg": line}
    return {"ts": m.group("ts"), "level": m.group("level"), "msg": m.group("msg")}


# ----------------------------------------------------------------------------
# Exploit Quality Scorer
# ----------------------------------------------------------------------------

@dataclass
class ExploitScore:
    """Quality score for a single exploitation attempt."""
    command: str
    score: float            # 0.0 (fake) to 1.0 (real exploit success)
    is_real_exploit: bool   # Was this a genuine exploitation attempt?
    category: str           # shell | data_extract | cred_dump | file_write | scan | recon | other
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "command": self.command[:200],
            "score": round(self.score, 2),
            "is_real_exploit": self.is_real_exploit,
            "category": self.category,
            "evidence": self.evidence[:5],
        }


class ExploitQualityScorer:
    """
    Scores exploitation attempts for quality. Distinguishes real attacks
    from recon disguised as exploitation.
    """

    def __init__(self, window_size: int = EXPLOIT_QUALITY_WINDOW) -> None:
        self._scores: Deque[ExploitScore] = deque(maxlen=window_size)
        self._total_scored: int = 0
        self._real_exploits: int = 0
        self._successful_exploits: int = 0

    def score_command(self, cmd: str, output: str = "") -> ExploitScore:
        """
        Score a command + its output for exploitation quality.

        Returns ExploitScore with:
          - score: 0.0-1.0 quality rating
          - is_real_exploit: whether this was a genuine attack
          - category: what type of exploit it represents
        """
        cmd_lower = _normalize_cmd(cmd)
        output_lower = output.lower() if output else ""

        # Base classification
        intent = _classify_cmd_intent(cmd)
        category = "other"
        base_score = 0.0
        is_real = False
        evidence: List[str] = []

        if intent == "exploit":
            is_real = True
            base_score = 0.4  # Starting score for a real exploit attempt
            category = self._categorize_exploit(cmd_lower)
            evidence.append(f"exploit_command:{category}")

            # Check if it's actually recon disguised as exploit
            for marker in RECON_DISGUISED_COMMANDS:
                if marker in cmd_lower:
                    is_real = False
                    base_score = 0.15
                    category = "recon"
                    evidence.append(f"recon_disguised:{marker}")
                    break

        elif intent == "enum":
            base_score = 0.1
            category = "recon"
            evidence.append("enumeration_command")

        # Boost score based on output success indicators
        if output_lower:
            success_hits = sum(1 for m in EXPLOIT_SUCCESS_MARKERS if m in output_lower)
            if success_hits > 0:
                base_score = min(base_score + 0.2 * success_hits, 1.0)
                is_real = True
                evidence.append(f"success_indicators:{success_hits}")

                # Specific high-value indicators
                if any(m in output_lower for m in ["shell obtained", "session opened", "meterpreter"]):
                    base_score = 1.0
                    category = "shell"
                    evidence.append("shell_obtained")
                elif any(m in output_lower for m in ["dumping", "pg_dump", "mysqldump", "data extracted"]):
                    base_score = max(base_score, 0.9)
                    category = "data_extract"
                    evidence.append("data_extracted")
                elif any(m in output_lower for m in ["hash:", "ntlm:", "credentials found"]):
                    base_score = max(base_score, 0.85)
                    category = "cred_dump"
                    evidence.append("credentials_found")

            # Penalize based on failure indicators
            fail_hits = sum(1 for m in EXPLOIT_FAKE_MARKERS if m in output_lower)
            if fail_hits > 0:
                base_score = max(base_score - 0.1 * fail_hits, 0.0)
                evidence.append(f"failure_indicators:{fail_hits}")

        score = ExploitScore(
            command=cmd,
            score=base_score,
            is_real_exploit=is_real,
            category=category,
            evidence=evidence,
        )

        self._scores.append(score)
        self._total_scored += 1
        if is_real:
            self._real_exploits += 1
        if base_score >= 0.7:
            self._successful_exploits += 1

        return score

    def _categorize_exploit(self, cmd_lower: str) -> str:
        """Categorize the type of exploitation being attempted."""
        if any(m in cmd_lower for m in ["nc -e", "bash -i", "reverse", "meterpreter", "shell"]):
            return "shell"
        if any(m in cmd_lower for m in ["pg_dump", "mysqldump", "dump", "extract"]):
            return "data_extract"
        if any(m in cmd_lower for m in ["john", "hashcat", "crackmapexec", "secretsdump"]):
            return "cred_dump"
        if any(m in cmd_lower for m in ["upload", "webshell", "file write"]):
            return "file_write"
        if any(m in cmd_lower for m in ["sqlmap", "commix", "hydra", "medusa"]):
            return "injection"
        return "other"

    @property
    def average_score(self) -> float:
        """Average quality score across recent exploitation attempts."""
        if not self._scores:
            return 0.0
        return sum(s.score for s in self._scores) / len(self._scores)

    @property
    def real_exploit_ratio(self) -> float:
        """Fraction of scored commands that were real exploitation attempts."""
        if self._total_scored == 0:
            return 0.0
        return self._real_exploits / self._total_scored

    @property
    def success_ratio(self) -> float:
        """Fraction of exploit attempts that scored >= 0.7 (likely successful)."""
        if self._real_exploits == 0:
            return 0.0
        return self._successful_exploits / self._real_exploits

    def get_quality_report(self) -> Dict:
        """Generate a summary quality report."""
        return {
            "average_score": round(self.average_score, 2),
            "real_exploit_ratio": round(self.real_exploit_ratio, 2),
            "success_ratio": round(self.success_ratio, 2),
            "total_scored": self._total_scored,
            "real_exploits": self._real_exploits,
            "successful_exploits": self._successful_exploits,
            "recent_scores": [s.to_dict() for s in list(self._scores)[-5:]],
        }

    def is_quality_low(self) -> bool:
        """Check if exploit quality has dropped below threshold."""
        if len(self._scores) < 3:
            return False
        return self.average_score < EXPLOIT_QUALITY_LOW_THRESHOLD

    def reset(self) -> None:
        self._scores.clear()
        self._total_scored = 0
        self._real_exploits = 0
        self._successful_exploits = 0


# ----------------------------------------------------------------------------
# Multi-Target Progress Tracker
# ----------------------------------------------------------------------------

@dataclass
class TargetProgress:
    """Track progress against a specific target."""
    target: str
    first_seen_iter: int = 0
    last_seen_iter: int = 0
    command_count: int = 0
    finding_count: int = 0
    phases_seen: Set[str] = field(default_factory=set)  # recon | exploit | post
    tools_used: Set[str] = field(default_factory=set)

    def to_dict(self) -> Dict:
        return {
            "target": self.target,
            "first_seen_iter": self.first_seen_iter,
            "last_seen_iter": self.last_seen_iter,
            "command_count": self.command_count,
            "finding_count": self.finding_count,
            "phases_seen": sorted(self.phases_seen),
            "tools_used": sorted(self.tools_used),
        }


class TargetTracker:
    """Tracks which targets have been touched and how deeply."""

    def __init__(self) -> None:
        self._targets: Dict[str, TargetProgress] = {}
        self._known_targets: Set[str] = set()  # All targets from job config
        self._last_coverage_alert_iter: int = 0

    def set_known_targets(self, targets: List[str]) -> None:
        """Set the list of targets from job configuration."""
        self._known_targets = set(targets)

    def record_command(self, cmd: str, iteration: int) -> Optional[str]:
        """
        Record a command and extract its target. Returns the target IP/host if found.
        """
        target = _extract_target(cmd)
        if not target:
            return None

        if target not in self._targets:
            self._targets[target] = TargetProgress(
                target=target,
                first_seen_iter=iteration,
            )

        tp = self._targets[target]
        tp.last_seen_iter = iteration
        tp.command_count += 1

        # Track phase
        intent = _classify_cmd_intent(cmd)
        if intent == "exploit":
            tp.phases_seen.add("exploit")
        elif intent == "enum":
            tp.phases_seen.add("recon")
        else:
            tp.phases_seen.add("other")

        # Track tool
        cmd_lower = _normalize_cmd(cmd)
        parts = cmd_lower.split()
        if parts:
            tool = parts[0].rstrip("/").rsplit("/", 1)[-1]
            tp.tools_used.add(tool)

        return target

    def record_finding(self, target: str) -> None:
        """Record a finding against a specific target."""
        if target in self._targets:
            self._targets[target].finding_count += 1

    @property
    def touched_targets(self) -> Set[str]:
        return set(self._targets.keys())

    @property
    def untouched_targets(self) -> Set[str]:
        """Targets in the known set that haven't been touched."""
        return self._known_targets - self.touched_targets

    def coverage_ratio(self) -> float:
        """Fraction of known targets that have been touched."""
        if not self._known_targets:
            # If we don't know the target list, use discovered targets
            return 1.0 if self._targets else 0.0
        return len(self.touched_targets & self._known_targets) / max(len(self._known_targets), 1)

    def check_coverage(self, current_iter: int, max_iter: int) -> Optional[Dict]:
        """
        Check if target coverage is adequate for the current progress.
        Returns alert data if coverage is too low, None otherwise.
        """
        if not self._known_targets or max_iter <= 0:
            return None

        progress_ratio = current_iter / max_iter

        # Only check after TARGET_COVERAGE_CHECK_RATIO of iterations
        if progress_ratio < TARGET_COVERAGE_CHECK_RATIO:
            return None

        # Don't re-alert too frequently
        if current_iter - self._last_coverage_alert_iter < 10:
            return None

        coverage = self.coverage_ratio()
        if coverage >= TARGET_COVERAGE_MIN_TOUCHED:
            return None

        self._last_coverage_alert_iter = current_iter

        untouched = sorted(self.untouched_targets)[:5]  # Show max 5

        return {
            "coverage_ratio": round(coverage, 2),
            "progress_ratio": round(progress_ratio, 2),
            "touched": len(self.touched_targets & self._known_targets),
            "total_known": len(self._known_targets),
            "untouched_targets": untouched,
        }

    def get_shallow_targets(self) -> List[Dict]:
        """
        Find targets where vulnerabilities were found but never exploited
        (only recon phase seen, no exploit phase).
        """
        shallow = []
        for target, tp in self._targets.items():
            if tp.finding_count > 0 and "exploit" not in tp.phases_seen:
                shallow.append(tp.to_dict())
        return shallow

    def get_neglected_targets(self, current_iter: int, stale_iters: int = 20) -> List[str]:
        """Find targets that haven't been touched in a while."""
        neglected = []
        for target, tp in self._targets.items():
            if current_iter - tp.last_seen_iter > stale_iters and tp.command_count > 0:
                neglected.append(target)
        return neglected

    def get_report(self) -> Dict:
        return {
            "known_targets": sorted(self._known_targets),
            "touched_count": len(self.touched_targets),
            "coverage_ratio": round(self.coverage_ratio(), 2),
            "per_target": {t: p.to_dict() for t, p in self._targets.items()},
        }


# ----------------------------------------------------------------------------
# State (Enhanced)
# ----------------------------------------------------------------------------

@dataclass
class JobState:
    job_status: str = "unknown"
    last_status_ts: float = 0
    last_output_ts: float = 0
    last_iteration_ts: float = 0
    last_command_ts: float = 0
    last_progress_ts: float = 0
    last_findings_total: int = 0
    last_findings_ts: float = 0
    current_iteration: int = 0
    max_iterations: int = 0
    recent_commands: Deque[str] = field(default_factory=lambda: deque(maxlen=5))
    recent_cmd_classes: Deque[str] = field(default_factory=lambda: deque(maxlen=SCAN_LOOP_WINDOW))
    last_exploit_ts: float = 0
    noop_count: int = 0
    noop_since_ts: float = 0
    last_alert_ts: Dict[str, float] = field(default_factory=dict)
    audit_count: int = 0
    last_audit_ts: float = 0
    action_count: int = 0
    last_action_ts: float = 0

    # --- Phase 2 enhancements ---
    # Loop detection
    loop_detector: Optional[LoopDetector] = field(default=None)
    # Exploit quality scoring
    exploit_scorer: Optional[ExploitQualityScorer] = field(default=None)
    # Multi-target tracking
    target_tracker: Optional[TargetTracker] = field(default=None)
    # Phase tracking for smarter escalation
    recon_iterations: int = 0
    exploit_iterations: int = 0
    post_exploit_iterations: int = 0
    total_iterations_with_commands: int = 0
    # Phase transition tracking
    first_exploit_iter: int = 0
    last_phase: str = "recon"
    phase_transition_count: int = 0
    # Resource monitoring
    last_resource_log_iter: int = 0
    kali_container_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.loop_detector is None:
            self.loop_detector = LoopDetector()
        if self.exploit_scorer is None:
            self.exploit_scorer = ExploitQualityScorer()
        if self.target_tracker is None:
            self.target_tracker = TargetTracker()


# ----------------------------------------------------------------------------
# Supervisor (Enhanced)
# ----------------------------------------------------------------------------

class Supervisor:
    def __init__(self) -> None:
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        self.states: Dict[str, JobState] = {}
        self._stop_event = asyncio.Event()
        self._health_runner: Optional[web.AppRunner] = None
        if SUPERVISOR_ACTIONS_ENABLED:
            try:
                self.docker_client = docker.from_env()
            except Exception:
                self.docker_client = None
                logger.warn("docker_client_unavailable")
        else:
            self.docker_client = None
        self._enabled_cache_value = SUPERVISOR_ENABLED_DEFAULT
        self._enabled_cache_ts = 0.0
        self._provider_cache_value: Optional[str] = SUPERVISOR_LLM_PROVIDER_OVERRIDE or None
        self._provider_cache_ts = 0.0
        self._job_enabled_cache: Dict[str, tuple] = {}
        self._job_provider_cache: Dict[str, tuple] = {}

        # Phase 2: Resource monitor
        self._resource_monitor: Optional[ResourceMonitor] = None
        if RESOURCE_MONITOR_ENABLED and self.docker_client:
            self._resource_monitor = ResourceMonitor(
                on_alert=self._handle_resource_alert,
                docker_client=self.docker_client,
            )

    def _get_state(self, job_id: str) -> JobState:
        if job_id not in self.states:
            self.states[job_id] = JobState()
        return self.states[job_id]

    async def start(self) -> None:
        logger.info("supervisor_started", version="2.0",
                     enhancements=["loop_detection", "exploit_scoring",
                                   "resource_monitoring", "target_tracking",
                                   "smart_escalation"])
        await self._start_health_server()

        tasks = [
            asyncio.create_task(self._listen_output()),
            asyncio.create_task(self._listen_status()),
            asyncio.create_task(self._poll_live_stats()),
            asyncio.create_task(self._alert_sweeper()),
        ]

        # Phase 2: Start resource monitor if available
        if self._resource_monitor:
            tasks.append(asyncio.create_task(
                self._resource_monitor.run(self._stop_event)
            ))

        await self._stop_event.wait()

        for task in tasks:
            task.cancel()
        await self._stop_health_server()
        try:
            await self.redis.close()
        except Exception:
            pass

    async def stop(self) -> None:
        self._stop_event.set()

    async def _start_health_server(self) -> None:
        if not AIOHTTP_AVAILABLE or HEALTH_PORT <= 0:
            return

        async def health(_request: web.Request) -> web.Response:
            payload = {
                "status": "ok",
                "time": _utc_now_iso(),
                "jobs_tracking": len(self.states),
                "version": "2.0",
                "enhancements": {
                    "loop_detection": True,
                    "exploit_scoring": True,
                    "resource_monitoring": RESOURCE_MONITOR_ENABLED,
                    "target_tracking": True,
                    "smart_escalation": True,
                },
            }
            return web.json_response(payload)

        # Phase 2: Add detailed stats endpoint
        async def job_stats(request: web.Request) -> web.Response:
            job_id = request.match_info.get("job_id", "")
            if job_id not in self.states:
                return web.json_response({"error": "job not found"}, status=404)
            state = self.states[job_id]
            payload = {
                "job_id": job_id,
                "iteration": f"{state.current_iteration}/{state.max_iterations}",
                "status": state.job_status,
                "audit_count": state.audit_count,
                "action_count": state.action_count,
                "loop_detection": {
                    "total_commands": state.loop_detector.total_commands if state.loop_detector else 0,
                    "total_noops": state.loop_detector.total_noops if state.loop_detector else 0,
                    "tool_distribution": state.loop_detector.get_tool_distribution() if state.loop_detector else {},
                },
                "exploit_quality": state.exploit_scorer.get_quality_report() if state.exploit_scorer else {},
                "target_tracking": state.target_tracker.get_report() if state.target_tracker else {},
                "phase_distribution": {
                    "recon": state.recon_iterations,
                    "exploit": state.exploit_iterations,
                    "post_exploit": state.post_exploit_iterations,
                    "total_with_commands": state.total_iterations_with_commands,
                },
                "resource": (
                    self._resource_monitor.get_memory_stats(job_id)
                    if self._resource_monitor else None
                ),
            }
            return web.json_response(payload)

        app = web.Application()
        app.add_routes([
            web.get("/health", health),
            web.get("/job/{job_id}/stats", job_stats),
        ])
        self._health_runner = web.AppRunner(app)
        await self._health_runner.setup()
        site = web.TCPSite(self._health_runner, "0.0.0.0", HEALTH_PORT)
        await site.start()
        logger.info("health_server_started", port=HEALTH_PORT)

    async def _stop_health_server(self) -> None:
        if self._health_runner:
            await self._health_runner.cleanup()
            self._health_runner = None

    # -----------------------------------------------------------------------
    # Redis listeners
    # -----------------------------------------------------------------------

    async def _listen_output(self) -> None:
        while not self._stop_event.is_set():
            try:
                pubsub = self.redis.pubsub()
                await pubsub.psubscribe("job:*:output")

                async for message in pubsub.listen():
                    if self._stop_event.is_set():
                        break
                    if message.get("type") != "pmessage":
                        continue

                    channel = message.get("channel")
                    if isinstance(channel, bytes):
                        channel = channel.decode()
                    if not isinstance(channel, str):
                        continue

                    parts = channel.split(":")
                    if len(parts) < 3:
                        continue
                    job_id = parts[1]

                    data = message.get("data")
                    if isinstance(data, bytes):
                        data = data.decode(errors="replace")

                    try:
                        payload = json.loads(data)
                    except Exception:
                        payload = {"line": str(data), "timestamp": _utc_now_iso()}

                    line = payload.get("line", "")
                    msg_ts = payload.get("timestamp") or _utc_now_iso()

                    await self._handle_output_line(job_id, line, msg_ts)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("output_listener_error", error=str(e))
                await asyncio.sleep(2)

    async def _listen_status(self) -> None:
        """Listen for job:*:status events so we can stop alerting on completed jobs."""
        terminal_statuses = {"completed", "failed", "cancelled", "canceled", "error"}
        while not self._stop_event.is_set():
            try:
                pubsub = self.redis.pubsub()
                await pubsub.psubscribe("job:*:status")

                async for message in pubsub.listen():
                    if self._stop_event.is_set():
                        break
                    if message.get("type") != "pmessage":
                        continue

                    channel = message.get("channel")
                    if isinstance(channel, bytes):
                        channel = channel.decode()
                    if not isinstance(channel, str):
                        continue

                    parts = channel.split(":")
                    if len(parts) < 3:
                        continue
                    job_id = parts[1]

                    data = message.get("data")
                    if isinstance(data, bytes):
                        data = data.decode(errors="replace")
                    try:
                        payload = json.loads(data)
                    except Exception:
                        payload = {"status": str(data), "timestamp": _utc_now_iso()}

                    status = str(payload.get("status") or "").strip().lower() or "unknown"
                    msg_ts = payload.get("timestamp") or _utc_now_iso()

                    state = self._get_state(job_id)
                    state.job_status = status
                    state.last_status_ts = time.time()

                    await self._emit_event(
                        job_id,
                        "job_status",
                        msg_ts,
                        "",
                        {"status": status},
                    )

                    if status in terminal_statuses:
                        # Clean up resource monitor tracking
                        if self._resource_monitor:
                            self._resource_monitor.untrack_job(job_id)
                        self.states.pop(job_id, None)
                        self._job_enabled_cache.pop(job_id, None)
                        self._job_provider_cache.pop(job_id, None)
                        logger.info("job_terminal_status", job_id=job_id, status=status)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("status_listener_error", error=str(e))
                await asyncio.sleep(2)

    # -----------------------------------------------------------------------
    # Output handling (enhanced)
    # -----------------------------------------------------------------------

    async def _handle_output_line(self, job_id: str, line: str, msg_ts: str) -> None:
        now = time.time()
        state = self._get_state(job_id)
        state.last_output_ts = now

        parsed = _parse_log_line(line)
        level = parsed.get("level")
        msg = parsed.get("msg") or ""

        # Iteration event
        iter_match = ITERATION_RE.match(msg)
        if iter_match:
            current = _safe_int(iter_match.group("current"))
            total = _safe_int(iter_match.group("total"))
            state.current_iteration = current
            state.max_iterations = total
            state.last_iteration_ts = now
            state.last_progress_ts = now

            await self._emit_event(
                job_id,
                "iteration",
                msg_ts,
                line,
                {
                    "current": current,
                    "total": total,
                },
            )

            # Phase 2: Periodic resource logging
            if (RESOURCE_MONITOR_ENABLED and self._resource_monitor
                    and current - state.last_resource_log_iter >= RESOURCE_LOG_INTERVAL_ITERS):
                state.last_resource_log_iter = current
                await self._log_resource_usage(job_id, state, current)

            # Phase 2: Check target coverage at this iteration
            await self._check_target_coverage(job_id, state)

            # Phase 2: Check for recon stagnation
            await self._check_recon_stagnation(job_id, state)

            # Phase 2: Check for shallow exploitation
            await self._check_shallow_exploitation(job_id, state)

            # Phase 2: Register container for resource monitoring on first iteration
            if current == 1 and self._resource_monitor:
                await self._register_container_for_monitoring(job_id, state)

            return

        # Command execution event
        exec_match = EXEC_RE.match(msg)
        if exec_match:
            exec_type = exec_match.group("exec_type")
            cmd = exec_match.group("cmd")
            state.last_command_ts = now
            state.last_progress_ts = now

            normalized_cmd = _normalize_cmd(cmd)
            if normalized_cmd:
                state.recent_commands.append(normalized_cmd)

            await self._emit_event(
                job_id,
                "command",
                msg_ts,
                line,
                {
                    "exec_type": exec_type,
                    "command": cmd,
                },
            )

            # Original alerts
            await self._maybe_emit_noop_alert(job_id, state, cmd, now)
            await self._maybe_emit_repeat_alert(job_id, state, normalized_cmd, now)
            await self._maybe_emit_scan_loop_alert(job_id, state, cmd, now)

            # Phase 2: Advanced loop detection
            await self._run_loop_detection(job_id, state, cmd)

            # Phase 2: Track target
            if state.target_tracker:
                state.target_tracker.record_command(cmd, state.current_iteration)

            # Phase 2: Track phase distribution
            await self._track_phase(job_id, state, cmd)

            # Phase 2: Score exploitation quality
            await self._score_exploit_quality(job_id, state, cmd)

            return

        # Stalling signal from agent
        if "STALLING DETECTED" in msg:
            await self._emit_event(
                job_id,
                "stalling",
                msg_ts,
                line,
                {"message": msg},
            )
            return

        # Warnings / errors
        if level in {"WARN", "ERROR"}:
            await self._emit_event(
                job_id,
                "log",
                msg_ts,
                line,
                {"level": level, "message": msg},
            )

    # -----------------------------------------------------------------------
    # Phase 2: Advanced Loop Detection
    # -----------------------------------------------------------------------

    async def _run_loop_detection(self, job_id: str, state: JobState, cmd: str) -> None:
        """Run the advanced loop detector on each command."""
        if not state.loop_detector:
            return

        alerts: List[LoopAlert] = state.loop_detector.ingest(
            cmd, iteration=state.current_iteration
        )

        for alert in alerts:
            logger.info(
                "loop_detected",
                job_id=job_id,
                alert_type=alert.alert_type,
                severity=alert.severity,
                tool=alert.tool,
                count=alert.count,
                confidence=alert.confidence,
            )

            await self._emit_alert(
                job_id,
                "loop_detected",
                {
                    "loop_type": alert.alert_type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "directive": alert.directive,
                    "tool": alert.tool,
                    "count": alert.count,
                    "confidence": alert.confidence,
                    "commands_involved": alert.commands_involved,
                },
            )

    # -----------------------------------------------------------------------
    # Phase 2: Exploit Quality Scoring
    # -----------------------------------------------------------------------

    async def _score_exploit_quality(self, job_id: str, state: JobState, cmd: str) -> None:
        """Score each command for exploitation quality."""
        if not state.exploit_scorer:
            return

        intent = _classify_cmd_intent(cmd)
        if intent not in ("exploit", "enum"):
            return  # Only score relevant commands

        score = state.exploit_scorer.score_command(cmd)

        # Emit quality event for significant scores
        if score.is_real_exploit or score.score >= 0.3:
            await self._emit_event(
                job_id,
                "exploit_quality",
                _utc_now_iso(),
                "",
                score.to_dict(),
            )

        # Check if overall quality has dropped too low
        if state.exploit_scorer.is_quality_low():
            if self._cooldown_ok(state, "exploit_quality", time.time()):
                report = state.exploit_scorer.get_quality_report()
                await self._emit_alert(
                    job_id,
                    "exploit_quality_low",
                    {
                        "message": (
                            f"Exploitation quality is critically low "
                            f"(avg score: {report['average_score']}, "
                            f"real exploit ratio: {report['real_exploit_ratio']}). "
                            f"Agent is running scanners/recon instead of actual exploits."
                        ),
                        "directive": (
                            "STOP scanning and START exploiting. You have been running "
                            "reconnaissance tools disguised as exploitation. Execute a "
                            "real attack: SQL injection with --dump, command injection "
                            "with reverse shell, credential brute-force, or file upload. "
                            "Prove exploitation with concrete evidence (data, shell, creds)."
                        ),
                        "quality_report": report,
                    },
                )

    # -----------------------------------------------------------------------
    # Phase 2: Multi-Target Progress Tracking
    # -----------------------------------------------------------------------

    async def _check_target_coverage(self, job_id: str, state: JobState) -> None:
        """Check if target coverage is adequate and alert if not."""
        if not state.target_tracker:
            return

        # Try to load known targets from Redis if not set
        if not state.target_tracker._known_targets:
            await self._load_known_targets(job_id, state)

        coverage_data = state.target_tracker.check_coverage(
            state.current_iteration, state.max_iterations
        )

        if coverage_data:
            untouched = coverage_data.get("untouched_targets", [])
            if self._cooldown_ok(state, "target_neglect", time.time()):
                await self._emit_alert(
                    job_id,
                    "target_neglect",
                    {
                        "message": (
                            f"Target coverage is too low: only {coverage_data['touched']}"
                            f"/{coverage_data['total_known']} targets touched "
                            f"({coverage_data['coverage_ratio']:.0%}) at "
                            f"{coverage_data['progress_ratio']:.0%} progress."
                        ),
                        "directive": (
                            f"You are neglecting targets. Move to untouched target(s): "
                            f"{', '.join(untouched[:3])}. Start with port scanning and "
                            f"service enumeration, then exploit any findings."
                        ),
                        "coverage": coverage_data,
                    },
                )

    async def _load_known_targets(self, job_id: str, state: JobState) -> None:
        """Load the target list from Redis job config."""
        try:
            # Try multiple Redis keys where targets might be stored
            for key_pattern in [
                f"job:{job_id}:targets",
                f"job:{job_id}:config",
            ]:
                val = await self.redis.get(key_pattern)
                if val:
                    try:
                        data = json.loads(val)
                        if isinstance(data, list):
                            state.target_tracker.set_known_targets(data)
                            return
                        if isinstance(data, dict):
                            targets = data.get("targets", data.get("target_hosts", []))
                            if isinstance(targets, list):
                                state.target_tracker.set_known_targets(targets)
                                return
                            if isinstance(targets, str):
                                state.target_tracker.set_known_targets([targets])
                                return
                    except json.JSONDecodeError:
                        # Might be a comma-separated string
                        targets = [t.strip() for t in val.split(",") if t.strip()]
                        if targets:
                            state.target_tracker.set_known_targets(targets)
                            return
        except Exception as e:
            logger.debug("load_known_targets_failed", job_id=job_id, error=str(e))

    # -----------------------------------------------------------------------
    # Phase 2: Smarter Escalation — Phase Tracking
    # -----------------------------------------------------------------------

    async def _track_phase(self, job_id: str, state: JobState, cmd: str) -> None:
        """Track which phase the agent is in for smarter escalation."""
        intent = _classify_cmd_intent(cmd)
        state.total_iterations_with_commands += 1

        if intent == "exploit":
            state.exploit_iterations += 1
            if state.first_exploit_iter == 0:
                state.first_exploit_iter = state.current_iteration
            if state.last_phase != "exploit":
                state.phase_transition_count += 1
                state.last_phase = "exploit"
        elif intent == "enum":
            state.recon_iterations += 1
            if state.last_phase != "recon":
                state.phase_transition_count += 1
                state.last_phase = "recon"
        else:
            # "other" could be post-exploitation
            if state.exploit_iterations > 0:
                state.post_exploit_iterations += 1

    async def _check_recon_stagnation(self, job_id: str, state: JobState) -> None:
        """
        Alert when agent has been in recon for >30% of iterations without
        transitioning to exploitation.
        """
        if state.total_iterations_with_commands < 10:
            return  # Too early to judge

        if state.max_iterations <= 0:
            return

        progress = state.current_iteration / state.max_iterations
        recon_ratio = state.recon_iterations / max(state.total_iterations_with_commands, 1)

        # Only alert if we're past the early phase and recon ratio is too high
        if (progress > RECON_STAGNATION_RATIO
                and recon_ratio > 0.7
                and state.exploit_iterations < 3):
            if self._cooldown_ok(state, "recon_stagnation", time.time()):
                await self._emit_alert(
                    job_id,
                    "recon_stagnation",
                    {
                        "message": (
                            f"Agent has spent {recon_ratio:.0%} of iterations on recon "
                            f"({state.recon_iterations}/{state.total_iterations_with_commands}) "
                            f"with only {state.exploit_iterations} exploitation attempts. "
                            f"Progress is at {progress:.0%}."
                        ),
                        "directive": (
                            "TRANSITION TO EXPLOITATION NOW. You have spent too long on "
                            "reconnaissance. Use what you've found so far: pick the most "
                            "promising vulnerability and attempt to exploit it. "
                            "Run sqlmap, hydra, or manual injection — not more nmap/gobuster."
                        ),
                        "recon_ratio": round(recon_ratio, 2),
                        "exploit_count": state.exploit_iterations,
                        "progress": round(progress, 2),
                    },
                )

    async def _check_shallow_exploitation(self, job_id: str, state: JobState) -> None:
        """
        Alert when findings exist but exploitation depth is shallow.
        (Found vuln but never actually exploited it.)
        """
        if not state.target_tracker:
            return
        if state.max_iterations <= 0:
            return

        progress = state.current_iteration / state.max_iterations
        if progress < 0.4:
            return  # Too early

        # Check if there are findings with no exploitation
        if state.last_findings_total < SHALLOW_EXPLOIT_MIN_FINDINGS:
            return

        shallow_targets = state.target_tracker.get_shallow_targets()
        if not shallow_targets:
            return

        # Only alert if we've been exploiting but shallowly
        if state.exploit_iterations < 2:
            return  # Recon stagnation handles this case

        if self._cooldown_ok(state, "shallow_exploitation", time.time()):
            target_names = [t["target"] for t in shallow_targets[:3]]
            await self._emit_alert(
                job_id,
                "shallow_exploitation",
                {
                    "message": (
                        f"Found {state.last_findings_total} vulnerabilities but exploitation "
                        f"is shallow. Targets {', '.join(target_names)} have findings but "
                        f"were never exploited (only recon phase seen)."
                    ),
                    "directive": (
                        f"DEEPEN EXPLOITATION. You found vulnerabilities on "
                        f"{', '.join(target_names)} but never exploited them. "
                        f"Go back and exploit: dump data, get a shell, extract credentials. "
                        f"Finding a vuln without proving exploitation is incomplete."
                    ),
                    "shallow_targets": shallow_targets,
                    "total_findings": state.last_findings_total,
                },
            )

    # -----------------------------------------------------------------------
    # Phase 2: Resource Monitoring Integration
    # -----------------------------------------------------------------------

    async def _register_container_for_monitoring(self, job_id: str, state: JobState) -> None:
        """Register the Kali container for resource monitoring."""
        if not self._resource_monitor:
            return
        try:
            container_id = await self.redis.get(f"job:{job_id}:kali_container")
            container_name = await self.redis.get(f"job:{job_id}:kali_container_name")
            target_id = container_id or container_name
            if target_id:
                state.kali_container_id = target_id
                self._resource_monitor.track_container(job_id, target_id)
                logger.info("container_registered_for_monitoring",
                            job_id=job_id, container_id=target_id[:12] if target_id else "")
        except Exception as e:
            logger.debug("container_registration_failed", job_id=job_id, error=str(e))

    async def _log_resource_usage(self, job_id: str, state: JobState, iteration: int) -> None:
        """Log resource usage at periodic intervals."""
        if not self._resource_monitor:
            return
        stats = self._resource_monitor.get_memory_stats(job_id)
        if stats:
            await self._emit_event(
                job_id,
                "resource_usage",
                _utc_now_iso(),
                "",
                {
                    "iteration": iteration,
                    **stats,
                },
            )
            logger.info(
                "resource_usage",
                job_id=job_id,
                iteration=iteration,
                usage_mb=stats.get("usage_mb"),
                limit_mb=stats.get("limit_mb"),
                usage_fraction=stats.get("usage_fraction"),
                trend=stats.get("trend"),
            )

    async def _handle_resource_alert(self, job_id: str, alert: ResourceAlert) -> None:
        """Callback from ResourceMonitor when a threshold is crossed."""
        await self._emit_event(
            job_id,
            "resource_alert",
            _utc_now_iso(),
            "",
            alert.to_dict(),
        )

        # For high-severity alerts, emit as supervisor alerts and take action
        if alert.severity in ("high", "critical"):
            state = self._get_state(job_id)

            await self._emit_alert(
                job_id,
                "resource_warning",
                {
                    "alert_type": alert.alert_type,
                    "message": alert.message,
                    "directive": alert.directive,
                    "severity": alert.severity,
                    "snapshot": alert.snapshot.to_dict(),
                    "trend": alert.trend,
                },
            )

            # Emergency: send CANCEL
            if alert.alert_type == "mem_emergency":
                try:
                    await self.redis.publish(f"job:{job_id}:control", "CANCEL")
                    logger.warn("emergency_cancel_sent", job_id=job_id,
                                usage_fraction=alert.snapshot.usage_fraction)
                except Exception as e:
                    logger.error("emergency_cancel_failed", job_id=job_id, error=str(e))

            # Save & reset: write directive
            elif alert.alert_type == "mem_reset" and alert.directive:
                decision = {
                    "action": "force_pivot",
                    "severity": "high",
                    "hint": alert.directive,
                    "next_strategy": "Save findings and reduce memory usage immediately.",
                    "rationale": alert.message,
                    "model": "resource_monitor",
                }
                await self._maybe_execute_action(job_id, state, decision)

            # Context trim: write hint
            elif alert.alert_type == "mem_trim" and alert.directive:
                decision = {
                    "action": "hint",
                    "severity": "medium",
                    "hint": alert.directive,
                    "next_strategy": "Reduce memory footprint to prevent OOM.",
                    "rationale": alert.message,
                    "model": "resource_monitor",
                }
                await self._maybe_execute_action(job_id, state, decision)

    # -----------------------------------------------------------------------
    # Event emission
    # -----------------------------------------------------------------------

    async def _emit_event(self, job_id: str, event_type: str, msg_ts: str, line: str, data: Dict) -> None:
        payload = {
            "job_id": job_id,
            "event_type": event_type,
            "timestamp": msg_ts,
            "line": line,
            "data": data,
        }

        channel = f"job:{job_id}:supervisor_events"
        list_key = f"job:{job_id}:supervisor_log"

        try:
            await self.redis.publish(channel, json.dumps(payload))
            await self.redis.rpush(list_key, json.dumps(payload))
            await self.redis.ltrim(list_key, -EVENT_LIST_MAX, -1)
            await self.redis.expire(list_key, EVENT_TTL_SECONDS)
        except Exception as e:
            logger.warn("emit_event_failed", error=str(e), job_id=job_id, event_type=event_type)

    async def _emit_alert(self, job_id: str, alert_type: str, data: Dict) -> None:
        await self._emit_event(
            job_id,
            "alert",
            _utc_now_iso(),
            "",
            {"alert_type": alert_type, **data},
        )
        state = self._get_state(job_id)
        await self._schedule_audit(job_id, state, alert_type, data)

    # -----------------------------------------------------------------------
    # Audit scheduling and execution
    # -----------------------------------------------------------------------

    async def _schedule_audit(self, job_id: str, state: JobState, alert_type: str, data: Dict) -> None:
        if not await self._is_supervisor_enabled(job_id):
            return
        if not self._should_audit(state, alert_type):
            return
        state.audit_count += 1
        state.last_audit_ts = time.time()
        logger.info("audit_scheduled", job_id=job_id, alert_type=alert_type)
        asyncio.create_task(self._run_audit(job_id, alert_type, data, state))

    def _should_audit(self, state: JobState, alert_type: str) -> bool:
        if SUPERVISOR_LLM_MODE == "disabled":
            return False
        if alert_type not in SUPERVISOR_AUDIT_ALERT_TYPES:
            return False
        if state.audit_count >= SUPERVISOR_AUDIT_MAX_PER_JOB:
            if state.last_audit_ts and time.time() - state.last_audit_ts < 300:
                return False
        if state.last_audit_ts and time.time() - state.last_audit_ts < SUPERVISOR_AUDIT_COOLDOWN_SECONDS:
            return False
        return True

    # -----------------------------------------------------------------------
    # Original alert methods (preserved)
    # -----------------------------------------------------------------------

    async def _maybe_emit_noop_alert(self, job_id: str, state: JobState, cmd: str, now: float) -> None:
        if not _is_noop_command(cmd):
            state.noop_count = 0
            state.noop_since_ts = 0
            return

        if state.noop_since_ts == 0:
            state.noop_since_ts = now
            state.noop_count = 1
        else:
            if now - state.noop_since_ts > ALERT_STALL_SECONDS:
                state.noop_since_ts = now
                state.noop_count = 1
            else:
                state.noop_count += 1

        if state.noop_count >= ALERT_NOOP_THRESHOLD:
            if self._cooldown_ok(state, "noop", now):
                await self._emit_alert(
                    job_id,
                    "noop_loop",
                    {
                        "count": state.noop_count,
                        "command": cmd,
                    },
                )

    async def _maybe_emit_repeat_alert(self, job_id: str, state: JobState, cmd: str, now: float) -> None:
        if not cmd:
            return
        repeats = list(state.recent_commands).count(cmd)
        if repeats >= ALERT_REPEAT_THRESHOLD and self._cooldown_ok(state, "repeat", now):
            await self._emit_alert(
                job_id,
                "repeated_command",
                {
                    "command": cmd,
                    "count": repeats,
                    "recent": list(state.recent_commands),
                },
            )

    async def _maybe_emit_scan_loop_alert(self, job_id: str, state: JobState, cmd: str, now: float) -> None:
        """Detect enumeration-heavy loops with no exploitation progress."""
        if not cmd:
            return
        intent = _classify_cmd_intent(cmd)
        if intent:
            state.recent_cmd_classes.append(intent)
            if intent == "exploit":
                state.last_exploit_ts = now

        window = list(state.recent_cmd_classes)
        if len(window) < SCAN_LOOP_MIN_COMMANDS:
            return

        enum_ratio = window.count("enum") / max(len(window), 1)
        if enum_ratio < SCAN_LOOP_ENUM_RATIO:
            return

        if state.last_exploit_ts and now - state.last_exploit_ts < SCAN_LOOP_EXPLOIT_GRACE_SECONDS:
            return

        if self._cooldown_ok(state, "scan_loop", now):
            await self._emit_alert(
                job_id,
                "scan_loop",
                {
                    "enum_ratio": round(enum_ratio, 2),
                    "window": len(window),
                    "recent": window[-10:],
                },
            )

    def _cooldown_ok(self, state: JobState, key: str, now: float) -> bool:
        last = state.last_alert_ts.get(key, 0)
        if now - last >= ALERT_COOLDOWN_SECONDS:
            state.last_alert_ts[key] = now
            return True
        return False

    # -----------------------------------------------------------------------
    # Supervisor enabled / provider checks
    # -----------------------------------------------------------------------

    async def _is_supervisor_enabled(self, job_id: Optional[str] = None) -> bool:
        now = time.time()
        if job_id:
            cached = self._job_enabled_cache.get(job_id)
            if cached and now - cached[1] < SUPERVISOR_ENABLED_CACHE_SECONDS:
                return cached[0]
            try:
                val = await self.redis.get(f"job:{job_id}:supervisor_enabled")
                if val is not None:
                    enabled = str(val).strip().lower() in ("1", "true", "yes", "on")
                    self._job_enabled_cache[job_id] = (enabled, now)
                    logger.debug("supervisor_enabled_check", job_id=job_id, source="per_job_redis", enabled=enabled)
                    return enabled
            except Exception as e:
                if cached:
                    logger.warn("supervisor_enabled_redis_fail_using_stale_cache", job_id=job_id, error=str(e), stale_value=cached[0])
                    return cached[0]
                logger.warn("supervisor_enabled_redis_fail_no_cache", job_id=job_id, error=str(e))
        if now - self._enabled_cache_ts < SUPERVISOR_ENABLED_CACHE_SECONDS:
            return self._enabled_cache_value
        enabled = SUPERVISOR_ENABLED_DEFAULT
        try:
            val = await self.redis.get("supervisor:enabled")
            if val is not None:
                enabled = str(val).strip().lower() in ("1", "true", "yes", "on")
        except Exception:
            pass
        self._enabled_cache_value = enabled
        self._enabled_cache_ts = now
        return enabled

    async def _get_supervisor_provider_override(self, job_id: Optional[str] = None) -> Optional[str]:
        """Read supervisor LLM provider from Redis (cached ~5s), fall back to env var."""
        now = time.time()
        if job_id:
            cached = self._job_provider_cache.get(job_id)
            if cached and now - cached[1] < SUPERVISOR_ENABLED_CACHE_SECONDS:
                return cached[0]
            try:
                val = await self.redis.get(f"job:{job_id}:supervisor_provider")
                if val and str(val).strip():
                    provider = str(val).strip()
                    self._job_provider_cache[job_id] = (provider, now)
                    return provider
            except Exception:
                pass
        if now - self._provider_cache_ts < SUPERVISOR_ENABLED_CACHE_SECONDS:
            return self._provider_cache_value
        provider = SUPERVISOR_LLM_PROVIDER_OVERRIDE or None
        try:
            val = await self.redis.get("supervisor:provider")
            if val and str(val).strip():
                provider = str(val).strip()
        except Exception:
            pass
        self._provider_cache_value = provider
        self._provider_cache_ts = now
        return provider

    # -----------------------------------------------------------------------
    # Audit execution
    # -----------------------------------------------------------------------

    async def _run_audit(self, job_id: str, alert_type: str, data: Dict, state: JobState) -> None:
        try:
            context = await self._build_audit_context(job_id, state)
            try:
                decision = await self._audit_decision(job_id, alert_type, data, context)
            except Exception as e:
                status = None
                try:
                    import httpx  # type: ignore
                    if isinstance(e, httpx.HTTPStatusError) and e.response is not None:
                        status = e.response.status_code
                except Exception:
                    status = None
                if status in (429, 500, 502, 503, 504):
                    logger.warn("audit_llm_unavailable_fallback_stub", job_id=job_id, alert_type=alert_type, status=status)
                    decision = self._stub_audit(alert_type, data, context)
                    decision["tier"] = "stub"
                    decision["note"] = f"llm_unavailable_{status}"
                else:
                    raise
            if not decision:
                return
            logger.info(
                "audit_decision",
                job_id=job_id,
                alert_type=alert_type,
                action=decision.get("action"),
                severity=decision.get("severity"),
                model=decision.get("model"),
                tier=decision.get("tier"),
            )
            await self._emit_event(
                job_id,
                "audit",
                _utc_now_iso(),
                "",
                {
                    "alert_type": alert_type,
                    "decision": decision,
                    "context": context,
                },
            )
            await self._maybe_execute_action(job_id, state, decision)
        except Exception as e:
            logger.warn("audit_failed", job_id=job_id, alert_type=alert_type, error=str(e))

    async def _build_audit_context(self, job_id: str, state: JobState) -> Dict:
        list_key = f"job:{job_id}:supervisor_log"
        try:
            raw_events = await self.redis.lrange(list_key, -10, -1)
        except Exception:
            raw_events = []
        events = []
        for item in raw_events:
            try:
                events.append(json.loads(item))
            except Exception:
                continue

        stats_key = f"job:{job_id}:live_stats"
        try:
            stats = await self.redis.hgetall(stats_key)
        except Exception:
            stats = {}

        context = {
            "recent_commands": list(state.recent_commands),
            "current_iteration": state.current_iteration,
            "max_iterations": state.max_iterations,
            "last_progress_seconds": int(time.time() - (state.last_progress_ts or state.last_output_ts or time.time())),
            "live_stats": stats,
            "recent_events": events,
        }

        # Phase 2: Add enhanced context
        context["phase_distribution"] = {
            "recon": state.recon_iterations,
            "exploit": state.exploit_iterations,
            "post_exploit": state.post_exploit_iterations,
            "total": state.total_iterations_with_commands,
        }

        if state.exploit_scorer:
            context["exploit_quality"] = state.exploit_scorer.get_quality_report()

        if state.target_tracker:
            context["target_coverage"] = {
                "coverage_ratio": round(state.target_tracker.coverage_ratio(), 2),
                "touched_targets": sorted(state.target_tracker.touched_targets),
                "untouched_targets": sorted(state.target_tracker.untouched_targets),
                "shallow_targets": state.target_tracker.get_shallow_targets(),
            }

        if state.loop_detector:
            context["loop_detection"] = {
                "total_commands": state.loop_detector.total_commands,
                "total_noops": state.loop_detector.total_noops,
                "consecutive_noops": state.loop_detector.consecutive_noops,
                "tool_distribution": state.loop_detector.get_tool_distribution(),
            }

        if self._resource_monitor:
            mem_stats = self._resource_monitor.get_memory_stats(job_id)
            if mem_stats:
                context["resource_usage"] = mem_stats

        return context

    async def _audit_decision(self, job_id: str, alert_type: str, data: Dict, context: Dict) -> Dict:
        if SUPERVISOR_LLM_MODE == "stub":
            decision = self._stub_audit(alert_type, data, context)
            decision["tier"] = "stub"
            return decision

        if SUPERVISOR_LLM_MODE != "live":
            return {}

        provider = SUPERVISOR_LLM_PROVIDER
        if provider not in {"internal_proxy", "proxy", "internal"}:
            if not SUPERVISOR_LLM_API_KEY or not SUPERVISOR_TRIAGE_MODEL:
                logger.warn("audit_missing_llm_config", job_id=job_id)
                decision = self._stub_audit(alert_type, data, context)
                decision["tier"] = "stub"
                decision["note"] = "Missing LLM config; fell back to stub"
                return decision

        system_prompt = (
            "You are a supervising safety/quality agent for an autonomous penetration testing worker. "
            "You see alerts about stalling, repeated commands, scan/enumeration loops, lack of progress, "
            "low exploit quality, resource pressure, target neglect, or shallow exploitation. "
            "Return a STRICT JSON object with keys: action, severity, rationale, hint, next_strategy, confidence. "
            "Allowed actions: ignore, hint, force_pivot, inject_command, reset, stop. "
            "Do not include any extra text outside JSON."
        )

        user_prompt = json.dumps(
            {
                "job_id": job_id,
                "alert_type": alert_type,
                "alert_data": data,
                "context": context,
            },
            indent=2,
        )

        decision = await self._call_llm(SUPERVISOR_TRIAGE_MODEL, system_prompt, user_prompt, job_id)
        decision = self._normalize_decision(decision, model=SUPERVISOR_TRIAGE_MODEL, tier="triage")

        if SUPERVISOR_ESCALATION_MODEL:
            if decision.get("severity") in {"high", "critical"} or decision.get("action") in {"reset", "stop"}:
                escalation = await self._call_llm(SUPERVISOR_ESCALATION_MODEL, system_prompt, user_prompt, job_id)
                escalation = self._normalize_decision(
                    escalation, model=SUPERVISOR_ESCALATION_MODEL, tier="escalation"
                )
                if escalation:
                    decision = escalation

        return decision

    async def _call_llm(self, model: str, system_prompt: str, user_prompt: str, job_id: Optional[str] = None) -> Dict:
        provider = SUPERVISOR_LLM_PROVIDER

        if provider in {"internal_proxy", "proxy", "internal"}:
            if not SUPERVISOR_LLM_PROXY_TOKEN:
                logger.warn("missing_proxy_token")
                return self._stub_audit("missing_proxy_token", {}, {})
            if not SUPERVISOR_LLM_API_BASE:
                logger.warn("missing_proxy_base")
                return self._stub_audit("missing_proxy_base", {}, {})

            headers = {
                "X-LLM-Proxy-Token": SUPERVISOR_LLM_PROXY_TOKEN,
                "Content-Type": "application/json",
            }
            payload = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": SUPERVISOR_LLM_MAX_TOKENS,
                "temperature": 0,
            }
            provider_override = await self._get_supervisor_provider_override(job_id)
            if provider_override:
                payload["provider_override"] = provider_override

            async with httpx.AsyncClient(timeout=SUPERVISOR_LLM_TIMEOUT_SECONDS) as client:
                resp = await client.post(SUPERVISOR_LLM_API_BASE, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()

            text = data.get("content", "") if isinstance(data, dict) else ""
            parsed = self._parse_llm_json(text)
            if isinstance(parsed, dict):
                if not parsed.get("model"):
                    provider_id = data.get("provider") if isinstance(data, dict) else ""
                    model_id = data.get("model") if isinstance(data, dict) else model
                    parsed["model"] = f"{provider_id}/{model_id}".strip("/")
            return parsed

        if provider != "anthropic":
            logger.warn("unsupported_llm_provider", provider=provider)
            return self._stub_audit("unsupported_provider", {}, {})

        headers = {
            "x-api-key": SUPERVISOR_LLM_API_KEY,
            "anthropic-version": SUPERVISOR_ANTHROPIC_VERSION,
            "content-type": "application/json",
        }
        payload = {
            "model": model,
            "max_tokens": SUPERVISOR_LLM_MAX_TOKENS,
            "temperature": 0,
            "system": system_prompt,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        }

        async with httpx.AsyncClient(timeout=SUPERVISOR_LLM_TIMEOUT_SECONDS) as client:
            resp = await client.post(f"{SUPERVISOR_LLM_API_BASE}/v1/messages", headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

        content = data.get("content", [])
        text = ""
        if isinstance(content, list) and content:
            text = content[0].get("text", "") if isinstance(content[0], dict) else str(content[0])
        elif isinstance(content, str):
            text = content

        parsed = self._parse_llm_json(text)
        if isinstance(parsed, dict) and not parsed.get("model"):
            parsed["model"] = model
        return parsed

    def _parse_llm_json(self, text: str) -> Dict:
        if not text:
            return {}
        text = text.strip()
        try:
            return json.loads(text)
        except Exception:
            start = text.find("{")
            end = text.rfind("}")
            if start >= 0 and end > start:
                try:
                    return json.loads(text[start : end + 1])
                except Exception:
                    return {}
        return {}

    def _normalize_decision(self, decision: Dict, model: str, tier: str) -> Dict:
        if not isinstance(decision, dict):
            return {}
        note = decision.get("note", "")
        if not decision.get("action") and not note:
            note = "llm_parse_failed"
        normalized = {
            "action": decision.get("action", "hint"),
            "severity": decision.get("severity", "medium"),
            "rationale": decision.get("rationale", ""),
            "hint": decision.get("hint", ""),
            "next_strategy": decision.get("next_strategy", ""),
            "confidence": decision.get("confidence", 0.5),
            "model": decision.get("model") or model,
            "tier": tier,
            "note": note,
        }
        return normalized

    def _stub_audit(self, alert_type: str, data: Dict, context: Dict) -> Dict:
        action = "hint"
        severity = "low"
        hint = "Change approach and avoid repeating noop commands."
        next_strategy = "Pick a different tool or target path; validate with evidence."

        if alert_type in {"stalled", "no_new_findings"}:
            action = "retry"
            severity = "medium"
            hint = "Progress stalled. Try a different recon or exploit path."
            next_strategy = "Switch tools; narrow scope; validate at least one vuln."
        elif alert_type in {"noop_loop", "repeated_command"}:
            action = "hint"
            severity = "medium"
            hint = "Stop repeating the same command. Try a distinct technique."
            next_strategy = "Choose an alternate tool or vector and proceed."
        elif alert_type == "stalling":
            action = "hint"
            severity = "medium"
            hint = "Agent claims done but has no evidence. Continue testing."
            next_strategy = "Validate findings with concrete proof."
        elif alert_type == "scan_loop":
            action = "hint"
            severity = "medium"
            hint = "Enumeration loop detected. Stop scanning and perform exploitation."
            next_strategy = "Run sqlmap --dump or attempt RCE/file upload; capture proof."

        # --- Phase 2: New alert type handlers ---
        elif alert_type == "loop_detected":
            action = "force_pivot"
            severity = data.get("severity", "high")
            directive = data.get("directive", "")
            hint = directive or "Command loop detected. STOP and try a completely different approach."
            next_strategy = "Switch to an untried tool or vulnerability class entirely."
        elif alert_type == "exploit_quality_low":
            action = "force_pivot"
            severity = "high"
            hint = data.get("directive", "Stop running scanners. Execute real exploitation attacks.")
            next_strategy = "Run sqlmap --dump, hydra brute-force, or manual injection with proof of exploitation."
        elif alert_type == "resource_warning":
            resource_severity = data.get("severity", "medium")
            if resource_severity == "critical":
                action = "stop"
                severity = "critical"
                hint = data.get("directive", "Memory critical. Save findings and stop.")
                next_strategy = "Save all findings to disk immediately."
            else:
                action = "hint"
                severity = "high"
                hint = data.get("directive", "Memory usage high. Reduce footprint.")
                next_strategy = "Kill background processes, clear temp files, use --batch flags."
        elif alert_type == "target_neglect":
            action = "force_pivot"
            severity = "medium"
            untouched = data.get("coverage", {}).get("untouched_targets", [])
            hint = f"Target coverage too low. Move to: {', '.join(untouched[:3])}"
            next_strategy = "Start with port scanning on the neglected target, then exploit findings."
        elif alert_type == "recon_stagnation":
            action = "force_pivot"
            severity = "high"
            hint = data.get("directive", "Too much recon. Transition to exploitation immediately.")
            next_strategy = "Pick the best vulnerability found so far and exploit it to completion."
        elif alert_type == "shallow_exploitation":
            action = "hint"
            severity = "medium"
            hint = data.get("directive", "Exploitation is too shallow. Deepen your attacks.")
            next_strategy = "Go back to targets with findings and prove exploitation with evidence."

        return {
            "action": action,
            "severity": severity,
            "rationale": f"Stub decision for alert {alert_type}",
            "hint": hint,
            "next_strategy": next_strategy,
            "confidence": 0.5,
            "model": "stub",
        }

    # -----------------------------------------------------------------------
    # Escalation ladder and action execution
    # -----------------------------------------------------------------------

    def _escalation_ladder_action(self, state: JobState, decision: Dict) -> str:
        """Fix #5: Escalation ladder — hint(x2) → force_pivot → inject_command → early_terminate.

        Returns the escalated action string based on how many actions have been taken.
        """
        base_action = decision.get("action", "hint").lower()
        hint_count = state.action_count

        if base_action == "stop":
            return "early_terminate"

        # Phase 2: Factor in severity — high severity alerts escalate faster
        severity = decision.get("severity", "medium").lower()
        if severity == "critical":
            if hint_count < 1:
                return "force_pivot"
            return "early_terminate"

        if severity == "high":
            if hint_count < 1:
                return "hint"
            elif hint_count < 2:
                return "force_pivot"
            elif hint_count < 3:
                return "inject_command"
            else:
                return "early_terminate"

        # Normal escalation
        if hint_count < 1:
            return "hint"
        elif hint_count < 2:
            return "force_pivot"
        elif hint_count < 4:
            return "inject_command"
        else:
            return "early_terminate"

    async def _maybe_execute_action(self, job_id: str, state: JobState, decision: Dict) -> None:
        if not SUPERVISOR_ACTIONS_ENABLED:
            logger.debug("escalation_blocked", job_id=job_id, reason="SUPERVISOR_ACTIONS_ENABLED=false")
            return
        if not await self._is_supervisor_enabled(job_id):
            logger.info("escalation_blocked", job_id=job_id, reason="supervisor_not_enabled", action_count=state.action_count)
            return
        if not decision:
            logger.debug("escalation_blocked", job_id=job_id, reason="empty_decision")
            return
        if state.action_count >= SUPERVISOR_ACTION_MAX_PER_JOB:
            logger.info("escalation_blocked", job_id=job_id, reason="action_count_max_reached", action_count=state.action_count, max=SUPERVISOR_ACTION_MAX_PER_JOB)
            return
        if state.last_action_ts and time.time() - state.last_action_ts < SUPERVISOR_ACTION_COOLDOWN_SECONDS:
            logger.debug("escalation_blocked", job_id=job_id, reason="cooldown", seconds_remaining=int(SUPERVISOR_ACTION_COOLDOWN_SECONDS - (time.time() - state.last_action_ts)))
            return

        action = self._escalation_ladder_action(state, decision)
        logger.info("escalation_ladder", job_id=job_id, raw_action=decision.get("action"), escalated_action=action, action_count=state.action_count)

        state.action_count += 1
        state.last_action_ts = time.time()
        await self._execute_action(job_id, action, decision)

    async def _execute_action(self, job_id: str, action: str, decision: Dict) -> None:
        result = {"action": action, "success": False, "detail": ""}

        if SUPERVISOR_ACTIONS_DRY_RUN:
            result["success"] = True
            result["detail"] = "dry_run"
            await self._emit_event(job_id, "action", _utc_now_iso(), "", result)
            return

        if action in ("stop", "early_terminate"):
            try:
                await self.redis.publish(f"job:{job_id}:control", "CANCEL")
                result["success"] = True
                result["detail"] = f"cancel_sent (escalation: {action})"
            except Exception as e:
                result["detail"] = f"cancel_failed: {e}"
            try:
                directive = {
                    "id": f"{job_id}-{int(time.time()*1000)}",
                    "timestamp": _utc_now_iso(),
                    "action": "early_terminate",
                    "severity": "critical",
                    "message": self._build_hint_message(decision),
                    "rationale": decision.get("rationale", ""),
                    "model": decision.get("model", ""),
                }
                await self._write_hint_to_container(job_id, directive)
            except Exception:
                pass
            await self._emit_event(job_id, "action", _utc_now_iso(), "", result)
            return

        try:
            directive = {
                "id": f"{job_id}-{int(time.time()*1000)}",
                "timestamp": _utc_now_iso(),
                "action": action,
                "severity": decision.get("severity", "medium"),
                "message": self._build_hint_message(decision),
                "rationale": decision.get("rationale", ""),
                "model": decision.get("model", ""),
            }
            await self._write_hint_to_container(job_id, directive)
            result["success"] = True
            result["detail"] = f"{action}_written"
        except Exception as e:
            result["detail"] = f"{action}_failed: {e}"

        await self._emit_event(job_id, "action", _utc_now_iso(), "", result)

    def _build_hint_message(self, decision: Dict) -> str:
        hint = decision.get("hint", "") or ""
        next_strategy = decision.get("next_strategy", "") or ""
        if hint and next_strategy:
            return f"{hint}\n\nNext strategy: {next_strategy}"
        return hint or next_strategy or "Adjust approach and continue."

    async def _write_hint_to_container(self, job_id: str, directive: Dict) -> None:
        if not self.docker_client:
            raise RuntimeError("Docker client unavailable")

        container_id = await self.redis.get(f"job:{job_id}:kali_container")
        container_name = await self.redis.get(f"job:{job_id}:kali_container_name")
        target_id = container_id or container_name
        if not target_id:
            raise RuntimeError("Missing kali container mapping for job")

        hint_path = SUPERVISOR_HINT_PATH_TEMPLATE.format(job_id=job_id)
        hint_dir = os.path.dirname(hint_path)
        payload = json.dumps(directive, ensure_ascii=True)

        heredoc = f"mkdir -p {shlex.quote(hint_dir)} && cat <<'EOF' >> {shlex.quote(hint_path)}\n{payload}\nEOF"
        container = self.docker_client.containers.get(target_id)
        exec_result = container.exec_run(cmd=["bash", "-lc", heredoc])
        if exec_result.exit_code != 0:
            raise RuntimeError(exec_result.output.decode(errors="replace"))

    # -----------------------------------------------------------------------
    # Periodic pollers
    # -----------------------------------------------------------------------

    async def _poll_live_stats(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(STATS_POLL_SECONDS)
                now = time.time()
                for job_id, state in list(self.states.items()):
                    if state.last_output_ts and now - state.last_output_ts > ACTIVE_WINDOW_SECONDS:
                        if self._resource_monitor:
                            self._resource_monitor.untrack_job(job_id)
                        self.states.pop(job_id, None)
                        self._job_enabled_cache.pop(job_id, None)
                        self._job_provider_cache.pop(job_id, None)
                        continue

                    stats_key = f"job:{job_id}:live_stats"
                    stats = await self.redis.hgetall(stats_key)
                    if not stats:
                        continue

                    total_findings = _safe_int(stats.get("total_findings"), state.last_findings_total)
                    if total_findings > state.last_findings_total:
                        state.last_findings_total = total_findings
                        state.last_findings_ts = now
                        state.last_progress_ts = now
                        await self._emit_event(
                            job_id,
                            "finding_update",
                            _utc_now_iso(),
                            "",
                            {"total_findings": total_findings},
                        )

                        # Phase 2: Track findings per target
                        if state.target_tracker:
                            # Try to associate findings with the last-touched target
                            recent_targets = state.target_tracker.touched_targets
                            if recent_targets:
                                # Attribute to most recently active target
                                for t, tp in state.target_tracker._targets.items():
                                    if tp.last_seen_iter == state.current_iteration:
                                        tp.finding_count += (total_findings - state.last_findings_total + (total_findings - state.last_findings_total))
                                        break

                    current_iter = _safe_int(stats.get("current_iteration"), state.current_iteration)
                    max_iter = _safe_int(stats.get("max_iterations"), state.max_iterations)
                    if current_iter and current_iter != state.current_iteration:
                        state.current_iteration = current_iter
                    if max_iter and max_iter != state.max_iterations:
                        state.max_iterations = max_iter
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("stats_poll_error", error=str(e))

    async def _alert_sweeper(self) -> None:
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(10)
                now = time.time()
                for job_id, state in list(self.states.items()):
                    if state.last_output_ts and now - state.last_output_ts > ACTIVE_WINDOW_SECONDS:
                        if self._resource_monitor:
                            self._resource_monitor.untrack_job(job_id)
                        self.states.pop(job_id, None)
                        self._job_enabled_cache.pop(job_id, None)
                        self._job_provider_cache.pop(job_id, None)
                        continue

                    last_progress = state.last_progress_ts or state.last_output_ts
                    if last_progress and now - last_progress > ALERT_STALL_SECONDS:
                        if self._cooldown_ok(state, "stall", now):
                            await self._emit_alert(
                                job_id,
                                "stalled",
                                {
                                    "seconds_since_progress": int(now - last_progress),
                                    "current_iteration": state.current_iteration,
                                    "max_iterations": state.max_iterations,
                                },
                            )

                    if state.last_findings_ts and now - state.last_findings_ts > FINDINGS_STALL_SECONDS:
                        if self._cooldown_ok(state, "findings", now):
                            await self._emit_alert(
                                job_id,
                                "no_new_findings",
                                {
                                    "seconds_since_findings": int(now - state.last_findings_ts),
                                    "total_findings": state.last_findings_total,
                                },
                            )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warn("alert_sweeper_error", error=str(e))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _run() -> None:
    supervisor = Supervisor()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(supervisor.stop()))
        except NotImplementedError:
            pass

    await supervisor.start()


if __name__ == "__main__":
    asyncio.run(_run())
