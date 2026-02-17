"""project_settings.py

Sprint 3: Job settings (per-job overrides) stored in Redis.

Design goals:
- Fail-open: if Redis is unavailable or the payload is malformed, continue with defaults.
- Safe allowlist: only a small set of non-secret runtime toggles are supported.
- Env integration: dynamic_agent.py reads many feature flags from os.environ; we therefore
  optionally apply settings as environment variables early during agent initialization.

Redis key:
- job:{job_id}:settings  (JSON object)

NOTE: This module intentionally does NOT support secrets (API keys/tokens/passwords).
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


DEFAULT_AGENT_SETTINGS: Dict[str, Any] = {
    # ── LLM Configuration ──
    "LLM_MODEL": "auto",  # 'auto' = use LLM_PROFILES system, or specific model name
    "INFORMATIONAL_SYSTEM_PROMPT": "",  # Custom prompt appended during RECON phase
    "EXPLOITATION_SYSTEM_PROMPT": "",   # Custom prompt for EXPLOITATION phase
    "POST_EXPLOITATION_SYSTEM_PROMPT": "",  # Custom prompt for POST_EXPLOIT phase
    "LLM_THINKING_ENABLED": False,

    # ── Feature Flags ──
    "USE_STRUCTURED_OUTPUT": False,
    "TOOL_USAGE_TRACKER_ENABLED": True,
    "EXPLOITATION_INJECTOR_ENABLED": True,
    "TOOL_PHASE_GATE_ENABLED": True,
    "TOOL_RECOMMENDER_ENABLED": True,

    # ── Approval Gates (default OFF for autonomous operation) ──
    "REQUIRE_APPROVAL_FOR_EXPLOITATION": False,
    "REQUIRE_APPROVAL_FOR_POST_EXPLOITATION": False,

    # ── Phase Configuration ──
    "ACTIVATE_POST_EXPLOIT_PHASE": True,  # Toggle post-exploitation phase
    "PHASE_MODE": "stateful",  # 'stateful' or 'stateless'

    # ── Payload Direction ──
    "LHOST": "",       # Attacker IP for reverse shells (empty = auto-detect)
    "LPORT": 0,        # Listener port for reverse shells (0 = not set)
    "BIND_PORT_ON_TARGET": 0,  # Port for bind shells (0 = not set)
    "PAYLOAD_USE_HTTPS": False,  # Prefer reverse_https over reverse_tcp

    # ── Agent Limits ──
    "MAX_ITERATIONS": 100,
    "EXECUTION_TRACE_MEMORY_STEPS": 100,
    "TOOL_OUTPUT_MAX_CHARS": 20000,
    "AUTO_COMPLETE_IDLE_ITERATIONS": 50,
    "AUTO_COMPLETE_MIN_ITERATIONS": 50,

    # ── Brute Force ──
    "BRUTE_FORCE_MAX_WORDLIST_ATTEMPTS": 3,
    "BRUTEFORCE_SPEED": 5,  # 1-5 (hydra -t equivalent)

    # ── Scan Settings ──
    "SCAN_RATE_LIMIT": 0,       # 0 = no limit, >0 = max requests per second
    "SCAN_TIMEOUT": 300,         # Default timeout per scan command (seconds)
    "VULN_SEVERITY_FILTER": "critical,high,medium",  # Nuclei severity focus

    # ── LLM Parse ──
    "LLM_PARSE_MAX_RETRIES": 3,

    # ── Knowledge Graph (Neo4j) ──
    "KNOWLEDGE_GRAPH_ENABLED": True,
    "KG_INJECT_EVERY": 5,
    "KG_SUMMARY_MAX_CHARS": 1800,
    "NEO4J_URI": "bolt://neo4j:7687",
    "NEO4J_USER": "neo4j",
    "NEO4J_PASSWORD": "",
    "CYPHER_MAX_RETRIES": 3,

    # ── Logging ──
    "LOG_MAX_MB": 10,
    "LOG_BACKUP_COUNT": 5,
}


ALLOWED_JOB_SETTING_KEYS = set(DEFAULT_AGENT_SETTINGS.keys())

_settings: Optional[Dict[str, Any]] = None
_overrides: Optional[Dict[str, Any]] = None


def _coerce_value(key: str, value: Any) -> Any:
    """Coerce values to match DEFAULT_AGENT_SETTINGS types."""

    default = DEFAULT_AGENT_SETTINGS.get(key)

    if isinstance(default, bool):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return default

    if isinstance(default, int):
        try:
            return int(value)
        except Exception:
            return default

    if isinstance(default, str):
        try:
            return str(value)
        except Exception:
            return default

    return value


def _sanitize_overrides(overrides: Any) -> Dict[str, Any]:
    if not isinstance(overrides, dict):
        return {}

    sanitized: Dict[str, Any] = {}
    for raw_key, raw_val in overrides.items():
        if raw_key is None:
            continue
        key = str(raw_key).strip().upper()
        if key not in ALLOWED_JOB_SETTING_KEYS:
            continue
        sanitized[key] = _coerce_value(key, raw_val)

    # Bounds for numeric fields
    if "KG_INJECT_EVERY" in sanitized:
        try:
            sanitized["KG_INJECT_EVERY"] = max(1, min(int(sanitized["KG_INJECT_EVERY"]), 50))
        except Exception:
            sanitized["KG_INJECT_EVERY"] = DEFAULT_AGENT_SETTINGS["KG_INJECT_EVERY"]

    if "KG_SUMMARY_MAX_CHARS" in sanitized:
        try:
            sanitized["KG_SUMMARY_MAX_CHARS"] = max(
                200, min(int(sanitized["KG_SUMMARY_MAX_CHARS"]), 20000)
            )
        except Exception:
            sanitized["KG_SUMMARY_MAX_CHARS"] = DEFAULT_AGENT_SETTINGS["KG_SUMMARY_MAX_CHARS"]

    if "AUTO_COMPLETE_IDLE_ITERATIONS" in sanitized:
        try:
            sanitized["AUTO_COMPLETE_IDLE_ITERATIONS"] = max(
                0, min(int(sanitized["AUTO_COMPLETE_IDLE_ITERATIONS"]), 5000)
            )
        except Exception:
            sanitized["AUTO_COMPLETE_IDLE_ITERATIONS"] = DEFAULT_AGENT_SETTINGS["AUTO_COMPLETE_IDLE_ITERATIONS"]

    if "AUTO_COMPLETE_MIN_ITERATIONS" in sanitized:
        try:
            sanitized["AUTO_COMPLETE_MIN_ITERATIONS"] = max(
                0, min(int(sanitized["AUTO_COMPLETE_MIN_ITERATIONS"]), 5000)
            )
        except Exception:
            sanitized["AUTO_COMPLETE_MIN_ITERATIONS"] = DEFAULT_AGENT_SETTINGS["AUTO_COMPLETE_MIN_ITERATIONS"]

    return sanitized


def load_overrides_from_redis(redis_client, job_id: str) -> Dict[str, Any]:
    """Load *only* the allowlisted overrides from Redis (best-effort).

    This does NOT merge defaults. Use load_settings_from_redis() to get the
    resolved settings (defaults + overrides).

    Semantics:
    - If Redis key is missing/unreadable/malformed -> return {} (no overrides)
    - If Redis key exists -> return sanitized allowlisted overrides
    """

    global _overrides

    if not redis_client or not job_id:
        _overrides = {}
        return {}

    key = f"job:{job_id}:settings"

    try:
        raw = redis_client.get(key)
    except Exception as e:
        logger.warning("job_settings_redis_get_failed", extra={"job_id": job_id, "error": str(e)})
        _overrides = {}
        return {}

    if not raw:
        _overrides = {}
        return {}

    try:
        parsed = json.loads(raw)
    except Exception as e:
        logger.warning(
            "job_settings_json_parse_failed",
            extra={"job_id": job_id, "error": str(e)},
        )
        _overrides = {}
        return {}

    overrides = _sanitize_overrides(parsed)
    _overrides = dict(overrides)
    return overrides


def load_settings_from_redis(redis_client, job_id: str) -> Dict[str, Any]:
    """Load job-specific settings from Redis (best-effort).

    Args:
        redis_client: redis client instance (sync) supporting .get(key)
        job_id: job id string

    Returns:
        Full settings dict: DEFAULT_AGENT_SETTINGS merged with sanitized overrides.
    """

    global _settings

    settings = dict(DEFAULT_AGENT_SETTINGS)
    overrides = load_overrides_from_redis(redis_client, job_id)
    settings.update(overrides)

    _settings = settings
    return settings


def get_setting(key: str, default: Any = None) -> Any:
    """Get a single setting value."""

    if not key:
        return default

    settings = _settings if isinstance(_settings, dict) else DEFAULT_AGENT_SETTINGS
    return settings.get(str(key).strip().upper(), default)


def get_settings() -> Dict[str, Any]:
    """Get the current resolved settings."""

    settings = _settings if isinstance(_settings, dict) else DEFAULT_AGENT_SETTINGS
    return dict(settings)


def apply_settings_to_env(settings: Dict[str, Any], *, override: bool = True) -> None:
    """Apply allowlisted settings to os.environ.

    This is used to integrate job settings with code paths that read feature flags
    via os.getenv(...).

    Args:
        settings: resolved settings dict.
        override: if False, do not overwrite existing env vars.
    """

    if not isinstance(settings, dict):
        return

    for key in ALLOWED_JOB_SETTING_KEYS:
        if key not in settings:
            continue
        if not override and key in os.environ:
            continue

        val = settings.get(key)
        if isinstance(val, bool):
            os.environ[key] = "true" if val else "false"
        else:
            os.environ[key] = str(val)
