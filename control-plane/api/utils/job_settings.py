"""control-plane/api/utils/job_settings.py

Per-job runtime settings stored in Redis.

Redis key:
  job:{job_id}:settings

Design goals:
- Safe allowlist: only a small set of non-secret runtime toggles are supported.
- Type-safe coercion + bounds for numeric knobs.
- Stdlib-only module so unit tests can import this without FastAPI/SQLAlchemy.

NOTE: This module intentionally does NOT support secrets (API keys/tokens/passwords).
"""

from __future__ import annotations

from typing import Any, Dict, Optional


JOB_SETTINGS_ALLOWED_KEYS = {
    # Feature flags
    "USE_STRUCTURED_OUTPUT",
    "TOOL_USAGE_TRACKER_ENABLED",
    "EXPLOITATION_INJECTOR_ENABLED",
    "TOOL_PHASE_GATE_ENABLED",
    # Approval gates
    "REQUIRE_APPROVAL_FOR_EXPLOITATION",
    "REQUIRE_APPROVAL_FOR_POST_EXPLOITATION",
    # KG toggles
    "KNOWLEDGE_GRAPH_ENABLED",
    "KG_INJECT_EVERY",
    "KG_SUMMARY_MAX_CHARS",
    # Safe runtime knobs
    "AUTO_COMPLETE_IDLE_ITERATIONS",
    "AUTO_COMPLETE_MIN_ITERATIONS",
    "LLM_THINKING_ENABLED",
}


JOB_SETTINGS_BOOL_KEYS = {
    "USE_STRUCTURED_OUTPUT",
    "TOOL_USAGE_TRACKER_ENABLED",
    "EXPLOITATION_INJECTOR_ENABLED",
    "TOOL_PHASE_GATE_ENABLED",
    "REQUIRE_APPROVAL_FOR_EXPLOITATION",
    "REQUIRE_APPROVAL_FOR_POST_EXPLOITATION",
    "KNOWLEDGE_GRAPH_ENABLED",
    "LLM_THINKING_ENABLED",
}


JOB_SETTINGS_INT_KEYS = {
    "KG_INJECT_EVERY",
    "KG_SUMMARY_MAX_CHARS",
    "AUTO_COMPLETE_IDLE_ITERATIONS",
    "AUTO_COMPLETE_MIN_ITERATIONS",
}


def coerce_job_setting_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return None


def sanitize_job_settings(raw: Any) -> Dict[str, Any]:
    """Allowlist + type-safe coercion for per-job settings stored in Redis."""

    if not isinstance(raw, dict):
        return {}

    out: Dict[str, Any] = {}
    for raw_key, raw_val in raw.items():
        if raw_key is None:
            continue
        key = str(raw_key).strip().upper()
        if key not in JOB_SETTINGS_ALLOWED_KEYS:
            continue

        if key in JOB_SETTINGS_BOOL_KEYS:
            coerced = coerce_job_setting_bool(raw_val)
            if coerced is not None:
                out[key] = coerced
            continue

        if key in JOB_SETTINGS_INT_KEYS:
            try:
                out[key] = int(raw_val)
            except Exception:
                continue
            continue

        # Future-proof: ignored today (we only allow bool/int keys).

    # Bounds for numeric knobs
    if "KG_INJECT_EVERY" in out:
        out["KG_INJECT_EVERY"] = max(1, min(int(out["KG_INJECT_EVERY"]), 50))
    if "KG_SUMMARY_MAX_CHARS" in out:
        out["KG_SUMMARY_MAX_CHARS"] = max(200, min(int(out["KG_SUMMARY_MAX_CHARS"]), 20000))
    if "AUTO_COMPLETE_IDLE_ITERATIONS" in out:
        # 0 disables auto-complete; otherwise clamp to a reasonable upper bound.
        out["AUTO_COMPLETE_IDLE_ITERATIONS"] = max(0, min(int(out["AUTO_COMPLETE_IDLE_ITERATIONS"]), 5000))
    if "AUTO_COMPLETE_MIN_ITERATIONS" in out:
        out["AUTO_COMPLETE_MIN_ITERATIONS"] = max(0, min(int(out["AUTO_COMPLETE_MIN_ITERATIONS"]), 5000))

    return out


def job_settings_ttl_seconds(timeout_seconds: Optional[int]) -> int:
    """Return Redis TTL for job settings.

    Rules:
    - At least 24h (so long-running jobs don't lose settings mid-run)
    - Otherwise: timeout + 1h buffer
    - Cap at 7 days
    """

    try:
        base = int(timeout_seconds or 3600)
    except Exception:
        base = 3600

    ttl = max(base + 3600, 86400)
    return min(ttl, 604800)
