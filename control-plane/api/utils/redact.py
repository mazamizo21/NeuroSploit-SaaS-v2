"""Redaction utilities.

Goal: prevent accidental leakage of secrets (API keys, bearer tokens) into:
- Job results stored in DB
- Findings fields
- WebSocket and polling output

This is defense-in-depth and should be combined with not injecting provider keys
into untrusted execution environments.
"""

from __future__ import annotations

import re
from typing import Any


# Common key/token patterns
_REPLACEMENTS: list[tuple[re.Pattern, str]] = [
    # Generic secret keys (OpenAI/Anthropic/etc.)
    (re.compile(r"\bsk-[A-Za-z0-9_-]{10,}\b"), "sk-***REDACTED***"),
    # Bearer tokens
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]{10,}\b"), "Bearer ***REDACTED***"),
    # Zhipu/GLM style key seen in .env: <32hex>.<token>
    (re.compile(r"\b[a-f0-9]{32}\.[A-Za-z0-9_-]{10,}\b", re.IGNORECASE), "***REDACTED_ZHIPU_KEY***"),
    # x-api-key style headers
    (re.compile(r"(?i)(x-api-key\s*[:=]\s*)([^\s]+)"), r"\1***REDACTED***"),
    # Explicit env var prints
    (re.compile(r"(?i)(ANTHROPIC_TOKEN|ANTHROPIC_API_KEY|OPENAI_API_KEY|ZHIPU_API_KEY|CLAUDE_API_KEY)\s*[:=]\s*([^\s]+)"), r"\1=***REDACTED***"),
]


def redact_text(text: str) -> str:
    if not text:
        return text
    out = text
    for pat, repl in _REPLACEMENTS:
        out = pat.sub(repl, out)
    return out


def redact_obj(obj: Any) -> Any:
    """Recursively redact secrets in nested JSON-like structures."""
    if obj is None:
        return None
    if isinstance(obj, str):
        return redact_text(obj)
    if isinstance(obj, bytes):
        try:
            return redact_text(obj.decode(errors="replace"))
        except Exception:
            return "***REDACTED_BYTES***"
    if isinstance(obj, list):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, tuple):
        return [redact_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: redact_obj(v) for k, v in obj.items()}
    return obj
