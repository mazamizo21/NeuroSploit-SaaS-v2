"""kali-executor/open-interpreter/approval_gate.py

Sprint 3: Approval gate system for TazoSploit.

Integrates with existing WebSocket/Redis to add blocking approval flows
for phase transitions and dangerous commands.

Design goals:
- Non-blocking poll loop (agent checks each iteration, no async blocking)
- Redis-backed for API-based approval (WebSocket not required)
- Timeout defaults to abort (fail-safe)
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class ApprovalGate:
    """Manages approval requests via Redis (+ optional WebSocket)."""

    def __init__(
        self,
        redis_client: Any = None,
        job_id: Optional[str] = None,
        websocket: Any = None,
        timeout: int = 300,
    ):
        self.redis = redis_client
        self.job_id = job_id
        self.websocket = websocket
        self.timeout = timeout  # seconds
        self.pending: Optional[Dict] = None
        self._deadline: float = 0.0

    # ── Request ─────────────────────────────────────────────────

    def request_approval(
        self,
        request_type: str,
        details: Dict,
    ) -> str:
        """Create an approval request. Returns request_id.

        Args:
            request_type: 'phase_transition' or 'dangerous_command'
            details: {from_phase, to_phase, reason, planned_actions, risks, ...}
        """
        request_id = f"{self.job_id}-{int(time.time())}"
        self.pending = {
            "request_id": request_id,
            "type": request_type,
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._deadline = time.time() + self.timeout

        # Store in Redis so the API/WebSocket handler can read it
        if self.redis and self.job_id:
            try:
                self.redis.set(
                    f"job:{self.job_id}:pending_approval",
                    json.dumps(self.pending),
                    ex=self.timeout,
                )
            except Exception as exc:
                logger.warning("approval_gate_redis_set_failed err=%s", exc)

        logger.info(
            "approval_requested type=%s request_id=%s",
            request_type,
            request_id,
        )
        return request_id

    # ── Poll (non-blocking) ────────────────────────────────────

    def check_response(self) -> Optional[Dict]:
        """Non-blocking check for an approval response.

        Returns:
            None if still waiting.
            {'decision': 'approve'|'modify'|'abort', 'modification': str|None}
            if a response is available or the request timed out.
        """
        if not self.pending:
            return None

        # Timeout check
        if time.time() > self._deadline:
            logger.warning("approval_request_timed_out request_id=%s", self.pending.get("request_id"))
            self._cleanup()
            return {"decision": "abort", "modification": None}

        if not self.redis or not self.job_id:
            return None

        try:
            raw = self.redis.get(f"job:{self.job_id}:approval_response")
        except Exception as exc:
            logger.warning("approval_gate_redis_get_failed err=%s", exc)
            return None

        if not raw:
            return None

        try:
            response = json.loads(raw)
        except Exception:
            return None

        # Match request_id if present
        if response.get("request_id") and response["request_id"] != self.pending.get("request_id"):
            return None  # stale response

        self._cleanup()
        logger.info(
            "approval_response_received decision=%s",
            response.get("decision", "unknown"),
        )
        return {
            "decision": response.get("decision", "abort"),
            "modification": response.get("modification"),
        }

    # ── Helpers ─────────────────────────────────────────────────

    @property
    def is_pending(self) -> bool:
        return self.pending is not None

    def _cleanup(self) -> None:
        """Remove pending state and Redis keys."""
        if self.redis and self.job_id:
            try:
                self.redis.delete(f"job:{self.job_id}:pending_approval")
                self.redis.delete(f"job:{self.job_id}:approval_response")
            except Exception:
                pass
        self.pending = None
        self._deadline = 0.0
