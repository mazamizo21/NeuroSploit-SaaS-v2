"""
Redis-backed guidance queue for live operator instructions.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class GuidanceQueue:
    def __init__(self, redis_client=None, job_id: Optional[str] = None):
        self.redis = redis_client
        self.job_id = str(job_id) if job_id else ""
        self.queue_key = f"job:{self.job_id}:guidance" if self.job_id else ""
        self.history_key = f"job:{self.job_id}:guidance_history" if self.job_id else ""
        self._local_queue: List[Dict[str, str]] = []

    def push(self, message: str, source: str = "user") -> int:
        entry = {
            "message": str(message or "").strip(),
            "source": source,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if not entry["message"]:
            return 0

        if self.redis and self.queue_key:
            try:
                size = int(self.redis.rpush(self.queue_key, json.dumps(entry, ensure_ascii=True)) or 0)
                self.redis.expire(self.queue_key, 86400)
                if self.history_key:
                    self.redis.rpush(self.history_key, json.dumps(entry, ensure_ascii=True))
                    self.redis.ltrim(self.history_key, -100, -1)
                    self.redis.expire(self.history_key, 86400)
                return size
            except Exception as exc:
                logger.warning("guidance_push_redis_failed job_id=%s error=%s", self.job_id, exc)

        self._local_queue.append(entry)
        return len(self._local_queue)

    def drain(self) -> List[str]:
        messages: List[str] = []

        if self.redis and self.queue_key:
            try:
                while True:
                    raw = self.redis.lpop(self.queue_key)
                    if raw is None:
                        break
                    try:
                        obj = json.loads(raw)
                    except Exception:
                        obj = {"message": str(raw)}
                    msg = str(obj.get("message", "")).strip()
                    if msg:
                        messages.append(msg)
            except Exception as exc:
                logger.warning("guidance_drain_redis_failed job_id=%s error=%s", self.job_id, exc)

        if not messages and self._local_queue:
            messages = [str(item.get("message", "")).strip() for item in self._local_queue if item.get("message")]
            self._local_queue.clear()

        return messages

    def format_for_injection(self, messages: List[str]) -> Optional[str]:
        cleaned = [m.strip() for m in messages if isinstance(m, str) and m.strip()]
        if not cleaned:
            return None

        lines = ["USER GUIDANCE (received during execution):"]
        for idx, msg in enumerate(cleaned, start=1):
            lines.append(f"{idx}. {msg}")
        lines.append("")
        lines.append("Acknowledge this guidance and adapt your next action.")
        return "\n".join(lines)

    def get_history(self, limit: int = 50) -> List[Dict[str, str]]:
        if not self.redis or not self.history_key:
            return []
        try:
            raw_items = self.redis.lrange(self.history_key, max(-int(limit or 50), -500), -1)
            parsed: List[Dict[str, str]] = []
            for raw in raw_items:
                try:
                    obj = json.loads(raw)
                    if isinstance(obj, dict):
                        parsed.append(obj)
                except Exception:
                    continue
            return parsed
        except Exception:
            return []
