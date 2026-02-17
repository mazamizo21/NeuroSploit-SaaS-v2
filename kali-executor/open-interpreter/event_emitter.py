"""
Structured event emitter for dynamic_agent runtime updates.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class EventType:
    THINKING = "thinking"
    THINKING_CHUNK = "thinking_chunk"
    TOOL_START = "tool_start"
    TOOL_OUTPUT_CHUNK = "tool_output_chunk"
    TOOL_COMPLETE = "tool_complete"
    PHASE_UPDATE = "phase_update"
    TODO_UPDATE = "todo_update"
    APPROVAL_REQUEST = "approval_request"
    QUESTION_REQUEST = "question"
    RESPONSE = "response"
    EXECUTION_STEP = "execution_step"
    TASK_COMPLETE = "task_complete"
    ERROR = "error"
    STOPPED = "stopped"


class AgentEventEmitter:
    def __init__(self, redis_client=None, job_id: Optional[str] = None, websocket=None):
        self.redis = redis_client
        self.job_id = str(job_id) if job_id else ""
        self.websocket = websocket
        self.events_channel = f"job:{self.job_id}:events" if self.job_id else ""

    def _build_message(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": event_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "job_id": self.job_id,
        }

    def _publish(self, event_type: str, payload: Dict[str, Any]) -> None:
        msg = self._build_message(event_type, payload)

        if self.redis and self.events_channel:
            try:
                self.redis.publish(self.events_channel, json.dumps(msg, ensure_ascii=True))
            except Exception as exc:
                logger.warning("event_publish_failed job_id=%s type=%s error=%s", self.job_id, event_type, exc)

        if self.websocket:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self.websocket.send_json(msg))
            except Exception:
                pass

    def emit_thinking(self, iteration: int, phase: str, thought: str, reasoning: str = "") -> None:
        self._publish(EventType.THINKING, {
            "iteration": iteration,
            "phase": phase,
            "thought": thought,
            "reasoning": reasoning,
        })

    def emit_thinking_chunk(self, chunk: str) -> None:
        self._publish(EventType.THINKING_CHUNK, {"chunk": chunk})

    def emit_tool_start(self, tool_name: str, command: str, args: Optional[Dict[str, Any]] = None) -> None:
        self._publish(EventType.TOOL_START, {
            "tool_name": tool_name,
            "command": command,
            "args": args or {},
        })

    def emit_tool_output_chunk(self, tool_name: str, chunk: str, is_final: bool = False) -> None:
        self._publish(EventType.TOOL_OUTPUT_CHUNK, {
            "tool_name": tool_name,
            "chunk": chunk,
            "is_final": is_final,
        })

    def emit_tool_complete(
        self,
        tool_name: str,
        success: bool,
        output_summary: str,
        findings: Optional[List[str]] = None,
        next_steps: Optional[List[str]] = None,
    ) -> None:
        self._publish(EventType.TOOL_COMPLETE, {
            "tool_name": tool_name,
            "success": bool(success),
            "output_summary": (output_summary or "")[:2000],
            "findings": findings or [],
            "next_steps": next_steps or [],
        })

    def emit_phase_update(self, phase: str, iteration: int, attack_type: str = "general") -> None:
        self._publish(EventType.PHASE_UPDATE, {
            "phase": phase,
            "iteration": iteration,
            "attack_type": attack_type,
        })

    def emit_todo_update(self, todo_list: List[Dict[str, Any]]) -> None:
        self._publish(EventType.TODO_UPDATE, {"items": todo_list})

    def emit_approval_request(
        self,
        from_phase: str,
        to_phase: str,
        reason: str,
        planned_actions: Optional[List[str]] = None,
        risks: Optional[List[str]] = None,
    ) -> None:
        self._publish(EventType.APPROVAL_REQUEST, {
            "from_phase": from_phase,
            "to_phase": to_phase,
            "reason": reason,
            "planned_actions": planned_actions or [],
            "risks": risks or [],
        })

    def emit_question(
        self,
        question: str,
        context: str = "",
        format: str = "text",
        options: Optional[List[str]] = None,
        question_id: Optional[str] = None,
    ) -> None:
        qid = question_id or f"q-{int(datetime.now(timezone.utc).timestamp())}"
        self._publish(EventType.QUESTION_REQUEST, {
            "question_id": qid,
            "question": question,
            "context": context,
            "format": format,
            "options": options or [],
        })

    def emit_execution_step(self, step: Dict[str, Any]) -> None:
        self._publish(EventType.EXECUTION_STEP, step)

    def emit_response(self, answer: str, iteration: int, phase: str, complete: bool = False) -> None:
        self._publish(EventType.RESPONSE, {
            "answer": answer,
            "iteration": iteration,
            "phase": phase,
            "complete": bool(complete),
        })

    def emit_task_complete(self, message: str, phase: str, total_iterations: int) -> None:
        self._publish(EventType.TASK_COMPLETE, {
            "message": message,
            "final_phase": phase,
            "total_iterations": total_iterations,
        })

    def emit_error(self, message: str, recoverable: bool = True) -> None:
        self._publish(EventType.ERROR, {
            "message": message,
            "recoverable": bool(recoverable),
        })

    def emit_stopped(self, iteration: int, phase: str) -> None:
        self._publish(EventType.STOPPED, {
            "iteration": iteration,
            "phase": phase,
        })
