"""kali-executor/open-interpreter/structured_output.py

Sprint 1: Structured ReAct output (optional).

This is an *additive* feature behind a runtime flag (see `dynamic_agent.py`).
When enabled, the agent will ask the LLM to emit a single JSON object describing
its decision. Parsing is best-effort and falls back to the legacy regex-based
```bash``` extraction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import re
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ActionType(str, Enum):
    EXECUTE_COMMAND = "execute_command"
    EXECUTE_SCRIPT = "execute_script"
    TRANSITION_PHASE = "transition_phase"
    COMPLETE = "complete"
    ASK_USER = "ask_user"


class TodoStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    BLOCKED = "blocked"


@dataclass
class TodoItem:
    description: str
    status: str = TodoStatus.PENDING.value
    priority: str = "medium"  # high, medium, low


@dataclass
class AgentDecision:
    """Structured output from each agent turn (best-effort; no external deps)."""

    thought: str = ""
    reasoning: str = ""
    action: str = ActionType.EXECUTE_COMMAND.value

    # Command execution
    command: Optional[str] = None
    command_type: Optional[str] = None  # bash|python|msfconsole
    tool_name: Optional[str] = None
    expected_outcome: Optional[str] = None
    fallback_command: Optional[str] = None

    # Phase transition
    target_phase: Optional[str] = None
    transition_reason: Optional[str] = None

    # Completion
    completion_reason: Optional[str] = None

    # User question
    question: Optional[str] = None

    # Todo list
    updated_todo: List[TodoItem] = field(default_factory=list)

    # Output analysis
    output_analysis: Optional[str] = None
    findings: List[str] = field(default_factory=list)

    # MITRE mapping
    mitre_technique: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentDecision":
        if not isinstance(data, dict):
            return cls()

        def _as_str(key: str, default: Optional[str] = None) -> Optional[str]:
            val = data.get(key, default)
            if val is None:
                return None
            try:
                return str(val)
            except Exception:
                return default

        action = (_as_str("action") or ActionType.EXECUTE_COMMAND.value).strip()
        valid_actions = {a.value for a in ActionType}
        if action not in valid_actions:
            action = ActionType.EXECUTE_COMMAND.value

        # updated_todo
        todo_items: List[TodoItem] = []
        raw_todo = data.get("updated_todo")
        if isinstance(raw_todo, list):
            valid_status = {s.value for s in TodoStatus}
            for item in raw_todo[:50]:
                if isinstance(item, str) and item.strip():
                    todo_items.append(TodoItem(description=item.strip()))
                    continue
                if not isinstance(item, dict):
                    continue
                desc = str(item.get("description") or "").strip()
                if not desc:
                    continue
                status = str(item.get("status") or TodoStatus.PENDING.value).strip()
                if status not in valid_status:
                    status = TodoStatus.PENDING.value
                prio = str(item.get("priority") or "medium").strip().lower() or "medium"
                if prio not in ("high", "medium", "low"):
                    prio = "medium"
                todo_items.append(TodoItem(description=desc, status=status, priority=prio))

        # findings
        findings: List[str] = []
        raw_findings = data.get("findings")
        if isinstance(raw_findings, list):
            for f in raw_findings[:50]:
                if f is None:
                    continue
                try:
                    findings.append(str(f)[:500])
                except Exception:
                    continue

        return cls(
            thought=(_as_str("thought") or "")[:2000],
            reasoning=(_as_str("reasoning") or "")[:2000],
            action=action,
            command=_as_str("command"),
            command_type=(_as_str("command_type") or None),
            tool_name=_as_str("tool_name"),
            expected_outcome=_as_str("expected_outcome"),
            fallback_command=_as_str("fallback_command"),
            target_phase=_as_str("target_phase"),
            transition_reason=_as_str("transition_reason"),
            completion_reason=_as_str("completion_reason"),
            question=_as_str("question"),
            updated_todo=todo_items,
            output_analysis=_as_str("output_analysis"),
            findings=findings,
            mitre_technique=_as_str("mitre_technique"),
        )


STRUCTURED_OUTPUT_PROMPT = """
OUTPUT FORMAT OVERRIDE (STRUCTURED MODE):
You MUST respond with a SINGLE JSON object and NOTHING ELSE (no markdown).

Schema (example):
{
  \"thought\": \"...\",
  \"reasoning\": \"...\",
  \"action\": \"execute_command\",
  \"command\": \"nmap -sV -F -n <target>\",
  \"command_type\": \"bash\",
  \"tool_name\": \"nmap\",
  \"expected_outcome\": \"Identify open ports + service versions\",
  \"fallback_command\": \"masscan -p1-1000 <target> --rate 2000\",
  \"target_phase\": null,
  \"transition_reason\": null,
  \"completion_reason\": null,
  \"question\": null,
  \"updated_todo\": [],
  \"output_analysis\": null,
  \"findings\": [],
  \"mitre_technique\": null
}

Valid action values:
- execute_command
- execute_script
- transition_phase
- complete
- ask_user
""".strip()


def parse_agent_decision(raw_text: str) -> Optional[AgentDecision]:
    """Parse best-effort AgentDecision from an LLM response."""

    raw_text = str(raw_text or "")
    json_str = _extract_json(raw_text)
    if json_str:
        try:
            data = json.loads(json_str)
            if isinstance(data, dict):
                return AgentDecision.from_dict(data)
        except Exception as exc:
            logger.warning("structured_output_json_parse_failed error=%s", exc)

    # Backward compat: synthesize a decision from free-form output.
    return _parse_freeform(raw_text)


def _extract_json(text: str) -> Optional[str]:
    """Extract a JSON object from text (handles ```json fences and raw JSON)."""

    # ```json ... ```
    fenced = re.search(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE)
    if fenced:
        candidate = (fenced.group(1) or "").strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            return candidate

    # Balanced-brace scan for the first JSON object.
    start = text.find("{")
    if start < 0:
        return None

    depth = 0
    in_str = False
    esc = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue

        if ch == '"':
            in_str = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : idx + 1]

    return None


def _parse_freeform(text: str) -> Optional[AgentDecision]:
    """Backward compatible parse: extract a single fenced code block."""

    bash_blocks = re.findall(r"```(?:bash|sh|shell)?\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE)
    if bash_blocks:
        cmd = (bash_blocks[0] or "").strip()
        if cmd:
            return AgentDecision(
                thought=text[:500],
                reasoning="Parsed from free-form output (bash fence)",
                action=ActionType.EXECUTE_COMMAND.value,
                command=cmd,
                command_type="bash",
            )

    py_blocks = re.findall(r"```python\s*\n(.*?)\n```", text, re.DOTALL | re.IGNORECASE)
    if py_blocks:
        code = (py_blocks[0] or "").strip()
        if code:
            return AgentDecision(
                thought=text[:500],
                reasoning="Parsed from free-form output (python fence)",
                action=ActionType.EXECUTE_SCRIPT.value,
                command=code,
                command_type="python",
            )

    return None


def decision_to_executables(decision: AgentDecision) -> List[tuple[str, str]]:
    """Translate an AgentDecision into the legacy `(exec_type, content)` list."""

    if not decision or not decision.command:
        return []
    exec_type = (decision.command_type or "bash").strip().lower() or "bash"
    # Keep dynamic_agent compatibility (expects 'bash'|'python'|'msfconsole' strings).
    if exec_type not in {"bash", "python", "msfconsole"}:
        exec_type = "bash"
    return [(exec_type, str(decision.command))]
