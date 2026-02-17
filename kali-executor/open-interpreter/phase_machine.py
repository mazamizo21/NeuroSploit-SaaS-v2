"""kali-executor/open-interpreter/phase_machine.py

Sprint 1: Phase State Machine (hard gates / deterministic tracking).

This module is intentionally small and dependency-light so it can be used inside
`dynamic_agent.py` without pulling in the full control-plane stack.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional


class Phase(str, Enum):
    RECON = "RECON"
    VULN_DISCOVERY = "VULN_DISCOVERY"
    EXPLOITATION = "EXPLOITATION"
    C2_DEPLOY = "C2_DEPLOY"
    POST_EXPLOIT = "POST_EXPLOIT"


PHASE_ORDER: List[Phase] = [
    Phase.RECON,
    Phase.VULN_DISCOVERY,
    Phase.EXPLOITATION,
    Phase.C2_DEPLOY,
    Phase.POST_EXPLOIT,
]


JOB_PHASE_TO_INTERNAL: Dict[str, Phase] = {
    # Control-plane / UI phases
    "RECON": Phase.RECON,
    "VULN_SCAN": Phase.VULN_DISCOVERY,
    "VULN_DISCOVERY": Phase.VULN_DISCOVERY,
    "EXPLOIT": Phase.EXPLOITATION,
    "EXPLOITATION": Phase.EXPLOITATION,
    "C2_DEPLOY": Phase.C2_DEPLOY,
    "POST_EXPLOIT": Phase.POST_EXPLOIT,
    "LATERAL": Phase.POST_EXPLOIT,
    "FULL": Phase.RECON,
    "REPORT": Phase.POST_EXPLOIT,
}


def normalize_phase(value: str) -> str:
    return str(value or "").strip().upper()


def resolve_start_phase(
    *,
    phase_gate_start: Optional[str] = None,
    effective_phase: Optional[str] = None,
    job_phase: Optional[str] = None,
) -> Phase:
    """Resolve the agent's internal starting phase.

    Priority:
      1) explicit PHASE_GATE_START (internal override)
      2) EFFECTIVE_PHASE (execution-plane override)
      3) JOB_PHASE (control-plane job config)
      4) default RECON
    """

    for raw in (phase_gate_start, effective_phase, job_phase):
        key = normalize_phase(raw)
        if not key:
            continue
        mapped = JOB_PHASE_TO_INTERNAL.get(key)
        if mapped:
            return mapped
    return Phase.RECON


@dataclass
class PhaseTransition:
    from_phase: str
    to_phase: str
    reason: str
    timestamp: str
    iteration: Optional[int] = None


@dataclass
class PhaseState:
    current: Phase = Phase.RECON
    history: List[PhaseTransition] = field(default_factory=list)
    iteration_counts: Dict[str, int] = field(
        default_factory=lambda: {
            Phase.RECON.value: 0,
            Phase.VULN_DISCOVERY.value: 0,
            Phase.EXPLOITATION.value: 0,
            Phase.C2_DEPLOY.value: 0,
            Phase.POST_EXPLOIT.value: 0,
        }
    )

    def can_transition_to(self, target: Phase) -> bool:
        if target == self.current:
            return True
        try:
            current_idx = PHASE_ORDER.index(self.current)
            target_idx = PHASE_ORDER.index(target)
        except ValueError:
            return False
        # Forward-only by default.
        return target_idx >= current_idx

    def transition(self, target: Phase, reason: str, iteration: Optional[int] = None) -> bool:
        if not self.can_transition_to(target):
            return False
        if target == self.current:
            return True

        self.history.append(
            PhaseTransition(
                from_phase=self.current.value,
                to_phase=target.value,
                reason=str(reason or "").strip(),
                timestamp=datetime.utcnow().isoformat() + "Z",
                iteration=iteration,
            )
        )
        self.current = target
        return True

    def increment_iteration(self) -> int:
        key = self.current.value
        self.iteration_counts[key] = int(self.iteration_counts.get(key, 0)) + 1
        return int(self.iteration_counts[key])
