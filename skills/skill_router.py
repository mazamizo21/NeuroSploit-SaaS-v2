"""
Skill Router
Selects relevant skills based on job phase, target type, and available evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Any

from .skill_loader import Skill


DEFAULT_PHASE_CATEGORY_MAP: Dict[str, List[str]] = {
    "RECON": ["reconnaissance"],
    "VULN_SCAN": ["scanning"],
    "EXPLOIT": ["exploitation"],
    "LATERAL": [
        "credential_access",
        "privilege_escalation",
        "lateral_movement",
        "persistence",
        "defense_evasion",
        "discovery",
        "collection",
        "exfiltration",
        "impact",
        "analysis",
    ],
    "FULL": [
        "reconnaissance",
        "scanning",
        "exploitation",
        "credential_access",
        "privilege_escalation",
        "lateral_movement",
        "persistence",
        "defense_evasion",
        "discovery",
        "collection",
        "exfiltration",
        "impact",
        "analysis",
        "reporting",
    ],
    "POST_EXPLOIT": [
        "credential_access",
        "privilege_escalation",
        "lateral_movement",
        "persistence",
        "defense_evasion",
        "discovery",
        "collection",
        "exfiltration",
        "impact",
        "analysis",
    ],
    "REPORT": ["reporting"],
}


@dataclass
class SkillSelection:
    phase: str
    target_type: str
    skills: List[Skill]


class SkillRouter:
    """Deterministic skill router with optional evidence gating."""

    def __init__(self, phase_map: Optional[Dict[str, List[str]]] = None):
        self.phase_map = phase_map or DEFAULT_PHASE_CATEGORY_MAP

    def select(
        self,
        skills: List[Skill],
        phase: str,
        target_type: str,
        evidence: Optional[Dict[str, Any]] = None,
        service_hints: Optional[List[str]] = None,
        max_skills: int = 3,
    ) -> SkillSelection:
        phase = (phase or "").upper()
        target_type = (target_type or "lab").lower()
        categories = self.phase_map.get(phase, [])
        service_hints = [s.lower() for s in (service_hints or [])]

        phase_candidates: List[Skill] = []
        service_candidates: List[Skill] = []

        for skill in skills:
            if skill.target_types and target_type not in [t.lower() for t in skill.target_types]:
                continue
            if not self._passes_prereqs(skill, evidence or {}, target_type):
                continue

            is_service = (skill.category == "service")
            if is_service and self._matches_service(skill, service_hints):
                service_candidates.append(skill)
                continue

            if skill.phase and skill.phase.upper() != phase and skill.category not in categories:
                continue
            if categories and skill.category not in categories and (skill.phase or "").upper() != phase:
                continue
            phase_candidates.append(skill)

        # Sort candidates by priority (desc), then by id for stability
        phase_candidates.sort(key=lambda s: (-int(s.priority), s.id))
        service_candidates.sort(key=lambda s: (-int(s.priority), s.id))

        # Service-first selection when service hints exist
        if max_skills <= 0:
            selected = service_candidates + phase_candidates
        elif service_candidates and service_hints:
            # Reserve at least one slot for a phase skill when possible
            service_limit = min(len(service_candidates), max_skills)
            if phase_candidates and max_skills > 1:
                service_limit = min(service_limit, max_skills - 1)
            selected = service_candidates[:service_limit]
            remaining = max_skills - len(selected)
            if remaining > 0:
                selected.extend(phase_candidates[:remaining])
        else:
            combined = phase_candidates + service_candidates
            selected = combined[:max_skills]
        return SkillSelection(phase=phase, target_type=target_type, skills=selected)

    def _passes_prereqs(self, skill: Skill, evidence: Dict[str, Any], target_type: str) -> bool:
        if not skill.prerequisites:
            return True
        # Lab targets: keep skills available even if prereqs not yet satisfied
        if (target_type or "").lower() == "lab":
            return True
        if not evidence:
            # No evidence context yet; allow skill selection
            return True
        # If prerequisites are specified, require at least one to be present in evidence
        for prereq in skill.prerequisites:
            if prereq in evidence:
                return True
        return False

    def format_plan(self, selection: SkillSelection) -> str:
        lines = [
            "# SKILL ROUTER PLAN",
            f"Phase: {selection.phase}",
            f"Target Type: {selection.target_type}",
        ]
        if not selection.skills:
            lines.append("No skills matched; proceed with core methodology and strict scoping.")
            return "\n".join(lines)

        lines.append("Selected Skills:")
        for skill in selection.skills:
            line = f"- {skill.name} ({skill.id}) [category: {skill.category}, priority: {skill.priority}]"
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def _matches_service(skill: Skill, service_hints: List[str]) -> bool:
        if not service_hints:
            return False
        tags = [t.lower() for t in (skill.tags or [])]
        for hint in service_hints:
            if hint in tags:
                return True
            if hint and hint in skill.id.lower():
                return True
        return False
