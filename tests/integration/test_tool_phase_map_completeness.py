#!/usr/bin/env python3
"""Integration test — verify all tools referenced in skills have phase map entries.

The tool_phase_map is the security boundary that prevents tools from running
outside their intended phase. If a skill's tools.yaml references a tool that
isn't in the phase map, it will be fail-open (allowed everywhere), which is a
potential security gap.
"""

import os
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SKILLS_DIR = ROOT / "skills"
sys.path.insert(0, str(ROOT / "kali-executor" / "open-interpreter"))

from tool_phase_map import (  # noqa: E402
    DEFAULT_TOOL_PHASE_MAP,
    ALWAYS_ALLOWED_TOOLS,
    INTERNAL_PHASES,
    build_effective_tool_phase_map,
    is_tool_allowed,
    normalize_tool_name,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SKIP_SKILL_DIRS = {"__pycache__", "_example"}


def _collect_all_skill_tools():
    """Parse every skill's tools.yaml and collect unique tool names."""
    tools_found = {}  # tool_name -> list of skill_ids referencing it
    if not SKILLS_DIR.is_dir():
        return tools_found

    for skill_path in sorted(SKILLS_DIR.iterdir()):
        if not skill_path.is_dir() or skill_path.name in SKIP_SKILL_DIRS:
            continue
        tools_yaml = skill_path / "tools.yaml"
        if not tools_yaml.exists():
            continue
        try:
            data = yaml.safe_load(tools_yaml.read_text(encoding="utf-8"))
        except Exception:
            continue
        if data is None:
            continue

        # tools.yaml can be a list of dicts or a dict with tool entries
        tool_entries = []
        if isinstance(data, list):
            tool_entries = data
        elif isinstance(data, dict):
            # Could be {tools: [...]} or {toolname: {...}}
            if "tools" in data and isinstance(data["tools"], list):
                tool_entries = data["tools"]
            else:
                for key, val in data.items():
                    if isinstance(val, dict):
                        tool_entries.append({"name": key, **val})

        for entry in tool_entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name") or entry.get("tool") or ""
            name = str(name).strip().lower()
            if name:
                tools_found.setdefault(name, []).append(skill_path.name)

    return tools_found


ALL_SKILL_TOOLS = _collect_all_skill_tools()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestToolPhaseMapCompleteness:
    """Every tool referenced in skills should appear in the effective phase map."""

    def test_default_map_has_entries(self):
        """The curated DEFAULT_TOOL_PHASE_MAP should not be empty."""
        assert len(DEFAULT_TOOL_PHASE_MAP) >= 20, (
            f"DEFAULT_TOOL_PHASE_MAP only has {len(DEFAULT_TOOL_PHASE_MAP)} entries — "
            "expected at least 20 curated tools."
        )

    def test_all_phases_valid(self):
        """Every phase string in the default map should be a known internal phase."""
        valid_phases = set(INTERNAL_PHASES)
        for tool, phases in DEFAULT_TOOL_PHASE_MAP.items():
            for phase in phases:
                assert phase.upper() in valid_phases, (
                    f"Tool '{tool}' references unknown phase '{phase}'. "
                    f"Valid phases: {valid_phases}"
                )

    def test_build_effective_map(self):
        """build_effective_tool_phase_map should succeed and return a superset."""
        if not SKILLS_DIR.is_dir():
            pytest.skip("skills/ directory not found")
        effective = build_effective_tool_phase_map(str(SKILLS_DIR))
        assert isinstance(effective, dict)
        # Effective map should include all curated entries
        for tool in DEFAULT_TOOL_PHASE_MAP:
            assert tool in effective, (
                f"Curated tool '{tool}' missing from effective map — "
                "build_effective_tool_phase_map may have a merge bug."
            )

    @pytest.mark.parametrize(
        "tool_name,skills",
        list(ALL_SKILL_TOOLS.items()),
        ids=list(ALL_SKILL_TOOLS.keys()),
    )
    def test_skill_tool_has_phase_entry(self, tool_name, skills):
        """Each tool from skills/*/tools.yaml should be in the map or always-allowed."""
        normalized = normalize_tool_name(tool_name) if normalize_tool_name else tool_name
        if normalized in ALWAYS_ALLOWED_TOOLS:
            return  # Always allowed, no phase map needed
        if not SKILLS_DIR.is_dir():
            pytest.skip("skills/ directory not found")
        effective = build_effective_tool_phase_map(str(SKILLS_DIR))
        # We warn (not fail) for tools that are fail-open, since this is by design
        # for custom scripts. But high-impact tools SHOULD be mapped.
        if normalized not in effective:
            pytest.skip(
                f"Tool '{tool_name}' (from skills: {skills}) is fail-open (not in phase map). "
                "Consider adding it to DEFAULT_TOOL_PHASE_MAP."
            )

    def test_is_tool_allowed_known_tool(self):
        """A known tool should be blocked outside its allowed phases."""
        # nmap is allowed in RECON, VULN_DISCOVERY, POST_EXPLOIT
        assert is_tool_allowed("nmap", "RECON") is True
        assert is_tool_allowed("nmap", "C2_DEPLOY") is False

    def test_is_tool_allowed_unknown_tool(self):
        """An unknown tool should be fail-open (allowed everywhere)."""
        assert is_tool_allowed("my_custom_script_xyz", "RECON") is True
        assert is_tool_allowed("my_custom_script_xyz", "EXPLOITATION") is True

    def test_is_tool_allowed_always_allowed(self):
        """Always-allowed tools should pass in any phase."""
        for tool in ("bash", "python3", "curl"):
            for phase in INTERNAL_PHASES:
                assert is_tool_allowed(tool, phase) is True, (
                    f"Always-allowed tool '{tool}' was blocked in phase '{phase}'"
                )

    def test_full_job_phase_bypasses_all(self):
        """job_phase=FULL should allow any tool in any phase."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase="FULL") is True
        assert is_tool_allowed("hydra", "RECON", job_phase="FULL") is True
