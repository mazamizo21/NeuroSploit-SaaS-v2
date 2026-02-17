#!/usr/bin/env python3
"""Integration test — verify tool_recommender returns results for every phase.

The tool recommender is a 3-layer funnel:
  Layer 1: Phase Gate  (tool_phase_map)
  Layer 2: Context Recommender (tool_recommender)
  Layer 3: Comfort Zone Breaker (tool_usage_tracker)

This test verifies Layer 2 produces non-empty recommendations for every
internal phase with reasonable context scenarios.
"""

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kali-executor" / "open-interpreter"))

from tool_recommender import (  # noqa: E402
    AgentContext,
    ServiceType,
    TargetOS,
    ToolRecommendation,
    VulnType,
    get_recommendations,
    format_recommendations_for_prompt,
    RECOMMENDATION_RULES,
)

# ---------------------------------------------------------------------------
# Phase scenarios — one realistic AgentContext per phase
# ---------------------------------------------------------------------------

PHASE_SCENARIOS = {
    "RECON": AgentContext(
        phase="RECON",
        target_ip="10.0.1.1",
        target_url="http://10.0.1.1",
        services_found=[],
        iteration=1,
    ),
    "RECON_with_http": AgentContext(
        phase="RECON",
        target_ip="10.0.1.1",
        target_url="http://10.0.1.1",
        services_found=[ServiceType.HTTP],
        iteration=5,
    ),
    "RECON_with_smb": AgentContext(
        phase="RECON",
        target_ip="10.0.1.1",
        services_found=[ServiceType.SMB],
        iteration=3,
    ),
    "RECON_with_ssh": AgentContext(
        phase="RECON",
        target_ip="10.0.1.1",
        services_found=[ServiceType.SSH],
        iteration=3,
    ),
    "VULN_DISCOVERY": AgentContext(
        phase="VULN_DISCOVERY",
        target_ip="10.0.1.1",
        target_url="http://10.0.1.1",
        services_found=[ServiceType.HTTP, ServiceType.SSH],
        iteration=10,
    ),
    "VULN_DISCOVERY_windows": AgentContext(
        phase="VULN_DISCOVERY",
        target_ip="10.0.1.1",
        target_os=TargetOS.WINDOWS,
        services_found=[ServiceType.SMB, ServiceType.RDP],
        iteration=12,
    ),
    "EXPLOITATION_sqli": AgentContext(
        phase="EXPLOITATION",
        target_ip="10.0.1.1",
        target_url="http://10.0.1.1/login",
        services_found=[ServiceType.HTTP],
        vulns_found=[{"type": VulnType.SQLI, "title": "SQL injection in login"}],
        iteration=20,
    ),
    "EXPLOITATION_rce": AgentContext(
        phase="EXPLOITATION",
        target_ip="10.0.1.1",
        target_url="http://10.0.1.1",
        services_found=[ServiceType.HTTP],
        vulns_found=[{"type": VulnType.RCE, "title": "RCE via deserialization"}],
        iteration=20,
    ),
    "EXPLOITATION_xss": AgentContext(
        phase="EXPLOITATION",
        target_ip="10.0.1.1",
        target_url="http://10.0.1.1",
        services_found=[ServiceType.HTTP],
        vulns_found=[{"type": VulnType.XSS, "title": "Reflected XSS"}],
        iteration=20,
    ),
    "EXPLOITATION_no_vulns": AgentContext(
        phase="EXPLOITATION",
        target_ip="10.0.1.1",
        services_found=[ServiceType.HTTP, ServiceType.SSH],
        vulns_found=[],
        has_creds=False,
        iteration=25,
    ),
    "EXPLOITATION_creds_windows": AgentContext(
        phase="EXPLOITATION",
        target_ip="10.0.1.1",
        target_os=TargetOS.WINDOWS,
        services_found=[ServiceType.SMB, ServiceType.WINRM],
        has_creds=True,
        iteration=22,
    ),
    "EXPLOITATION_creds_linux": AgentContext(
        phase="EXPLOITATION",
        target_ip="10.0.1.1",
        target_os=TargetOS.LINUX,
        services_found=[ServiceType.SSH],
        has_creds=True,
        iteration=22,
    ),
    "POST_EXPLOIT_windows": AgentContext(
        phase="POST_EXPLOIT",
        target_ip="10.0.1.1",
        target_os=TargetOS.WINDOWS,
        has_shell=True,
        has_creds=True,
        iteration=30,
    ),
    "POST_EXPLOIT_linux": AgentContext(
        phase="POST_EXPLOIT",
        target_ip="10.0.1.1",
        target_os=TargetOS.LINUX,
        has_shell=True,
        iteration=30,
    ),
    "POST_EXPLOIT_need_c2": AgentContext(
        phase="POST_EXPLOIT",
        target_ip="10.0.1.1",
        target_os=TargetOS.LINUX,
        has_shell=True,
        has_c2=False,
        iteration=32,
    ),
    "C2_DEPLOY_windows": AgentContext(
        phase="C2_DEPLOY",
        target_ip="10.0.1.1",
        target_os=TargetOS.WINDOWS,
        has_shell=True,
        iteration=35,
    ),
    "C2_DEPLOY_linux": AgentContext(
        phase="C2_DEPLOY",
        target_ip="10.0.1.1",
        target_os=TargetOS.LINUX,
        has_shell=True,
        iteration=35,
    ),
    "C2_DEPLOY_unknown": AgentContext(
        phase="C2_DEPLOY",
        target_ip="10.0.1.1",
        target_os=TargetOS.UNKNOWN,
        has_shell=True,
        iteration=35,
    ),
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestToolRecommenderCoverage:
    """Verify the recommender produces results for every realistic scenario."""

    @pytest.mark.parametrize(
        "scenario_name,context",
        list(PHASE_SCENARIOS.items()),
        ids=list(PHASE_SCENARIOS.keys()),
    )
    def test_recommendations_not_empty(self, scenario_name, context):
        recs = get_recommendations(context, max_results=5)
        assert len(recs) > 0, (
            f"Scenario '{scenario_name}' (phase={context.phase}) returned 0 recommendations. "
            "The agent would have no tool guidance."
        )

    @pytest.mark.parametrize(
        "scenario_name,context",
        list(PHASE_SCENARIOS.items()),
        ids=list(PHASE_SCENARIOS.keys()),
    )
    def test_recommendations_are_valid(self, scenario_name, context):
        recs = get_recommendations(context, max_results=5)
        for rec in recs:
            assert isinstance(rec, ToolRecommendation)
            assert rec.tool, f"Empty tool name in recommendation for '{scenario_name}'"
            assert rec.reason, f"Empty reason in recommendation for '{scenario_name}'"
            assert rec.command_hint, f"Empty command_hint in recommendation for '{scenario_name}'"
            assert rec.priority >= 1, f"Invalid priority {rec.priority} for '{scenario_name}'"

    def test_format_recommendations_output(self):
        """format_recommendations_for_prompt should return non-empty string."""
        ctx = PHASE_SCENARIOS["RECON"]
        recs = get_recommendations(ctx, max_results=3)
        output = format_recommendations_for_prompt(recs)
        assert "[RECOMMENDED TOOLS" in output
        assert len(output) > 50

    def test_format_empty_recommendations(self):
        """Empty recommendations should return empty string."""
        output = format_recommendations_for_prompt([])
        assert output == ""

    def test_overused_tool_demoted(self):
        """Tools used >=5 times should get demoted (priority increased)."""
        ctx = AgentContext(
            phase="RECON",
            target_ip="10.0.1.1",
            services_found=[],
            tools_used={"nmap": 10},
            iteration=20,
        )
        recs = get_recommendations(ctx, max_results=5)
        nmap_recs = [r for r in recs if r.tool == "nmap"]
        if nmap_recs:
            assert "OVERUSED" in nmap_recs[0].reason, (
                "nmap used 10 times should be marked as OVERUSED"
            )

    def test_failed_tool_excluded(self):
        """Tools that failed should be excluded from recommendations."""
        ctx = AgentContext(
            phase="RECON",
            target_ip="10.0.1.1",
            services_found=[],
            tools_failed=["nmap", "rustscan"],
            iteration=5,
        )
        recs = get_recommendations(ctx, max_results=10)
        tool_names = {r.tool for r in recs}
        assert "nmap" not in tool_names, "Failed tool 'nmap' should be excluded"
        assert "rustscan" not in tool_names, "Failed tool 'rustscan' should be excluded"

    def test_recommendation_rules_cover_all_phases(self):
        """Every internal phase should have at least one rule."""
        phases_with_rules = set()
        for rule in RECOMMENDATION_RULES:
            p = rule.get("phase", "")
            if p:
                phases_with_rules.add(p)
        expected = {"RECON", "VULN_DISCOVERY", "EXPLOITATION", "POST_EXPLOIT", "C2_DEPLOY"}
        missing = expected - phases_with_rules
        assert not missing, (
            f"No recommendation rules defined for phases: {missing}. "
            "The agent will get no tool guidance in these phases."
        )
