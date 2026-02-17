#!/usr/bin/env python3
"""Unit test — FULL job phase bypasses the tool phase gate.

When a job's phase is set to "FULL", ALL tools should be allowed regardless
of the current internal phase. This is used for multi-target autonomous
pentests that need recon + exploit + post-exploit simultaneously.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kali-executor" / "open-interpreter"))

from tool_phase_map import (  # noqa: E402
    DEFAULT_TOOL_PHASE_MAP,
    INTERNAL_PHASES,
    ALWAYS_ALLOWED_TOOLS,
    is_tool_allowed,
    get_blocked_reason,
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFullPhaseBypass:
    """When job_phase=FULL, all tools should pass the phase gate."""

    @pytest.mark.parametrize("phase", INTERNAL_PHASES)
    def test_msfconsole_allowed_in_all_phases_with_full(self, phase):
        """msfconsole is normally exploitation-only; FULL should bypass."""
        assert is_tool_allowed("msfconsole", phase, job_phase="FULL") is True

    @pytest.mark.parametrize("phase", INTERNAL_PHASES)
    def test_hydra_allowed_in_all_phases_with_full(self, phase):
        """hydra is normally exploitation-only; FULL should bypass."""
        assert is_tool_allowed("hydra", phase, job_phase="FULL") is True

    @pytest.mark.parametrize("phase", INTERNAL_PHASES)
    def test_nmap_allowed_in_all_phases_with_full(self, phase):
        """nmap has specific phases; FULL should bypass."""
        assert is_tool_allowed("nmap", phase, job_phase="FULL") is True

    @pytest.mark.parametrize("phase", INTERNAL_PHASES)
    def test_linpeas_allowed_in_all_phases_with_full(self, phase):
        """Post-exploit tools should be allowed everywhere under FULL."""
        assert is_tool_allowed("linpeas", phase, job_phase="FULL") is True

    def test_all_curated_tools_allowed_with_full(self):
        """Every tool in DEFAULT_TOOL_PHASE_MAP should pass under FULL."""
        for tool in DEFAULT_TOOL_PHASE_MAP:
            for phase in INTERNAL_PHASES:
                assert is_tool_allowed(tool, phase, job_phase="FULL") is True, (
                    f"Tool '{tool}' blocked in phase '{phase}' even with job_phase=FULL"
                )


class TestNonFullPhaseEnforcement:
    """Without FULL, the normal phase restrictions should apply."""

    def test_msfconsole_blocked_in_recon(self):
        """msfconsole should not be allowed in RECON phase normally."""
        assert is_tool_allowed("msfconsole", "RECON") is False

    def test_msfconsole_allowed_in_exploitation(self):
        """msfconsole should be allowed in EXPLOITATION phase."""
        assert is_tool_allowed("msfconsole", "EXPLOITATION") is True

    def test_nmap_blocked_in_c2_deploy(self):
        """nmap should not be allowed in C2_DEPLOY phase."""
        assert is_tool_allowed("nmap", "C2_DEPLOY") is False

    def test_nmap_allowed_in_recon(self):
        """nmap should be allowed in RECON."""
        assert is_tool_allowed("nmap", "RECON") is True

    def test_blocked_reason_non_empty(self):
        """get_blocked_reason should return a non-empty string for blocked tools."""
        reason = get_blocked_reason("msfconsole", "RECON")
        assert reason, "Expected non-empty blocked reason for msfconsole in RECON"
        assert "BLOCKED" in reason
        assert "msfconsole" in reason

    def test_blocked_reason_empty_for_allowed(self):
        """get_blocked_reason should return empty for allowed tools."""
        reason = get_blocked_reason("nmap", "RECON")
        assert reason == "", f"Expected empty reason for allowed tool, got: {reason}"


class TestFullPhaseVariations:
    """Test edge cases for the FULL phase string."""

    def test_full_lowercase(self):
        """job_phase='full' (lowercase) should also bypass."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase="full") is True

    def test_full_mixed_case(self):
        """job_phase='Full' should also bypass (case-insensitive)."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase="Full") is True

    def test_full_with_whitespace(self):
        """job_phase=' FULL ' should be stripped and still bypass."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase=" FULL ") is True

    def test_empty_job_phase_no_bypass(self):
        """Empty job_phase should not bypass."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase="") is False

    def test_none_job_phase_no_bypass(self):
        """None job_phase should not bypass."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase=None) is False

    def test_recon_job_phase_no_bypass(self):
        """job_phase='RECON' should not bypass (only FULL does)."""
        assert is_tool_allowed("msfconsole", "RECON", job_phase="RECON") is False


class TestAlwaysAllowedNotAffectedByPhase:
    """Always-allowed tools should work regardless of phase or job_phase."""

    @pytest.mark.parametrize("tool", sorted(ALWAYS_ALLOWED_TOOLS))
    def test_always_allowed_in_any_phase(self, tool):
        for phase in INTERNAL_PHASES:
            assert is_tool_allowed(tool, phase) is True
            assert is_tool_allowed(tool, phase, job_phase="") is True
            assert is_tool_allowed(tool, phase, job_phase="FULL") is True
