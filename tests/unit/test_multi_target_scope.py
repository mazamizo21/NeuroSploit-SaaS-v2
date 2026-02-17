#!/usr/bin/env python3
"""Unit test — multi-target scope auto-enable.

When ALLOWED_TARGETS contains >1 target, the agent should auto-enable
allow_multi_target_scan. This prevents the agent from blocking itself
when it needs to scan multiple authorized hosts.
"""

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kali-executor" / "open-interpreter"))

from dynamic_agent import DynamicAgent  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def agent_factory(monkeypatch):
    """Factory to create agents with different target configurations."""
    monkeypatch.setenv("ALLOW_FULL_PORT_SCAN", "false")
    monkeypatch.setenv("ALLOW_COMMAND_CHAINING", "false")
    monkeypatch.setenv("ALLOW_MULTI_BLOCKS", "false")
    monkeypatch.setenv("LOG_DIR", "/tmp/tazosploit_tests")
    monkeypatch.setenv("KNOWLEDGE_GRAPH_ENABLED", "false")
    monkeypatch.setenv("REDIS_URL", "")

    def _create(targets: str, multi_scan: str = "false"):
        monkeypatch.setenv("ALLOWED_TARGETS", targets)
        monkeypatch.setenv("ALLOW_MULTI_TARGET_SCAN", multi_scan)
        agent = DynamicAgent(max_iterations=1)
        agent.target = targets.split(",")[0].strip() if targets else "10.0.1.1"
        agent.objective = "Test multi-target scope."
        agent._initialize_scope_allowlist()
        return agent

    return _create


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMultiTargetAutoEnable:
    """Test auto-enable of multi-target scanning when >1 target in scope."""

    def test_single_target_no_auto_enable(self, agent_factory):
        """With one target, multi-target should stay disabled."""
        agent = agent_factory("10.0.1.1")
        assert agent.allow_multi_target_scan is False, (
            "Single target should not auto-enable multi-target scanning"
        )

    def test_two_targets_auto_enable(self, agent_factory):
        """With two targets, multi-target should auto-enable."""
        agent = agent_factory("10.0.1.1,10.0.1.2")
        assert agent.allow_multi_target_scan is True, (
            "Two targets in scope should auto-enable multi-target scanning"
        )

    def test_three_targets_auto_enable(self, agent_factory):
        """With three targets, multi-target should auto-enable."""
        agent = agent_factory("10.0.1.1,10.0.1.2,10.0.1.3")
        assert agent.allow_multi_target_scan is True

    def test_scope_allowlist_populated(self, agent_factory):
        """The allowed_targets_set should contain all specified targets."""
        agent = agent_factory("10.0.1.1,10.0.1.2,10.0.1.3")
        assert "10.0.1.1" in agent.allowed_targets_set
        assert "10.0.1.2" in agent.allowed_targets_set
        assert "10.0.1.3" in agent.allowed_targets_set

    def test_empty_targets_no_enable(self, agent_factory):
        """With empty targets, multi-target should stay disabled."""
        agent = agent_factory("")
        assert agent.allow_multi_target_scan is False

    def test_explicit_multi_target_override(self, agent_factory):
        """When explicitly set to true, single target should still be true."""
        agent = agent_factory("10.0.1.1", multi_scan="true")
        assert agent.allow_multi_target_scan is True, (
            "Explicit ALLOW_MULTI_TARGET_SCAN=true should override"
        )


class TestMultiTargetScopeEnforcement:
    """Test that scope enforcement works with multiple targets."""

    def test_off_target_blocked_with_multi(self, agent_factory):
        """Commands targeting IPs outside the allowed set should be blocked."""
        agent = agent_factory("10.0.1.1,10.0.1.2")
        warning = agent._is_off_target("nmap 10.0.2.100")
        assert warning is not None, (
            "Off-target IP should be blocked even in multi-target mode"
        )

    def test_in_scope_target_allowed(self, agent_factory):
        """Commands targeting IPs in the allowed set should be fine."""
        agent = agent_factory("10.0.1.1,10.0.1.2")
        # A command targeting the second allowed target should not be blocked
        warning = agent._is_off_target("nmap 10.0.1.2")
        assert warning is None, (
            f"In-scope target 10.0.1.2 should be allowed, but got: {warning}"
        )

    def test_in_scope_first_target_allowed(self, agent_factory):
        """Primary target should always be allowed."""
        agent = agent_factory("10.0.1.1,10.0.1.2")
        warning = agent._is_off_target("nmap 10.0.1.1")
        assert warning is None
