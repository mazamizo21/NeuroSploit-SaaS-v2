#!/usr/bin/env python3
"""
Unit tests for scope guard and recon ladder enforcement.
Run: python3 tests/unit/test_scope_guard.py
"""

import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OPEN_INTERPRETER = ROOT / "kali-executor" / "open-interpreter"
sys.path.insert(0, str(OPEN_INTERPRETER))

from dynamic_agent import DynamicAgent, Execution  # noqa: E402


def _make_agent():
    os.environ["ALLOW_FULL_PORT_SCAN"] = "false"
    os.environ["ALLOW_MULTI_TARGET_SCAN"] = "false"
    os.environ["ALLOW_COMMAND_CHAINING"] = "false"
    os.environ["ALLOW_MULTI_BLOCKS"] = "false"
    os.environ["RECON_BASELINE_TOP_PORTS"] = "200"

    agent = DynamicAgent(max_iterations=1)
    agent.target = "10.0.1.1"
    agent.objective = "Test objective for scope guard."
    agent._initialize_scope_allowlist()
    return agent


def test_off_target_block():
    agent = _make_agent()
    warning = agent._is_off_target("nmap 10.0.2.10")
    assert warning is not None, "Expected off-target command to be blocked"


def test_multi_target_block():
    agent = _make_agent()
    warning = agent._is_off_target("nmap 10.0.1.1 10.0.1.2")
    assert warning is not None and "Multiple targets" in warning


def test_recon_ladder_block_then_allow():
    agent = _make_agent()
    warning = agent._recon_ladder_violation("nmap -p- 10.0.1.1")
    assert warning is not None, "Expected full-port scan to be blocked before baseline"

    baseline = Execution(
        timestamp="t",
        iteration=1,
        execution_type="bash",
        content="nmap -F 10.0.1.1",
        stdout="",
        stderr="",
        exit_code=0,
        duration_ms=1,
        success=True,
        tool_used="nmap",
    )
    agent._update_recon_state(baseline)
    warning = agent._recon_ladder_violation("nmap -p- 10.0.1.1")
    assert warning is None, "Expected full-port scan to be allowed after baseline"


def test_command_structure_block():
    agent = _make_agent()
    warning = agent._command_structure_violation("nmap 10.0.1.1 && curl http://10.0.1.1")
    assert warning is not None and "chain" in warning.lower()


def test_wordlist_missing_block():
    agent = _make_agent()
    warning = agent._wordlist_violation("gobuster dir -u http://10.0.1.1 -w /tmp/does-not-exist.txt")
    assert warning is not None and "WORDLIST MISSING" in warning


def test_evidence_gate():
    agent = _make_agent()
    assert agent._evidence_gate_ok("vulnerability_found", "SQLi at /login") is False
    assert agent._evidence_gate_ok("vulnerability_found", "SQLi at /login Evidence: error-based dump") is True


if __name__ == "__main__":
    test_off_target_block()
    test_multi_target_block()
    test_recon_ladder_block_then_allow()
    test_command_structure_block()
    test_wordlist_missing_block()
    test_evidence_gate()
    print("OK")
