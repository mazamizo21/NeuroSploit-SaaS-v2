"""Tests for Proactive Phase Forcing (exploitation gap fix).

Covers: recon tracking, forcing activation, level escalation,
recon blocking, plan generation, severity picking, deactivation,
evidence processing, and env var overrides.
"""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock


def _import_dynamic_agent():
    import sys
    here = Path(__file__).resolve()
    repo = here.parents[2]
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))
    import dynamic_agent  # type: ignore
    return dynamic_agent


class TestProactivePhaseForcing(unittest.TestCase):
    def setUp(self):
        self.dynamic_agent = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name

        self._old_env = dict(os.environ)
        os.environ["EXPLOIT_MODE"] = "autonomous"
        os.environ["ENFORCE_EXPLOITATION_PROOF"] = "true"
        os.environ["PROACTIVE_RECON_THRESHOLD"] = "5"
        os.environ["PROACTIVE_ESCALATION_INTERVAL"] = "2"
        os.environ["PROACTIVE_DIRECT_EXEC"] = "true"

        self.agent = self.dynamic_agent.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)
        # Force exploit phase active
        self.agent.phase_current = "EXPLOIT"
        self.agent.allow_exploit_any_phase = True

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    # ── 1. Recon tracking increments ──

    def test_recon_tracking_increments(self):
        """Recon-only iterations should increment the counter."""
        executables = [("bash", "nmap -sV 10.0.0.1")]
        self.agent._track_recon_iteration(executables)
        self.assertEqual(self.agent.recon_consecutive_count, 1)

        self.agent._track_recon_iteration(executables)
        self.assertEqual(self.agent.recon_consecutive_count, 2)

    # ── 2. Recon tracking resets on exploit ──

    def test_recon_tracking_resets_on_exploit(self):
        """An exploit command should reset the recon counter to 0."""
        self.agent.recon_consecutive_count = 10
        executables = [("bash", "sqlmap -u http://target/login --batch --dump")]
        self.agent._track_recon_iteration(executables)
        self.assertEqual(self.agent.recon_consecutive_count, 0)

    # ── 3. Forcing activates at threshold ──

    def test_forcing_activates_at_threshold(self):
        """After threshold recon iterations, forcing should activate."""
        # Add a pending vuln
        self.agent.vulns_found["v1"] = {
            "id": "v1", "type": "sqli", "target": "http://target/login",
            "severity": "high", "exploited": False, "details": "SQL injection at /login",
        }
        self.agent.recon_consecutive_count = 5  # matches threshold

        self.agent._check_proactive_phase_forcing()

        self.assertTrue(self.agent.proactive_forcing_active)
        self.assertEqual(self.agent.proactive_forcing_level, 1)
        self.assertTrue(len(self.agent.proactive_forcing_plan) > 0)

    # ── 4. Forcing level escalation ──

    def test_forcing_level_escalation(self):
        """Forcing levels should escalate at the escalation interval."""
        self.agent.vulns_found["v1"] = {
            "id": "v1", "type": "sqli", "target": "http://target/login",
            "severity": "high", "exploited": False, "details": "",
        }

        # Activate forcing
        self.agent.recon_consecutive_count = 5
        self.agent._check_proactive_phase_forcing()
        self.assertEqual(self.agent.proactive_forcing_level, 1)

        # Escalate: interval=2, so at recon_consecutive_count=2 it escalates
        self.agent.recon_consecutive_count = 2
        self.agent._check_proactive_phase_forcing()
        self.assertEqual(self.agent.proactive_forcing_level, 2)

        # Escalate again at recon_consecutive_count=4
        self.agent.recon_consecutive_count = 4
        self.agent._check_proactive_phase_forcing()
        self.assertEqual(self.agent.proactive_forcing_level, 3)

    # ── 5. Recon blocked during forcing ──

    def test_recon_blocked_during_forcing(self):
        """_is_recon_command should identify recon tools."""
        self.assertTrue(self.agent._is_recon_command("nmap -sV 10.0.0.1"))
        self.assertTrue(self.agent._is_recon_command("gobuster dir -u http://target"))
        self.assertTrue(self.agent._is_recon_command("nikto -h http://target"))
        self.assertTrue(self.agent._is_recon_command("masscan 10.0.0.0/24 -p1-65535"))
        self.assertTrue(self.agent._is_recon_command("dirb http://target/"))
        self.assertTrue(self.agent._is_recon_command("whatweb http://target"))
        self.assertTrue(self.agent._is_recon_command("/usr/bin/nmap -sV target"))
        # Exploit tools should NOT be flagged
        self.assertFalse(self.agent._is_recon_command("sqlmap -u http://target --dump"))
        self.assertFalse(self.agent._is_recon_command("hydra -l root ssh://target"))
        self.assertFalse(self.agent._is_recon_command("curl http://target/etc/passwd"))
        self.assertFalse(self.agent._is_recon_command(""))

    # ── 6. Exploitation plan generated ──

    def test_exploitation_plan_generated(self):
        """Plan generation should produce valid commands for known vuln types."""
        vuln = {
            "type": "sqli", "target": "http://target/login",
            "details": "SQL injection at http://target/rest/user/login?id=1",
            "techniques_tried": [], "attempts": [],
        }
        plan = self.agent._generate_exploitation_plan(vuln)
        self.assertTrue(len(plan) > 0)
        self.assertIn("command", plan[0])
        self.assertIn("rationale", plan[0])
        self.assertIn("tool", plan[0])
        # Should contain sqlmap for sqli vuln
        self.assertTrue(any("sqlmap" in step["command"] for step in plan))

    def test_exploitation_plan_default_type(self):
        """Unknown vuln types should fall back to default commands."""
        vuln = {
            "type": "some_exotic_vuln", "target": "http://target",
            "details": "", "techniques_tried": [], "attempts": [],
        }
        plan = self.agent._generate_exploitation_plan(vuln)
        self.assertTrue(len(plan) > 0)

    # ── 7. Highest severity picked ──

    def test_highest_severity_picked(self):
        """Should pick the highest-severity vuln from a list."""
        vulns = [
            {"id": "v1", "severity": "low", "type": "info_disclosure"},
            {"id": "v2", "severity": "critical", "type": "rce"},
            {"id": "v3", "severity": "medium", "type": "xss"},
        ]
        picked = self.agent._pick_highest_severity_vuln(vulns)
        self.assertEqual(picked["id"], "v2")

    def test_highest_severity_empty_list(self):
        """Empty list should return empty dict."""
        self.assertEqual(self.agent._pick_highest_severity_vuln([]), {})

    def test_highest_severity_risk_field(self):
        """Should also handle 'risk' field when 'severity' is absent."""
        vulns = [
            {"id": "v1", "risk": "high", "type": "sqli"},
            {"id": "v2", "risk": "low", "type": "xss"},
        ]
        picked = self.agent._pick_highest_severity_vuln(vulns)
        self.assertEqual(picked["id"], "v1")

    # ── 8. Forcing deactivates on voluntary exploit ──

    def test_forcing_deactivates_on_voluntary_exploit(self):
        """If agent exploits voluntarily at level<=1, forcing should deactivate."""
        self.agent.proactive_forcing_active = True
        self.agent.proactive_forcing_level = 1
        self.agent.proactive_forcing_plan = [{"command": "sqlmap ...", "rationale": "test", "tool": "sqlmap"}]
        self.agent.recon_consecutive_count = 10

        # Simulate exploit command
        executables = [("bash", "sqlmap -u http://target --dump --batch")]
        self.agent._track_recon_iteration(executables)

        self.assertFalse(self.agent.proactive_forcing_active)
        self.assertEqual(self.agent.proactive_forcing_level, 0)
        self.assertEqual(self.agent.proactive_forcing_plan, [])

    def test_forcing_persists_at_high_level(self):
        """At level 2+, voluntary exploit should NOT deactivate forcing."""
        self.agent.proactive_forcing_active = True
        self.agent.proactive_forcing_level = 2
        self.agent.proactive_forcing_plan = [{"command": "sqlmap ...", "rationale": "test", "tool": "sqlmap"}]
        self.agent.recon_consecutive_count = 10

        executables = [("bash", "sqlmap -u http://target --dump --batch")]
        self.agent._track_recon_iteration(executables)

        # Should reset counter but NOT deactivate forcing (level > 1)
        self.assertEqual(self.agent.recon_consecutive_count, 0)
        self.assertTrue(self.agent.proactive_forcing_active)

    # ── 9. Direct exec processes evidence ──

    def test_direct_exec_processes_evidence(self):
        """Level 3 evidence processing should record attempts against the focused vuln."""
        Execution = self.dynamic_agent.Execution
        self.agent.vulns_found["v1"] = {
            "id": "v1", "type": "sqli", "target": "http://target",
            "exploited": False, "attempted": False, "attempt_count": 0,
            "attempts": [],
        }
        self.agent.proactive_forcing_vuln_id = "v1"

        # Output must match EXPLOITATION_EVIDENCE_PATTERNS for evidence to be recorded
        execution = Execution(
            timestamp="2026-02-17T00:00:00Z",
            iteration=1,
            execution_type="command",
            content="sqlmap -u http://target --dump --batch",
            stdout="Database: main\nTable: Users\n5 rows in set\nSELECT * FROM users",
            stderr="",
            exit_code=0,
            duration_ms=5000,
            success=True,
            tool_used="sqlmap",
        )
        self.agent._process_execution_evidence(execution, "sqlmap -u http://target --dump --batch")

        vrec = self.agent.vulns_found["v1"]
        self.assertTrue(vrec["attempted"])
        self.assertEqual(vrec["attempt_count"], 1)
        self.assertEqual(len(vrec["attempts"]), 1)
        self.assertEqual(vrec["attempts"][0]["source"], "proactive_direct_exec")

    # ── 10. Env var threshold override ──

    def test_env_var_threshold_override(self):
        """PROACTIVE_RECON_THRESHOLD env var should control the threshold."""
        # setUp set it to 5
        self.assertEqual(self.agent.proactive_recon_threshold, 5)
        self.assertEqual(self.agent.proactive_escalation_interval, 2)

    def test_env_var_direct_exec_disabled(self):
        """PROACTIVE_DIRECT_EXEC=false should disable Level 3."""
        os.environ["PROACTIVE_DIRECT_EXEC"] = "false"
        agent2 = self.dynamic_agent.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)
        self.assertFalse(agent2.proactive_direct_exec_enabled)

    # ── Bonus: no forcing when not autonomous ──

    def test_no_forcing_outside_autonomous_mode(self):
        """Forcing should NOT activate outside autonomous exploit mode."""
        os.environ["EXPLOIT_MODE"] = "explicit_only"
        self.agent.vulns_found["v1"] = {
            "id": "v1", "type": "sqli", "target": "http://target",
            "severity": "high", "exploited": False, "details": "",
        }
        self.agent.recon_consecutive_count = 100

        self.agent._check_proactive_phase_forcing()
        self.assertFalse(self.agent.proactive_forcing_active)

    def test_no_forcing_when_no_pending_vulns(self):
        """Forcing should NOT activate when all vulns are resolved."""
        self.agent.recon_consecutive_count = 100
        # No vulns_found at all
        self.agent._check_proactive_phase_forcing()
        self.assertFalse(self.agent.proactive_forcing_active)

    def test_empty_executables_ignored(self):
        """_track_recon_iteration with empty list should be a no-op."""
        self.agent.recon_consecutive_count = 5
        self.agent._track_recon_iteration([])
        self.assertEqual(self.agent.recon_consecutive_count, 5)

    def test_plan_filters_tried_tools(self):
        """Plan generation should skip tools already tried."""
        vuln = {
            "type": "sqli", "target": "http://target/login",
            "details": "SQL injection at http://target/rest/user/login",
            "techniques_tried": ["sqlmap"],
            "attempts": [],
        }
        plan = self.agent._generate_exploitation_plan(vuln)
        # sqlmap should be filtered out since it was tried
        for step in plan:
            self.assertNotEqual(step["tool"], "sqlmap")


if __name__ == "__main__":
    unittest.main()
