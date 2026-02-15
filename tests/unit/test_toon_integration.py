"""Tests for TOON format integration in dynamic_agent.py.

Verifies that TOON compact serialization is used in LLM context when enabled,
and that the original markdown format is used when disabled.
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _import_dynamic_agent():
    import sys
    here = Path(__file__).resolve()
    repo = here.parents[2]
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))
    import dynamic_agent  # type: ignore
    return dynamic_agent


class TestToonHelper(unittest.TestCase):
    """Test the _to_toon helper method."""

    def setUp(self):
        self.da = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)
        self.agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def test_to_toon_returns_compact_format(self):
        data = [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}]
        result = self.agent._to_toon(data)
        # TOON uses tabular header like {port,service}: and CSV-style rows
        self.assertIn("port", result)
        self.assertIn("service", result)
        self.assertIn("80", result)
        self.assertIn("443", result)
        # Should be shorter than JSON
        import json
        json_len = len(json.dumps(data))
        self.assertLessEqual(len(result), json_len)

    def test_to_toon_fallback_on_error(self):
        """If toon_encode raises, fallback to str()."""
        with patch.object(self.da, "toon_encode", side_effect=Exception("boom")):
            result = self.agent._to_toon({"a": 1})
            self.assertIn("a", result)

    def test_to_toon_disabled(self):
        """When TOON_ENABLED is False, returns str(data)."""
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = False
            data = [{"x": 1}]
            result = self.agent._to_toon(data)
            self.assertEqual(result, str(data))
        finally:
            self.da.TOON_ENABLED = original


class TestToonContextSummary(unittest.TestCase):
    """Test TOON integration in _build_structured_context_summary."""

    def setUp(self):
        self.da = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)
        self.agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def test_context_summary_uses_toon_for_vulns(self):
        """structured_findings should be serialized compactly with TOON."""
        self.agent.structured_findings = [
            {"type": "sqli", "target": "http://dvwa/vuln", "exploited": False, "exploit_attempts": 2},
            {"type": "xss", "target": "http://dvwa/xss", "exploited": True, "exploit_attempts": 1},
        ]
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = True
            result = self.agent._build_structured_context_summary()
            self.assertIn("VULNERABILITIES", result)
            # TOON tabular format uses CSV-style header
            self.assertIn("sqli", result)
            self.assertIn("xss", result)
            # Should NOT have the old markdown format "- sqli @ ..."
            self.assertNotIn("- sqli @", result)
        finally:
            self.da.TOON_ENABLED = original

    def test_context_summary_fallback_when_disabled(self):
        """When TOON disabled, old markdown format preserved."""
        self.agent.structured_findings = [
            {"type": "sqli", "target": "http://dvwa/vuln", "exploited": False, "exploit_attempts": 2},
        ]
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = False
            result = self.agent._build_structured_context_summary()
            self.assertIn("VULNERABILITIES", result)
            # Old format: "- sqli @ http://dvwa/vuln (unexploited, attempts=2)"
            self.assertIn("- sqli @ http://dvwa/vuln", result)
        finally:
            self.da.TOON_ENABLED = original

    def test_context_summary_empty_data_shows_none(self):
        """Empty sections should show '- none recorded'."""
        self.agent.structured_findings = []
        self.agent.vulns_found = {}
        self.agent.arsenal = {"credentials": [], "tokens": []}
        result = self.agent._build_structured_context_summary()
        self.assertIn("none recorded", result)

    def test_context_summary_failed_approaches_toon(self):
        """Failed attempts from vulns_found should use TOON when enabled."""
        self.agent.vulns_found = {
            "v1": {
                "type": "sqli",
                "target": "http://dvwa",
                "attempts": [
                    {"status": "failed", "error": "timeout after 30s"},
                ],
            }
        }
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = True
            result = self.agent._build_structured_context_summary()
            self.assertIn("FAILED APPROACHES", result)
            self.assertIn("timeout", result)
        finally:
            self.da.TOON_ENABLED = original


class TestToonVulnTrackerDigest(unittest.TestCase):
    """Test TOON integration in vuln tracker injection (_rule_based_digest_extraction)."""

    def setUp(self):
        self.da = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)
        self.agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def test_digest_vuln_tracker_uses_toon(self):
        """Vuln tracker in digest should use TOON tabular format."""
        self.agent.vulns_found = {
            "v1": {
                "type": "sqli",
                "target": "http://dvwa/sqli",
                "proof": None,
                "attempted": True,
                "attempt_count": 3,
            }
        }
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = True
            messages = [
                {"role": "user", "content": "scan the target"},
                {"role": "assistant", "content": "Running nmap scan"},
            ]
            result = self.agent._rule_based_digest_extraction(messages)
            self.assertIn("VULNERABILITIES", result)
            # TOON format should be present (tabular header)
            self.assertIn("sqli", result)
        finally:
            self.da.TOON_ENABLED = original

    def test_digest_vuln_tracker_fallback(self):
        """Vuln tracker in digest uses markdown when TOON disabled."""
        self.agent.vulns_found = {
            "v1": {
                "type": "xss",
                "target": "http://dvwa/xss",
                "proof": "alert(1)",
                "attempted": True,
                "attempt_count": 1,
            }
        }
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = False
            messages = [{"role": "user", "content": "test"}]
            result = self.agent._rule_based_digest_extraction(messages)
            self.assertIn("VULNERABILITIES", result)
            # Old markdown format
            self.assertIn("- xss at http://dvwa/xss", result)
        finally:
            self.da.TOON_ENABLED = original


class TestToonRuntimeEnforcement(unittest.TestCase):
    """Test TOON in _build_runtime_enforcement_message finding items."""

    def setUp(self):
        self.da = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)
        self.agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def test_runtime_enforcement_uses_toon_for_findings(self):
        """Unexploited findings in enforcement msg should use TOON."""
        self.agent.structured_findings = [
            {
                "id": "v1",
                "type": "sqli",
                "target": "http://dvwa/sqli",
                "exploited": False,
                "not_exploitable_reason": "",
                "exploit_attempts": 2,
                "severity": "high",
            }
        ]
        self.agent.phase_current = "EXPLOITATION"
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = True
            result = self.agent._build_runtime_enforcement_message()
            self.assertIn("sqli", result)
            self.assertIn("EXPLOIT", result)
            # Should NOT have old format "- [v1] sqli @"
            self.assertNotIn("- [v1]", result)
        finally:
            self.da.TOON_ENABLED = original

    def test_runtime_enforcement_fallback(self):
        """Unexploited findings use markdown when TOON disabled."""
        self.agent.structured_findings = [
            {
                "id": "v1",
                "type": "sqli",
                "target": "http://dvwa/sqli",
                "exploited": False,
                "not_exploitable_reason": "",
                "exploit_attempts": 2,
                "severity": "high",
            }
        ]
        self.agent.phase_current = "EXPLOITATION"
        original = self.da.TOON_ENABLED
        try:
            self.da.TOON_ENABLED = False
            result = self.agent._build_runtime_enforcement_message()
            # Old format: "- [v1] sqli @ http://dvwa/sqli ..."
            self.assertIn("- [v1] sqli @ http://dvwa/sqli", result)
        finally:
            self.da.TOON_ENABLED = original


class TestToonFeatureFlag(unittest.TestCase):
    """Test TOON_ENABLED feature flag behavior."""

    def test_toon_module_constants_exist(self):
        da = _import_dynamic_agent()
        self.assertTrue(hasattr(da, "TOON_ENABLED"))
        self.assertTrue(hasattr(da, "TOON_AVAILABLE"))

    def test_toon_enabled_default_true(self):
        """TOON_ENABLED should default to true when toon_format is installed."""
        da = _import_dynamic_agent()
        if da.TOON_AVAILABLE:
            # The env var defaults to "true"
            self.assertTrue(da.TOON_ENABLED)


if __name__ == "__main__":
    unittest.main()
