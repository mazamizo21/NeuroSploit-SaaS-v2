"""Tests for LLM reasoning stripping and evidence sanitization."""
import os
import sys
import unittest

# Ensure kali-executor modules are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "kali-executor", "open-interpreter"))

from dynamic_agent import DynamicAgent
from comprehensive_report import ComprehensiveReport


class TestStripLLMReasoning(unittest.TestCase):
    """Test that LLM internal monologue is stripped from evidence fields."""

    def test_strips_wait_prefix(self):
        result = DynamicAgent._strip_llm_reasoning(
            "Wait, the user *provided* that output. So the IDOR is confirmed at /deck endpoint."
        )
        # Should keep the factual part about IDOR
        self.assertNotIn("Wait,", result)
        self.assertIn("IDOR", result)

    def test_strips_okay_prefix(self):
        result = DynamicAgent._strip_llm_reasoning(
            "Okay, so I have two things happening. The endpoint /api/users returns admin data."
        )
        self.assertNotIn("Okay, so I have", result)
        self.assertIn("/api/users", result)

    def test_strips_let_me_prefix(self):
        result = DynamicAgent._strip_llm_reasoning(
            "Let me think about this. SQL injection at /login with ' OR 1=1--"
        )
        self.assertNotIn("Let me think", result)
        self.assertIn("SQL injection", result)

    def test_strips_italicized_thoughts(self):
        result = DynamicAgent._strip_llm_reasoning(
            "*thinking about the best approach*\nFound XSS at /feedback endpoint"
        )
        self.assertNotIn("thinking about", result)
        self.assertIn("XSS", result)

    def test_preserves_pure_factual_content(self):
        factual = "IDOR (T1212) at /deck endpoint. Evidence: HTTP 200 with other user's data."
        result = DynamicAgent._strip_llm_reasoning(factual)
        self.assertEqual(result, factual)

    def test_preserves_technical_evidence(self):
        evidence = 'curl -H "Authorization: Bearer eyJhbGciOiJ..." http://target/api/users\nHTTP/1.1 200 OK\n{"role":"admin"}'
        result = DynamicAgent._strip_llm_reasoning(evidence)
        self.assertIn("curl", result)
        self.assertIn("200 OK", result)

    def test_empty_input(self):
        self.assertEqual(DynamicAgent._strip_llm_reasoning(""), "")
        self.assertEqual(DynamicAgent._strip_llm_reasoning(None), "")

    def test_all_reasoning_returns_original(self):
        """If everything is reasoning, return original rather than empty."""
        text = "Wait, I need to think about this."
        result = DynamicAgent._strip_llm_reasoning(text)
        # Should return something (original text if all stripped)
        self.assertTrue(len(result) > 0)

    def test_strips_i_need_to_pattern(self):
        result = DynamicAgent._strip_llm_reasoning(
            "I need to check the response. The server returned a JWT token for admin."
        )
        self.assertIn("JWT token", result)


class TestComprehensiveReportStripReasoning(unittest.TestCase):
    """Test that ComprehensiveReport also strips LLM reasoning."""

    def test_strips_reasoning_from_vuln_evidence(self):
        report = ComprehensiveReport()
        report.parse_memories([{
            "category": "vulnerability_found",
            "content": "Wait, the user *provided* that output. IDOR confirmed at /api/users. Evidence: HTTP 200 with admin data.",
            "context": {"target": "http://target:3000", "iteration": 5},
        }])
        self.assertTrue(len(report.vulnerabilities) > 0)
        vuln = report.vulnerabilities[0]
        self.assertNotIn("Wait,", vuln.evidence)
        self.assertNotIn("*provided*", vuln.evidence)


class TestWorkerEvidenceFallback(unittest.TestCase):
    """Test that worker evidence extraction prefers tool output over LLM text."""

    def test_evidence_from_attempts_not_details(self):
        """The evidence field should come from attempt stdout, not LLM details text."""
        # Simulate the worker's evidence extraction logic from vuln_tracker entries
        vuln = {
            "type": "idor",
            "target": "http://target:3000/deck",
            "details": "Wait, the user *provided* that output. So the IDOR is confirmed.",
            "exploited": False,
            "proof": "",
            "exploit_evidence": "",
            "attempts": [
                {
                    "iteration": 5,
                    "command": 'curl http://target:3000/api/users/1',
                    "success": True,
                    "evidence": '{"id":1,"email":"admin@example.com","role":"admin"}',
                    "technique": "curl_payload",
                }
            ],
        }
        
        # The worker should prefer attempt evidence over details
        evidence = ""
        if vuln.get("proof"):
            evidence = vuln["proof"]
        elif vuln.get("attempts"):
            for att in reversed(vuln["attempts"]):
                if att.get("success") and att.get("evidence"):
                    evidence = att["evidence"]
                    break
            if not evidence:
                for att in reversed(vuln["attempts"]):
                    if att.get("evidence"):
                        evidence = att["evidence"]
                        break
        if not evidence:
            evidence = f"{vuln.get('type', 'unknown')} detected at {vuln.get('target', 'unknown')} — awaiting exploitation proof"
        
        # Evidence should be the actual tool output, not LLM reasoning
        self.assertNotIn("Wait,", evidence)
        self.assertNotIn("*provided*", evidence)
        self.assertIn("admin@example.com", evidence)

    def test_no_attempts_gives_clean_fallback(self):
        """When there are no attempts, fallback should be clean, not LLM text."""
        vuln = {
            "type": "idor",
            "target": "http://target:3000/deck",
            "details": "Okay, so I found an IDOR here.",
            "exploited": False,
            "proof": "",
            "attempts": [],
        }
        
        evidence = ""
        if vuln.get("proof"):
            evidence = vuln["proof"]
        elif vuln.get("attempts"):
            for att in reversed(vuln["attempts"]):
                if att.get("success") and att.get("evidence"):
                    evidence = att["evidence"]
                    break
        if not evidence:
            evidence = f"{vuln.get('type', 'unknown')} detected at {vuln.get('target', 'unknown')} — awaiting exploitation proof"
        
        self.assertNotIn("Okay, so I found", evidence)
        self.assertIn("idor detected", evidence)


class TestVulnTypeMapping(unittest.TestCase):
    """Test that IDOR and other vuln types are properly mapped."""

    def test_idor_maps_to_proper_type(self):
        report = ComprehensiveReport()
        report.parse_memories([{
            "category": "vulnerability_found",
            "content": "IDOR found at /api/users endpoint. Evidence: accessed other user data.",
            "context": {"target": "http://target:3000", "iteration": 3},
        }])
        self.assertTrue(len(report.vulnerabilities) > 0)
        vuln = report.vulnerabilities[0]
        self.assertIn("Insecure Direct Object Reference", vuln.type)

    def test_mass_assignment_maps_properly(self):
        report = ComprehensiveReport()
        report.parse_memories([{
            "category": "vulnerability_found",
            "content": "Mass assignment vulnerability at /api/users. Evidence: set role=admin.",
            "context": {"target": "http://target:3000", "iteration": 4},
        }])
        self.assertTrue(len(report.vulnerabilities) > 0)
        vuln = report.vulnerabilities[0]
        self.assertIn("Mass Assignment", vuln.type)

    def test_path_traversal_maps_properly(self):
        report = ComprehensiveReport()
        report.parse_memories([{
            "category": "vulnerability_found",
            "content": "Path traversal found via ../../../etc/passwd. Evidence: root:x:0:0.",
            "context": {"target": "http://target:3000", "iteration": 2},
        }])
        self.assertTrue(len(report.vulnerabilities) > 0)
        vuln = report.vulnerabilities[0]
        # Should be Path Traversal or Directory Traversal, not Unknown
        self.assertNotEqual(vuln.type, "Unknown")


if __name__ == "__main__":
    unittest.main()
