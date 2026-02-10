import unittest
import sys
from pathlib import Path


# Import the Kali agent report generator module directly (not a packaged module).
REPO_ROOT = Path(__file__).resolve().parents[2]
OPEN_INTERPRETER_DIR = REPO_ROOT / "kali-executor" / "open-interpreter"
sys.path.insert(0, str(OPEN_INTERPRETER_DIR))

from comprehensive_report import ComprehensiveReport, Vulnerability  # noqa: E402


class TestComprehensiveReportCredsAndDedup(unittest.TestCase):
    def test_memory_ignores_ip_port_false_positive(self):
        r = ComprehensiveReport()
        r._extract_credential_from_memory(
            "JWT admin token for 172.21.0.12:3000 via SQLi on /rest/user/login",
            {"iteration": 1},
        )
        self.assertEqual(len(r.credentials), 0)

    def test_memory_extracts_email_slash_password_and_strong_dedups(self):
        r = ComprehensiveReport()
        r._extract_credential_from_memory("admin@juice-sh.op / admin123 (Default admin creds)", {"iteration": 1})
        # Same user/pass but different "service" cues should not create duplicates.
        r._extract_credential_from_memory("admin@juice-sh.op:admin123 via HTTP login", {"iteration": 2})
        self.assertEqual(len(r.credentials), 1)
        self.assertEqual(r.credentials[0].username, "admin@juice-sh.op")
        self.assertEqual(r.credentials[0].password, "admin123")

    def test_config_user_pass_pairing_does_not_use_placeholders(self):
        r = ComprehensiveReport()
        stdout = "DB_USER=appuser\nDB_PASSWORD=supersecret\n"
        r._extract_credentials("cat .env", stdout, iteration=10)
        self.assertTrue(any(c.username == "appuser" and c.password == "supersecret" for c in r.credentials))
        self.assertFalse(any(c.username.lower() == "extracted" for c in r.credentials))
        self.assertFalse(any(c.username.lower() == "email" for c in r.credentials))

    def test_json_api_response_creds_extract(self):
        r = ComprehensiveReport()
        stdout = '[{\"email\":\"a@b.com\",\"password\":\"p@ss\"},{\"email\":\"c@d.com\",\"password\":\"deadbeef\"}]'
        r._extract_credentials("curl /api/Users", stdout, iteration=3)
        self.assertTrue(any(c.username == "a@b.com" and c.password == "p@ss" for c in r.credentials))

    def test_api_findings_are_deduped(self):
        r = ComprehensiveReport()
        r.vulnerabilities.append(
            Vulnerability(
                type="SQL Injection",
                service="juiceshop",
                endpoint="http://juiceshop/rest/user/login",
                payload="email",
                impact="db dump",
                evidence="e1",
                extraction_command="sqlmap ...",
                iteration=1,
                mitre_id="T1190",
            )
        )
        # Duplicate of same vuln (common in long runs)
        r.vulnerabilities.append(
            Vulnerability(
                type="SQL Injection",
                service="juiceshop",
                endpoint="http://juiceshop/rest/user/login",
                payload="email",
                impact="db dump",
                evidence="e1-duplicate",
                extraction_command="sqlmap ...",
                iteration=2,
                mitre_id="T1190",
            )
        )
        findings = r.generate_api_findings()
        vuln_findings = [f for f in findings if f.get("finding_type") == "vulnerability"]
        self.assertEqual(len(vuln_findings), 1)


if __name__ == "__main__":
    unittest.main()
