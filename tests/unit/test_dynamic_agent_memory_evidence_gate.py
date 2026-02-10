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


class TestMemoryEvidenceGate(unittest.TestCase):
    def test_vuln_memory_accepts_implicit_jwt_evidence(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            content = "SQL injection in /rest/user/login returned token eyJaaaaaaaaaaa.bbbbbbbbbbb.ccccccccccc"
            self.assertTrue(agent._evidence_gate_ok("vulnerability_found", content))

    def test_vuln_memory_rejects_no_evidence(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            content = "SQL injection in /login"
            self.assertFalse(agent._evidence_gate_ok("vulnerability_found", content))


if __name__ == "__main__":
    unittest.main()

