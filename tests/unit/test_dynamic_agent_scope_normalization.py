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


class TestScopeNormalization(unittest.TestCase):
    def test_url_target_allows_hostname_commands(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "http://juice-sh.op:3000/#/login"
            agent.objective = "test"
            agent._initialize_scope_allowlist()

            # Command targets hostname; should not be considered off-target.
            warn = agent._is_off_target("curl -s http://juice-sh.op:3000/rest/products")
            self.assertIsNone(warn)

    def test_python_module_not_misdetected_as_target(self):
        da = _import_dynamic_agent()
        with tempfile.TemporaryDirectory() as tmpdir:
            agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=1)
            agent.target = "juiceshop"
            agent.objective = "test"
            agent._initialize_scope_allowlist()
            warn = agent._is_off_target("curl -s http://juiceshop:3000/api/Products | python3 -m json.tool | head -10")
            self.assertIsNone(warn)


if __name__ == "__main__":
    unittest.main()
