import os
import tempfile
import unittest
from pathlib import Path


def _import_dynamic_agent(memory_dir: str | None = None):
    # Import from repo path without requiring it to be installed as a package.
    import sys
    import importlib

    if memory_dir:
        os.environ["MEMORY_DIR"] = str(memory_dir)

    here = Path(__file__).resolve()
    repo = here.parents[2]
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))

    # Reload memory/dynamic_agent so env-driven constants honor current os.environ.
    if "memory" in sys.modules:
        importlib.reload(sys.modules["memory"])
    if "dynamic_agent" in sys.modules:
        importlib.reload(sys.modules["dynamic_agent"])

    import dynamic_agent  # type: ignore

    return dynamic_agent


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def chat(self, conversation, max_tokens=1024, temperature=0.2):
        if self.calls >= len(self.responses):
            return "No further actions."
        r = self.responses[self.calls]
        self.calls += 1
        return r


class TestDynamicAgentUnlimitedIterations(unittest.TestCase):
    def setUp(self):
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)

        # Ensure DynamicAgent's MemoryStore doesn't try writing to /pentest on host.
        self.da = _import_dynamic_agent(memory_dir=self.tmpdir)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def test_max_iterations_zero_is_unlimited_and_runs(self):
        # Regression: max_iterations=0 is documented as "unlimited".
        # Historically DynamicAgent.run used `while iteration < max_iterations`, so 0 meant "run zero iters".
        agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None, max_iterations=0)

        executed = []

        def fake_execute(exec_type, content, timeout=120):
            executed.append(content)
            # Stop after the first executed command so the test can't loop forever.
            agent.hard_stop_reason = "unit-test stop"
            tool = agent._detect_tool(content)
            return self.da.Execution(
                timestamp="2026-02-17T00:00:00Z",
                iteration=int(agent.iteration),
                execution_type=exec_type,
                content=content,
                stdout="ok",
                stderr="",
                exit_code=0,
                duration_ms=1,
                success=True,
                tool_used=tool,
            )

        agent._execute = fake_execute  # type: ignore
        agent.llm = FakeLLM(["Do it.\n```bash\necho hi\n```"])

        agent.run(target="juiceshop", objective="test", resume=False)

        self.assertTrue(executed)


if __name__ == "__main__":
    unittest.main()
