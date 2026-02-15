import os
import tempfile
import unittest
from pathlib import Path


def _import_dynamic_agent():
    import sys
    import importlib
    here = Path(__file__).resolve()
    repo = here.parents[2]
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))
    # Reload memory/dynamic_agent so env-driven constants (e.g., MEMORY_DIR) honor current os.environ.
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
            # Default to a safe "done" response with no commands.
            return "No further actions."
        r = self.responses[self.calls]
        self.calls += 1
        return r


class TestProofGateE2E(unittest.TestCase):
    def test_gate_blocks_enum_until_proof_then_marks_exploited(self):
        old_env = dict(os.environ)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                os.environ["MEMORY_DIR"] = tmpdir
                da = _import_dynamic_agent()
                # Configure exploit-proof gate
                os.environ["JOB_PHASE"] = "FULL"
                os.environ["EXPLOIT_MODE"] = "autonomous"
                os.environ["ENFORCE_EXPLOITATION_GATE"] = "true"
                os.environ["ENFORCE_EXPLOITATION_PROOF"] = "true"
                os.environ["EXPLOITATION_GATE_COOLDOWN_ITERS"] = "0"
                os.environ["EXPLOITATION_PROOF_MAX_ATTEMPTS_PER_VULN"] = "3"
                os.environ["EXPLOITATION_PROOF_FAIL_MODE"] = "stop"
                os.environ["TENANT_ID"] = "test"

                agent = da.DynamicAgent(log_dir=tmpdir, llm_provider=None, max_iterations=6)
                agent.max_iterations = 6

                # Pre-seed a vuln that must be proven.
                agent.vulns_found = {
                    "mass_assignment_juiceshop": {
                        "type": "mass assignment",
                        "target": "juiceshop",
                        "details": "test seed",
                        "iteration_found": 1,
                        "exploited": False,
                        "exploit_evidence": "",
                        "attempted": False,
                        "attempt_count": 0,
                        "attempts": [],
                        "not_exploitable_reason": "",
                    }
                }

                # First response tries enum; second response performs exploit (curl -d ... role=admin).
                agent.llm = FakeLLM(
                    [
                        "Try recon.\n```bash\nnmap -F juiceshop\n```",
                        "Exploit mass assignment.\n```bash\ncurl -s -X POST http://juiceshop/api/users -H 'Content-Type: application/json' -d '{\"email\":\"a@b.c\",\"role\":\"admin\"}'\n```",
                        "Done.",
                    ]
                )

                # Avoid running real subprocesses; synthesize execution results.
                def fake_execute(exec_type, content, timeout=120):
                    tool = agent._detect_tool(content)
                    if "curl" in content and "-d" in content:
                        stdout = "{\"email\":\"a@b.c\",\"role\":\"admin\"}"
                        success = True
                        exit_code = 0
                    else:
                        stdout = "Starting Nmap...\n"
                        success = True
                        exit_code = 0
                    return da.Execution(
                        timestamp="2026-02-06T00:00:00Z",
                        iteration=agent.iteration,
                        execution_type=exec_type,
                        content=content,
                        stdout=stdout,
                        stderr="",
                        exit_code=exit_code,
                        duration_ms=10,
                        success=success,
                        tool_used=tool,
                    )

                agent._execute = fake_execute  # type: ignore

                agent.run(target="juiceshop", objective="Exploit all tracked vulns with proof.", resume=False)

                # Only the exploit command should have executed (enum should be blocked by gate).
                self.assertGreaterEqual(len(agent.executions), 1)
                self.assertTrue(any("curl" in (e.content or "") for e in agent.executions))
                # The vuln should now be proven exploited with proof populated.
                v = agent.vulns_found["mass_assignment_juiceshop"]
                self.assertTrue(v.get("exploited"))
                self.assertIn("role", (v.get("proof") or ""))
        finally:
            os.environ.clear()
            os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
