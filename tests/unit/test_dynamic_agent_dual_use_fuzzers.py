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
            return "No further actions."
        r = self.responses[self.calls]
        self.calls += 1
        return r


class TestDynamicAgentDualUseFuzzers(unittest.TestCase):
    def setUp(self):
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)

        # Ensure DynamicAgent's MemoryStore doesn't try writing to /pentest on host.
        self.da = _import_dynamic_agent(memory_dir=self.tmpdir)

        # ffuf/wfuzz wordlist preflight requires an on-disk path.
        self.wordlist_path = str(Path(self.tmpdir) / "wordlist.txt")
        Path(self.wordlist_path).write_text("admin\nlogin\n", encoding="utf-8")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def _agent(self):
        return self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None, max_iterations=3)

    def _jwt(self) -> str:
        # Long enough to match dynamic_agent scrubbers and avoid being mis-parsed as a target token.
        return "eyJ" + ("a" * 20) + "." + ("b" * 20) + "." + ("c" * 20)

    def test_detect_tool_finds_ffuf_and_wfuzz_with_shell_prelude(self):
        agent = self._agent()
        self.assertEqual(agent._detect_tool('JWT="x"; ffuf -u http://t/FUZZ -w w'), "ffuf")
        self.assertEqual(agent._detect_tool('TOKEN=$(curl -s http://t) && wfuzz -c -z file,w http://t/FUZZ'), "curl")
        self.assertEqual(agent._detect_tool('TOKEN=$(curl -s http://t) ; wfuzz -c -z file,w http://t/FUZZ'), "curl")
        # Ensure plain tool start works
        self.assertEqual(agent._detect_tool('wfuzz -c -z file,w http://t/FUZZ'), "wfuzz")

    def test_classify_intent_ffuf_wfuzz_exploit_when_auth_or_injection(self):
        agent = self._agent()

        jwt = self._jwt()

        ffuf_auth = f'ffuf -u http://juiceshop:3000/rest/user/login -H "Authorization: Bearer {jwt}" -w w'
        ffuf_inject = 'ffuf -u "http://juiceshop:3000/rest/user/login?email=FUZZ" -w w -H "Cookie: token=abc" -mode clusterbomb -request "\' OR 1=1--"'
        wfuzz_auth = f'wfuzz -c -z file,w -H "Cookie: token={jwt}" "http://juiceshop:3000/api/Users?email=FUZZ"'
        wfuzz_inject = 'wfuzz -c -z file,w "http://juiceshop:3000/ftp?file=../../../../etc/passwd"'

        self.assertEqual(agent._classify_command_intent(ffuf_auth), "exploit")
        self.assertEqual(agent._classify_command_intent(ffuf_inject), "exploit")
        self.assertEqual(agent._classify_command_intent(wfuzz_auth), "exploit")
        self.assertEqual(agent._classify_command_intent(wfuzz_inject), "exploit")

        ffuf_enum = 'ffuf -u http://juiceshop:3000/FUZZ -w /usr/share/wordlists/dirb/common.txt'
        wfuzz_enum = 'wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt http://juiceshop:3000/FUZZ'
        self.assertEqual(agent._classify_command_intent(ffuf_enum), "enum")
        self.assertEqual(agent._classify_command_intent(wfuzz_enum), "enum")

    def test_is_scan_like_command_ffuf_wfuzz_only_when_enum_intent(self):
        agent = self._agent()

        jwt = self._jwt()

        ffuf_enum = 'ffuf -u http://juiceshop:3000/FUZZ -w w'
        wfuzz_enum = 'wfuzz -c -z file,w http://juiceshop:3000/FUZZ'
        ffuf_exploit = f'ffuf -u http://juiceshop:3000/rest/user/login -H "Authorization: Bearer {jwt}" -w w'
        wfuzz_exploit = f'wfuzz -c -z file,w -H "Cookie: token={jwt}" "http://juiceshop:3000/api/Users?email=FUZZ"'

        self.assertTrue(agent._is_scan_like_command(ffuf_enum))
        self.assertTrue(agent._is_scan_like_command(wfuzz_enum))
        self.assertFalse(agent._is_scan_like_command(ffuf_exploit))
        self.assertFalse(agent._is_scan_like_command(wfuzz_exploit))

    def test_recon_complete_gate_allows_exploit_intent_ffuf_wfuzz(self):
        agent = self._agent()
        agent.recon_phase_complete = True

        executed = []

        def fake_execute(exec_type, content, timeout=120):
            executed.append(content)
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

        jwt = self._jwt()
        ffuf_exploit = (
            f'ffuf -u http://juiceshop:3000/rest/user/login '
            f'-H "Authorization: Bearer {jwt}" -w {self.wordlist_path}'
        )
        agent.llm = FakeLLM([f"Do it.\n```bash\n{ffuf_exploit}\n```"])

        agent.max_iterations = 1
        agent.run(target="juiceshop", objective="test", resume=False)

        self.assertTrue(any("ffuf" in c for c in executed))

    def test_recon_complete_gate_blocks_enum_intent_ffuf_wfuzz(self):
        agent = self._agent()
        agent.recon_phase_complete = True

        executed = []

        def fake_execute(exec_type, content, timeout=120):
            executed.append(content)
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

        ffuf_enum = f'ffuf -u http://juiceshop:3000/FUZZ -w {self.wordlist_path}'
        agent.llm = FakeLLM([f"Try enum.\n```bash\n{ffuf_enum}\n```"])

        agent.max_iterations = 1
        agent.run(target="juiceshop", objective="test", resume=False)

        self.assertFalse(executed)
        # The recon-complete gate should have injected a specific nudge.
        last_user = [m for m in agent.conversation if m.get("role") == "user"][-1]["content"]
        self.assertIn("RECON ALREADY COMPLETE", last_user)

    def test_scan_with_unexploited_findings_gate_allows_exploit_intent_ffuf(self):
        agent = self._agent()
        # NOTE: structured_findings is re-synced from vulns_found every turn; seed vulns_found.
        agent.vulns_found = {
            "v1": {
                "type": "sql injection",
                "target": "juiceshop",
                "details": "seed",
                "exploited": False,
                "not_exploitable_reason": "",
                "attempt_count": 0,
            }
        }

        executed = []

        def fake_execute(exec_type, content, timeout=120):
            executed.append(content)
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

        jwt = self._jwt()
        ffuf_exploit = (
            f'ffuf -u http://juiceshop:3000/rest/user/login '
            f'-H "Authorization: Bearer {jwt}" -w {self.wordlist_path}'
        )
        agent.llm = FakeLLM([f"Exploit it.\n```bash\n{ffuf_exploit}\n```"])

        agent.max_iterations = 1
        agent.run(target="juiceshop", objective="test", resume=False)

        self.assertTrue(any("ffuf" in c for c in executed))

    def test_scan_with_unexploited_findings_gate_blocks_enum_intent_ffuf(self):
        agent = self._agent()
        # NOTE: structured_findings is re-synced from vulns_found every turn; seed vulns_found.
        agent.vulns_found = {
            "v1": {
                "type": "sql injection",
                "target": "juiceshop",
                "details": "seed",
                "exploited": False,
                "not_exploitable_reason": "",
                "attempt_count": 0,
            }
        }

        executed = []

        def fake_execute(exec_type, content, timeout=120):
            executed.append(content)
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

        ffuf_enum = f'ffuf -u http://juiceshop:3000/FUZZ -w {self.wordlist_path}'
        agent.llm = FakeLLM([f"Try enum.\n```bash\n{ffuf_enum}\n```"])

        agent.max_iterations = 1
        agent.run(target="juiceshop", objective="test", resume=False)

        self.assertFalse(executed)
        last_user = [m for m in agent.conversation if m.get("role") == "user"][-1]["content"]
        # Enforcement may happen via the explicit scan-with-unexploited-findings gate
        # or via the earlier exploit gate once the agent is forcing exploitation.
        # Either way, we expect a clear exploitation-required policy message.
        self.assertTrue(
            ("REJECTED" in last_user) or ("POLICY" in last_user) or ("EXPLOIT" in last_user.upper()),
            last_user,
        )

    def test_post_proof_hold_does_not_block_exploit_intent_fuzzers(self):
        agent = self._agent()
        agent.post_proof_hold_target = "juiceshop"
        agent.post_proof_hold_vuln_id = "v1"
        agent.post_proof_hold_min_actions = 2
        agent.post_proof_hold_max_blocks = 8
        agent.post_proof_hold_actions = 0
        agent.post_proof_hold_blocks = 0

        jwt = self._jwt()
        ffuf_exploit = f'ffuf -u http://juiceshop:3000/rest/user/login -H "Authorization: Bearer {jwt}" -w w'
        wfuzz_exploit = f'wfuzz -c -z file,w -H "Cookie: token={jwt}" "http://juiceshop:3000/api/Users?email=FUZZ"'

        self.assertIsNone(agent._post_proof_hold_violation(ffuf_exploit))
        self.assertIsNone(agent._post_proof_hold_violation(wfuzz_exploit))

        ffuf_enum = 'ffuf -u http://juiceshop:3000/FUZZ -w w'
        msg = agent._post_proof_hold_violation(ffuf_enum)
        self.assertIsInstance(msg, str)
        self.assertIn("POST-PROOF HOLD", msg)


if __name__ == "__main__":
    unittest.main()
