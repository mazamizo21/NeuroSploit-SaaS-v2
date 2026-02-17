"""Sprint 3 unit tests: per-job settings (Redis overrides).

Covers:
- kali-executor/open-interpreter/project_settings.py sanitization + env application
- dynamic_agent.py integration (loads settings from Redis and applies before reading flags)
- control-plane/api/utils/job_settings.py settings sanitization helper (stdlib-only)
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _repo_root() -> Path:
    here = Path(__file__).resolve()
    return here.parents[2]


def _import_open_interpreter(name: str):
    import sys

    repo = _repo_root()
    oi_dir = repo / "kali-executor" / "open-interpreter"
    sys.path.insert(0, str(oi_dir))
    return __import__(name)


def _import_control_plane_job_settings():
    """Import the stdlib-only per-job settings sanitizer helpers.

    This avoids importing FastAPI (and the full router package) in unit tests.
    """

    import sys

    repo = _repo_root()
    control_plane_dir = repo / "control-plane"
    sys.path.insert(0, str(control_plane_dir))
    from api.utils import job_settings  # type: ignore

    return job_settings


class FakeRedis:
    def __init__(self, job_settings: dict | None = None):
        self._job_settings = job_settings or {}

    def get(self, key: str):
        if key.endswith(":settings"):
            return json.dumps(self._job_settings, ensure_ascii=True)
        return None

    def publish(self, *_args, **_kwargs):
        # No-op for AgentEventEmitter; unit tests don't need Redis pubsub.
        return 0


class TestProjectSettings(unittest.TestCase):
    def setUp(self):
        self.ps = _import_open_interpreter("project_settings")
        self._old_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)

    def test_load_settings_from_redis_sanitizes_and_bounds(self):
        overrides = {
            "use_structured_output": "true",
            "require_approval_for_exploitation": "yes",
            "REQUIRE_APPROVAL_FOR_POST_EXPLOITATION": 1,
            "KG_INJECT_EVERY": 0,  # bounded to >=1
            "KG_SUMMARY_MAX_CHARS": "999999",  # bounded
            "NOT_ALLOWED": True,
        }
        settings = self.ps.load_settings_from_redis(FakeRedis(overrides), job_id="job1")

        self.assertTrue(settings["USE_STRUCTURED_OUTPUT"])
        self.assertTrue(settings["REQUIRE_APPROVAL_FOR_EXPLOITATION"])
        self.assertTrue(settings["REQUIRE_APPROVAL_FOR_POST_EXPLOITATION"])
        self.assertEqual(settings["KG_INJECT_EVERY"], 1)
        self.assertEqual(settings["KG_SUMMARY_MAX_CHARS"], 20000)
        self.assertNotIn("NOT_ALLOWED", settings)

    def test_apply_settings_to_env_bool_and_int(self):
        settings = {
            "USE_STRUCTURED_OUTPUT": True,
            "KG_INJECT_EVERY": 7,
            "NOT_ALLOWED": "x",
        }
        self.ps.apply_settings_to_env(settings, override=True)

        self.assertEqual(os.environ.get("USE_STRUCTURED_OUTPUT"), "true")
        self.assertEqual(os.environ.get("KG_INJECT_EVERY"), "7")
        self.assertIsNone(os.environ.get("NOT_ALLOWED"))


class TestDynamicAgentJobSettingsIntegration(unittest.TestCase):
    def setUp(self):
        self.da = _import_open_interpreter("dynamic_agent")
        self.tmpdir_obj = tempfile.TemporaryDirectory()
        self.tmpdir = self.tmpdir_obj.name
        self._old_env = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        self.tmpdir_obj.cleanup()

    def test_dynamic_agent_applies_redis_job_settings_before_flag_reads(self):
        os.environ["JOB_ID"] = "job-sprint3"
        os.environ["REDIS_URL"] = "redis://fake"
        os.environ["KNOWLEDGE_GRAPH_ENABLED"] = "true"

        fake_redis = FakeRedis({"KNOWLEDGE_GRAPH_ENABLED": False})

        class _FakeRedisModule:
            @staticmethod
            def from_url(*_args, **_kwargs):
                return fake_redis

        with patch.object(self.da, "REDIS_SYNC_AVAILABLE", True), patch.object(self.da, "redis_sync", _FakeRedisModule):
            agent = self.da.DynamicAgent(log_dir=self.tmpdir, llm_provider=None)

        self.assertFalse(agent.knowledge_graph_enabled)


class TestControlPlaneJobSettingsSanitization(unittest.TestCase):
    def setUp(self):
        self.job_settings = _import_control_plane_job_settings()

    def test_sanitize_job_settings_allowlists_and_bounds(self):
        raw = {
            "use_structured_output": "yes",
            "require_approval_for_exploitation": True,
            "require_approval_for_post_exploitation": "true",
            "KG_INJECT_EVERY": 999,
            "KG_SUMMARY_MAX_CHARS": 10,
            "AUTO_COMPLETE_IDLE_ITERATIONS": 999999,
            "AUTO_COMPLETE_MIN_ITERATIONS": -5,
            "LLM_THINKING_ENABLED": "yes",
            "PASSWORD": "nope",
        }
        sanitized = self.job_settings.sanitize_job_settings(raw)

        self.assertEqual(sanitized["USE_STRUCTURED_OUTPUT"], True)
        self.assertEqual(sanitized["REQUIRE_APPROVAL_FOR_EXPLOITATION"], True)
        self.assertEqual(sanitized["REQUIRE_APPROVAL_FOR_POST_EXPLOITATION"], True)
        self.assertEqual(sanitized["KG_INJECT_EVERY"], 50)
        self.assertEqual(sanitized["KG_SUMMARY_MAX_CHARS"], 200)
        self.assertEqual(sanitized["AUTO_COMPLETE_IDLE_ITERATIONS"], 5000)
        self.assertEqual(sanitized["AUTO_COMPLETE_MIN_ITERATIONS"], 0)
        self.assertEqual(sanitized["LLM_THINKING_ENABLED"], True)
        self.assertNotIn("PASSWORD", sanitized)
