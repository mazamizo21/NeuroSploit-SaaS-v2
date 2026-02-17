"""Root conftest.py — shared fixtures for all TazoSploit tests."""

import os
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
OPEN_INTERPRETER = ROOT / "kali-executor" / "open-interpreter"
SKILLS_DIR = ROOT / "skills"
CONTROL_PLANE = ROOT / "control-plane"

# Ensure production source is importable
for p in (str(OPEN_INTERPRETER), str(ROOT)):
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def project_root() -> Path:
    return ROOT


@pytest.fixture()
def skills_dir() -> Path:
    return SKILLS_DIR


@pytest.fixture()
def open_interpreter_dir() -> Path:
    return OPEN_INTERPRETER


@pytest.fixture()
def env_patch(monkeypatch):
    """Provide a monkeypatch pre-configured with sane defaults for agent tests."""
    defaults = {
        "ALLOW_FULL_PORT_SCAN": "false",
        "ALLOW_MULTI_TARGET_SCAN": "false",
        "ALLOW_COMMAND_CHAINING": "false",
        "ALLOW_MULTI_BLOCKS": "false",
        "RECON_BASELINE_TOP_PORTS": "200",
        "LOG_DIR": "/tmp/tazosploit_tests",
        "KNOWLEDGE_GRAPH_ENABLED": "false",
        "REDIS_URL": "",
    }
    for k, v in defaults.items():
        monkeypatch.setenv(k, v)
    return monkeypatch
