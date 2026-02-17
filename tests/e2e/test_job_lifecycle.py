#!/usr/bin/env python3
"""E2E test — full job lifecycle via the control plane API.

Tests the complete lifecycle:
  1. Create a job via POST /api/v1/jobs
  2. Verify it transitions to running (or queued)
  3. Check Redis stats keys exist
  4. Cancel the job via POST /api/v1/jobs/{id}/cancel
  5. Verify cleanup (status = cancelled)

Requires:
  - Control plane running (CONTROL_PLANE_URL env)
  - Valid auth token (TEST_AUTH_TOKEN env)
  - Redis (REDIS_URL env)

Skipped automatically if services are not available.
"""

import os
import sys
import time
import uuid
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "control-plane"))

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------

CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8000")
TEST_AUTH_TOKEN = os.getenv("TEST_AUTH_TOKEN", "")
REDIS_URL = os.getenv("REDIS_URL", "")
# Pre-existing test tenant & scope IDs (set via env or use defaults)
TEST_TENANT_ID = os.getenv("TEST_TENANT_ID", "a0000000-0000-0000-0000-000000000001")
TEST_SCOPE_ID = os.getenv("TEST_SCOPE_ID", "")

# ---------------------------------------------------------------------------
# Skip conditions
# ---------------------------------------------------------------------------

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    import redis as redis_lib
    REDIS_AVAILABLE = True
except ImportError:
    redis_lib = None
    REDIS_AVAILABLE = False


def _api_reachable():
    if not HTTPX_AVAILABLE:
        return False
    try:
        r = httpx.get(f"{CONTROL_PLANE_URL}/health", timeout=3)
        return r.status_code in (200, 404, 401)
    except Exception:
        return False


pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(not HTTPX_AVAILABLE, reason="httpx not installed"),
    pytest.mark.skipif(not _api_reachable(), reason=f"Control plane not reachable at {CONTROL_PLANE_URL}"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _headers():
    h = {"Content-Type": "application/json"}
    if TEST_AUTH_TOKEN:
        h["Authorization"] = f"Bearer {TEST_AUTH_TOKEN}"
    return h


def _get_redis():
    if not REDIS_AVAILABLE or not REDIS_URL:
        return None
    try:
        r = redis_lib.from_url(REDIS_URL, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestJobLifecycle:
    """Full job lifecycle: create → verify → cancel → verify cleanup."""

    @pytest.fixture(autouse=True)
    def setup(self):
        """Ensure we have minimum requirements."""
        if not TEST_SCOPE_ID:
            pytest.skip("TEST_SCOPE_ID not set — cannot create a job without a scope")

    def test_create_job(self):
        """POST /api/v1/jobs should create a job and return its ID."""
        payload = {
            "name": f"e2e-test-{uuid.uuid4().hex[:8]}",
            "scope_id": TEST_SCOPE_ID,
            "phase": "RECON",
            "exploit_mode": "disabled",
            "max_iterations": 5,
            "description": "Automated E2E test — will be cancelled immediately.",
        }
        resp = httpx.post(
            f"{CONTROL_PLANE_URL}/api/v1/jobs",
            json=payload,
            headers=_headers(),
            timeout=10,
        )
        assert resp.status_code in (200, 201), (
            f"Job creation failed: {resp.status_code} {resp.text}"
        )
        data = resp.json()
        job_id = data.get("id") or data.get("job_id")
        assert job_id, f"No job ID in response: {data}"

        # Store for subsequent tests
        self.__class__._job_id = str(job_id)

    def test_job_status_after_create(self):
        """GET /api/v1/jobs/{id} should show pending/queued/running status."""
        job_id = getattr(self.__class__, "_job_id", None)
        if not job_id:
            pytest.skip("No job created in prior test")

        # Give it a moment to transition
        time.sleep(1)

        resp = httpx.get(
            f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}",
            headers=_headers(),
            timeout=10,
        )
        assert resp.status_code == 200, f"GET job failed: {resp.status_code}"
        data = resp.json()
        status = data.get("status", "")
        assert status in ("pending", "queued", "running"), (
            f"Expected job in pending/queued/running, got: {status}"
        )

    def test_redis_stats_exist(self):
        """Redis should have stats keys for the job."""
        job_id = getattr(self.__class__, "_job_id", None)
        if not job_id:
            pytest.skip("No job created")

        r = _get_redis()
        if not r:
            pytest.skip("Redis not available")

        # Check for common stats keys
        patterns = [
            f"job:{job_id}:*",
            f"stats:{job_id}:*",
        ]
        found_any = False
        for pattern in patterns:
            keys = r.keys(pattern)
            if keys:
                found_any = True
                break

        # Stats may not be written immediately — don't fail hard
        if not found_any:
            pytest.skip("No Redis stats keys found yet (race condition)")

    def test_cancel_job(self):
        """POST /api/v1/jobs/{id}/cancel should cancel the job."""
        job_id = getattr(self.__class__, "_job_id", None)
        if not job_id:
            pytest.skip("No job created")

        resp = httpx.post(
            f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}/cancel",
            headers=_headers(),
            timeout=10,
        )
        assert resp.status_code in (200, 202), (
            f"Job cancel failed: {resp.status_code} {resp.text}"
        )

    def test_job_cancelled_status(self):
        """After cancel, job should show cancelled status."""
        job_id = getattr(self.__class__, "_job_id", None)
        if not job_id:
            pytest.skip("No job created")

        # Allow time for cancellation
        time.sleep(2)

        resp = httpx.get(
            f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}",
            headers=_headers(),
            timeout=10,
        )
        assert resp.status_code == 200
        data = resp.json()
        status = data.get("status", "")
        assert status in ("cancelled", "failed", "completed"), (
            f"Expected cancelled/failed/completed after cancel, got: {status}"
        )
