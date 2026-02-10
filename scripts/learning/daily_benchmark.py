#!/usr/bin/env python3
"""
Daily lab benchmark runner for TazoSploit.

Creates a lab job via control-plane API, waits for completion,
computes a score, and writes a learning gate file for reflection.
"""

import argparse
import json
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone


DEFAULT_SCOPE_ID = "c0000000-0000-0000-0000-000000000001"
DEFAULT_TARGETS = ["dvwa"]
DEFAULT_PHASE = "FULL"
DEFAULT_TARGET_TYPE = "lab"
DEFAULT_EXPLOIT_MODE = "autonomous"
DEFAULT_TIMEOUT = 10800  # 3 hours
DEFAULT_MAX_ITERATIONS = 120
DEFAULT_POLL_INTERVAL = 20
DEFAULT_MAX_WAIT = 14400  # 4 hours


def _load_env_file(path: str) -> dict:
    env = {}
    if not path or not os.path.exists(path):
        return env
    try:
        with open(path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip().strip('"').strip("'")
    except Exception:
        return env
    return env


def _http_request(method: str, url: str, token: str, payload: dict = None, timeout: int = 30):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(body)
            except Exception:
                return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except Exception as e:
        return 0, str(e)


def _score_job(job: dict) -> dict:
    result = job.get("result") or {}
    findings_count = job.get("findings_count")
    if findings_count is None:
        findings = result.get("findings", [])
        findings_count = len(findings) if isinstance(findings, list) else 0
    critical = job.get("critical_count", 0) or 0
    high = job.get("high_count", 0) or 0

    total_exec = result.get("total_executions", 0) or 0
    success_exec = result.get("successful_executions", 0) or 0
    success_rate = (success_exec / total_exec) if total_exec else 0.0

    score = float(findings_count) + (2.0 * float(critical)) + float(high) + (success_rate * 10.0)
    return {
        "findings_count": int(findings_count),
        "critical_count": int(critical),
        "high_count": int(high),
        "total_executions": int(total_exec),
        "successful_executions": int(success_exec),
        "success_rate": round(success_rate, 4),
        "score": round(score, 4),
    }


def run_benchmark(
    control_plane_url: str,
    token: str,
    memory_dir: str,
    scope_id: str,
    targets: list,
    phase: str,
    target_type: str,
    exploit_mode: str,
    timeout_seconds: int,
    max_iterations: int,
    poll_interval: int,
    max_wait: int,
    llm_provider: str = None,
    supervisor_enabled: bool = True,
    supervisor_provider: str = None,
    score_delta: float = 0.0,
):
    job_payload = {
        "name": f"Daily Lab Benchmark {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "scope_id": scope_id,
        "phase": phase,
        "targets": targets,
        "target_type": target_type,
        "exploit_mode": exploit_mode,
        "timeout_seconds": timeout_seconds,
        "max_iterations": max_iterations,
        "llm_provider": llm_provider,
        "supervisor_enabled": supervisor_enabled,
        "supervisor_provider": supervisor_provider,
    }
    job_payload = {k: v for k, v in job_payload.items() if v is not None}

    status, data = _http_request(
        "POST",
        f"{control_plane_url}/api/v1/jobs",
        token,
        payload=job_payload,
        timeout=30,
    )
    if status not in (200, 201):
        raise RuntimeError(f"Failed to create job: {status} {data}")

    job_id = data.get("id") if isinstance(data, dict) else None
    if not job_id:
        raise RuntimeError("Job ID missing in response")

    start = time.time()
    last_status = None
    job = None
    while True:
        status, job = _http_request(
            "GET",
            f"{control_plane_url}/api/v1/jobs/{job_id}",
            token,
            payload=None,
            timeout=30,
        )
        if status != 200 or not isinstance(job, dict):
            raise RuntimeError(f"Failed to fetch job status: {status} {job}")
        last_status = job.get("status")
        if last_status in ("completed", "failed", "cancelled", "timeout"):
            break
        if time.time() - start > max_wait:
            raise TimeoutError("Benchmark job timed out waiting for completion")
        time.sleep(poll_interval)

    metrics = _score_job(job)
    now = datetime.now(timezone.utc).isoformat()

    bench_dir = os.path.join(memory_dir, "BENCHMARKS")
    runs_dir = os.path.join(bench_dir, "runs")
    os.makedirs(runs_dir, exist_ok=True)

    run_data = {
        "timestamp": now,
        "job_id": job_id,
        "status": last_status,
        "payload": job_payload,
        "metrics": metrics,
    }
    run_path = os.path.join(runs_dir, f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json")
    with open(run_path, "w") as f:
        json.dump(run_data, f, indent=2)

    baseline_path = os.path.join(bench_dir, "baseline.json")
    baseline_score = None
    if os.path.exists(baseline_path):
        try:
            with open(baseline_path, "r") as f:
                baseline = json.load(f)
                baseline_score = baseline.get("score")
        except Exception:
            baseline_score = None

    promote = False
    if last_status == "completed":
        if baseline_score is None:
            promote = True
            baseline_score = metrics["score"]
        else:
            promote = metrics["score"] >= (baseline_score + score_delta)
            if promote:
                baseline_score = metrics["score"]
    else:
        promote = False

    # Update baseline if improved or missing
    if promote:
        with open(baseline_path, "w") as f:
            json.dump(
                {"score": baseline_score, "updated": now, "job_id": job_id},
                f,
                indent=2,
            )

    gate_path = os.path.join(bench_dir, "learning_gate.json")
    gate = {
        "timestamp": now,
        "job_id": job_id,
        "status": last_status,
        "score": metrics["score"],
        "baseline_score": baseline_score,
        "score_delta": score_delta,
        "promote": promote,
    }
    with open(gate_path, "w") as f:
        json.dump(gate, f, indent=2)

    return {"job_id": job_id, "status": last_status, "metrics": metrics, "gate": gate, "run_path": run_path}


def main():
    parser = argparse.ArgumentParser(description="Run daily lab benchmark and write learning gate.")
    parser.add_argument("--control-plane-url", default=os.environ.get("CONTROL_PLANE_URL", "http://localhost:8000"))
    parser.add_argument("--memory-dir", default=os.environ.get("MEMORY_DIR", "./memory"))
    parser.add_argument("--env-file", default=os.environ.get("ENV_FILE", ".env"))
    parser.add_argument("--scope-id", default=os.environ.get("BENCHMARK_SCOPE_ID", DEFAULT_SCOPE_ID))
    parser.add_argument("--targets", default=os.environ.get("BENCHMARK_TARGETS", ",".join(DEFAULT_TARGETS)))
    parser.add_argument("--phase", default=os.environ.get("BENCHMARK_PHASE", DEFAULT_PHASE))
    parser.add_argument("--target-type", default=os.environ.get("BENCHMARK_TARGET_TYPE", DEFAULT_TARGET_TYPE))
    parser.add_argument("--exploit-mode", default=os.environ.get("BENCHMARK_EXPLOIT_MODE", DEFAULT_EXPLOIT_MODE))
    parser.add_argument("--timeout-seconds", type=int, default=int(os.environ.get("BENCHMARK_TIMEOUT", DEFAULT_TIMEOUT)))
    parser.add_argument("--max-iterations", type=int, default=int(os.environ.get("BENCHMARK_MAX_ITERATIONS", DEFAULT_MAX_ITERATIONS)))
    parser.add_argument("--poll-interval", type=int, default=int(os.environ.get("BENCHMARK_POLL_INTERVAL", DEFAULT_POLL_INTERVAL)))
    parser.add_argument("--max-wait", type=int, default=int(os.environ.get("BENCHMARK_MAX_WAIT", DEFAULT_MAX_WAIT)))
    parser.add_argument("--llm-provider", default=os.environ.get("BENCHMARK_LLM_PROVIDER", None))
    parser.add_argument("--supervisor-enabled", default=os.environ.get("BENCHMARK_SUPERVISOR_ENABLED", "true"))
    parser.add_argument("--supervisor-provider", default=os.environ.get("BENCHMARK_SUPERVISOR_PROVIDER", None))
    parser.add_argument("--score-delta", type=float, default=float(os.environ.get("BENCHMARK_SCORE_DELTA", "0.0")))
    args = parser.parse_args()

    env = _load_env_file(args.env_file)
    secret = os.environ.get("SECRET_KEY") or env.get("SECRET_KEY")
    if not secret:
        raise RuntimeError("SECRET_KEY not found in environment or .env")
    token = f"internal-{secret}"

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    supervisor_enabled = str(args.supervisor_enabled).lower() not in ("false", "0", "no")

    result = run_benchmark(
        control_plane_url=args.control_plane_url.rstrip("/"),
        token=token,
        memory_dir=args.memory_dir,
        scope_id=args.scope_id,
        targets=targets,
        phase=args.phase,
        target_type=args.target_type,
        exploit_mode=args.exploit_mode,
        timeout_seconds=args.timeout_seconds,
        max_iterations=args.max_iterations,
        poll_interval=args.poll_interval,
        max_wait=args.max_wait,
        llm_provider=args.llm_provider,
        supervisor_enabled=supervisor_enabled,
        supervisor_provider=args.supervisor_provider,
        score_delta=args.score_delta,
    )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
