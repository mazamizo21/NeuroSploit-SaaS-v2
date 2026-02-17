#!/usr/bin/env python3
"""verify_callback.py — Poll Sliver for C2 callbacks matching a target IP.

After delivering an implant, this script polls for new sessions/beacons
until a callback from the target IP is detected or timeout is reached.

Usage:
    python3 verify_callback.py --target 192.168.4.125 --timeout 120
    python3 verify_callback.py --target 192.168.4.125 --mode beacon --retries 5

Outputs:
    - c2_session.json artifact to --output-dir
    - Prints session details on success
"""

import argparse
import asyncio
import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("verify_callback")

SLIVER_CLIENT = os.getenv("SLIVER_CLIENT_BIN", "/usr/local/bin/sliver-client")
SLIVER_CONFIG = os.getenv("SLIVER_CONFIG", "/opt/sliver/configs/kali-operator.cfg")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/pentest/output")


def poll_sessions_cli(target_ip: str, mode: str = "session") -> dict | None:
    """Poll sliver-client for sessions matching target IP (CLI approach)."""
    cmd = [SLIVER_CLIENT]
    if os.path.isfile(SLIVER_CONFIG):
        cmd.extend(["--config", SLIVER_CONFIG])

    if mode == "beacon":
        cmd.append("beacons")
    else:
        cmd.append("sessions")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            log.debug(f"sliver-client returned {result.returncode}: {result.stderr.strip()}")
            return None

        return _parse_session_output(result.stdout, target_ip, mode)
    except subprocess.TimeoutExpired:
        log.warning("sliver-client command timed out")
        return None
    except FileNotFoundError:
        log.error(f"sliver-client not found at {SLIVER_CLIENT}")
        return None


async def poll_sessions_grpc(target_ip: str, mode: str = "session") -> dict | None:
    """Poll Sliver gRPC API for sessions matching target IP (Python API approach)."""
    try:
        from sliver import SliverClientConfig, SliverClient
    except ImportError:
        log.warning("sliver-py not available, falling back to CLI")
        return None

    if not os.path.isfile(SLIVER_CONFIG):
        log.warning(f"Sliver config not found at {SLIVER_CONFIG}, falling back to CLI")
        return None

    try:
        config = SliverClientConfig.parse_config_file(SLIVER_CONFIG)
        client = SliverClient(config)
        await client.connect()

        if mode == "beacon":
            beacons = await client.beacons()
            for b in beacons:
                remote = getattr(b, "RemoteAddress", "") or ""
                if target_ip in remote:
                    return {
                        "session_id": b.ID,
                        "type": "beacon",
                        "target_ip": target_ip,
                        "target_os": getattr(b, "OS", "unknown"),
                        "target_arch": getattr(b, "Arch", "unknown"),
                        "username": f"{getattr(b, 'Hostname', '')}\\{getattr(b, 'Username', '')}",
                        "hostname": getattr(b, "Hostname", "unknown"),
                        "pid": getattr(b, "PID", 0),
                        "transport": getattr(b, "Transport", "unknown"),
                        "remote_address": remote,
                        "implant_name": getattr(b, "Name", "unknown"),
                    }
        else:
            sessions = await client.sessions()
            for s in sessions:
                remote = getattr(s, "RemoteAddress", "") or ""
                if target_ip in remote:
                    return {
                        "session_id": s.ID,
                        "type": "session",
                        "target_ip": target_ip,
                        "target_os": getattr(s, "OS", "unknown"),
                        "target_arch": getattr(s, "Arch", "unknown"),
                        "username": f"{getattr(s, 'Hostname', '')}\\{getattr(s, 'Username', '')}",
                        "hostname": getattr(s, "Hostname", "unknown"),
                        "pid": getattr(s, "PID", 0),
                        "transport": getattr(s, "Transport", "unknown"),
                        "remote_address": remote,
                        "implant_name": getattr(s, "Name", "unknown"),
                    }
    except Exception as e:
        log.warning(f"gRPC poll failed: {e}")
        return None

    return None


def _parse_session_output(output: str, target_ip: str, mode: str) -> dict | None:
    """Parse sliver-client sessions/beacons text output to find target IP match."""
    for line in output.strip().splitlines():
        if target_ip in line:
            # Parse tab/space-separated output
            parts = line.split()
            if len(parts) >= 6:
                return {
                    "session_id": parts[0],
                    "type": mode,
                    "target_ip": target_ip,
                    "target_os": parts[2] if len(parts) > 2 else "unknown",
                    "target_arch": parts[3] if len(parts) > 3 else "unknown",
                    "username": parts[4] if len(parts) > 4 else "unknown",
                    "hostname": parts[5] if len(parts) > 5 else "unknown",
                    "pid": 0,
                    "transport": parts[1] if len(parts) > 1 else "unknown",
                    "remote_address": target_ip,
                    "implant_name": parts[0],
                    "raw_line": line.strip(),
                }
    return None


def write_c2_session_artifact(session_info: dict, output_dir: str, job_id: str = "") -> str:
    """Write c2_session.json artifact for phase gate consumption."""
    # NOTE:
    # - The DynamicAgent already runs with --output-dir=/pentest/output/<JOB_ID>, and also sets JOB_ID.
    # - If we always nest output_dir/JOB_ID, we'd incorrectly write:
    #     /pentest/output/<JOB_ID>/<JOB_ID>/c2_session.json
    #   which the C2 phase gate will NOT find.
    artifact_dir = output_dir
    if job_id:
        try:
            out_base = os.path.basename(os.path.abspath(output_dir))
        except Exception:
            out_base = ""
        if out_base != job_id:
            artifact_dir = os.path.join(output_dir, job_id)
    os.makedirs(artifact_dir, exist_ok=True)

    artifact = {
        "sessions": [
            {
                "session_id": session_info["session_id"],
                "type": session_info["type"],
                "target_ip": session_info["target_ip"],
                "target_os": session_info.get("target_os", "unknown"),
                "target_arch": session_info.get("target_arch", "unknown"),
                "username": session_info.get("username", "unknown"),
                "hostname": session_info.get("hostname", "unknown"),
                "pid": session_info.get("pid", 0),
                "transport": session_info.get("transport", "unknown"),
                "implant_name": session_info.get("implant_name", "unknown"),
                "established_at": datetime.now(timezone.utc).isoformat(),
            }
        ],
        "verified_at": datetime.now(timezone.utc).isoformat(),
    }

    path = os.path.join(artifact_dir, "c2_session.json")
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    log.info(f"C2 session artifact written to {path}")
    return path


def verify_callback(
    target_ip: str,
    mode: str = "session",
    timeout: int = 120,
    poll_interval: int = 5,
    retries: int = 3,
    output_dir: str = OUTPUT_DIR,
    job_id: str = "",
    use_grpc: bool = True,
) -> dict:
    """Poll for C2 callback with timeout and retry logic.

    Returns a result dict with status and session info on success.
    """
    start_time = time.time()
    attempt = 0
    total_polls = 0

    log.info(f"Waiting for {mode} callback from {target_ip} (timeout={timeout}s, retries={retries})")

    while attempt < retries:
        attempt += 1
        attempt_start = time.time()
        log.info(f"Attempt {attempt}/{retries}")

        while (time.time() - start_time) < timeout:
            total_polls += 1
            elapsed = round(time.time() - start_time, 1)
            log.debug(f"Poll #{total_polls} at {elapsed}s...")

            # Try gRPC first, fall back to CLI
            session_info = None
            if use_grpc:
                try:
                    session_info = asyncio.run(poll_sessions_grpc(target_ip, mode))
                except Exception:
                    pass

            if session_info is None:
                session_info = poll_sessions_cli(target_ip, mode)

            if session_info:
                elapsed_total = round(time.time() - start_time, 2)
                log.info(
                    f"Callback received from {target_ip}! "
                    f"Session ID: {session_info['session_id']} "
                    f"({elapsed_total}s, {total_polls} polls)"
                )

                # Write artifact
                artifact_path = write_c2_session_artifact(session_info, output_dir, job_id)

                return {
                    "status": "success",
                    "session": session_info,
                    "artifact_path": artifact_path,
                    "elapsed_s": elapsed_total,
                    "polls": total_polls,
                    "attempt": attempt,
                }

            time.sleep(poll_interval)

        log.warning(f"Attempt {attempt} timed out after {timeout}s")

    elapsed_total = round(time.time() - start_time, 2)
    log.error(f"No callback received from {target_ip} after {retries} attempts ({elapsed_total}s)")

    return {
        "status": "timeout",
        "error": f"No callback from {target_ip} after {retries} attempts",
        "elapsed_s": elapsed_total,
        "polls": total_polls,
        "target_ip": target_ip,
        "mode": mode,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Verify Sliver C2 callback from a target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("--target", required=True,
                        help="Target IP to look for in callbacks")
    parser.add_argument("--mode", default="session", choices=["session", "beacon"],
                        help="Implant type to look for (default: session)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Per-attempt timeout in seconds (default: 120)")
    parser.add_argument("--poll-interval", type=int, default=5,
                        help="Seconds between polls (default: 5)")
    parser.add_argument("--retries", type=int, default=3,
                        help="Number of retry attempts (default: 3)")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help=f"Output directory for c2_session.json (default: {OUTPUT_DIR})")
    parser.add_argument("--job-id", default=os.getenv("JOB_ID", ""),
                        help="Job ID for artifact path nesting")
    parser.add_argument("--no-grpc", action="store_true",
                        help="Skip gRPC and use CLI only")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")

    args = parser.parse_args()

    result = verify_callback(
        target_ip=args.target,
        mode=args.mode,
        timeout=args.timeout,
        poll_interval=args.poll_interval,
        retries=args.retries,
        output_dir=args.output_dir,
        job_id=args.job_id,
        use_grpc=not args.no_grpc,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["status"] == "success":
            s = result["session"]
            print(f"[+] C2 Callback Confirmed!")
            print(f"    Session ID: {s['session_id']}")
            print(f"    Type: {s['type']}")
            print(f"    Target: {s['target_ip']}")
            print(f"    OS/Arch: {s.get('target_os', '?')}/{s.get('target_arch', '?')}")
            print(f"    User: {s.get('username', '?')}")
            print(f"    Host: {s.get('hostname', '?')}")
            print(f"    Transport: {s.get('transport', '?')}")
            print(f"    Time: {result['elapsed_s']}s ({result['polls']} polls)")
            print(f"    Artifact: {result.get('artifact_path', 'N/A')}")
        else:
            print(f"[-] No callback: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
