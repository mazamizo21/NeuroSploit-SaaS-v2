"""
TazoSploit SaaS v2 - Worker
Executes pentest jobs via Kali containers with Open Interpreter
"""

import os
import asyncio
import json
import structlog
from datetime import datetime
import redis.asyncio as redis
import httpx
import docker

structlog.configure(processors=[
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.JSONRenderer()
])
logger = structlog.get_logger()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://api:8000")
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "lm-studio")
WORKER_ID = os.getenv("HOSTNAME", "worker-1")
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_JOB_TIMEOUT", "3600"))
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
INTERNAL_AUTH = f"internal-{SECRET_KEY}"


class Worker:
    def __init__(self):
        self.redis = None
        self.docker_client = docker.from_env()
        self.current_job = None
        self._cancel_event = asyncio.Event()

    @staticmethod
    def _is_container_not_found_error(e: Exception) -> bool:
        """Detect Docker errors caused by container restarts/removals while a job is running."""
        msg = str(e) or ""
        return (
            "No such container" in msg
            or "No such exec instance" in msg
            or ("404 Client Error" in msg and "/containers/" in msg)
        )

    async def _exec_run_retry(self, container, *, cmd, workdir: str = None, retries: int = 1):
        """Run exec in a Kali container, retrying if the container restarted mid-job."""
        cur = container
        last_err = None
        retries = max(0, int(retries or 0))
        for attempt in range(retries + 1):
            try:
                res = cur.exec_run(cmd=cmd, workdir=workdir) if workdir else cur.exec_run(cmd=cmd)
                return cur, res
            except Exception as e:
                last_err = e
                if attempt >= retries or not self._is_container_not_found_error(e):
                    raise
                # Best-effort: reacquire a reserved Kali container for the current job.
                new_container = await self._get_kali_container(
                    job_id=self.current_job,
                    ttl_seconds=DEFAULT_TIMEOUT + 600,
                )
                logger.warning(
                    "container_exec_retry",
                    job_id=self.current_job,
                    old_container_id=getattr(cur, "id", None),
                    new_container_id=getattr(new_container, "id", None),
                    error=str(e)[:200],
                )
                cur = new_container
        raise last_err
        
    @staticmethod
    def _is_valid_credential(username: str, password: str) -> bool:
        """Validate a credential pair before posting as loot. Rejects garbage from LLM parsing."""
        if not username or not password:
            return False
        u = username.strip().lower()
        p = password.strip()
        # Too short
        if len(u) < 2 or len(p) < 2:
            return False
        # Reject known garbage words that appear as usernames from bad parsing
        garbage_words = {
            "evidence", "proof", "cat", "prefix", "dump", "passwords", "password",
            "assignment", "id", "access", "output", "result", "response", "unknown",
            "extracted", "found", "discovered", "obtained", "credential", "credentials",
            "finding", "findings", "vulnerability", "exploit", "shell", "command",
            "query", "select", "insert", "update", "delete", "from", "where",
            "curl", "wget", "echo", "grep", "awk", "sed", "type", "hash", "key",
            "value", "string", "object", "array", "iteration", "target", "service",
            "source", "method", "token", "data", "table", "tables", "records",
            "record", "user", "username", "email", "dumped", "jwt", "true", "false",
            "null", "none", "undefined", "test",
        }
        if u in garbage_words:
            return False
        # Reject pure numeric usernames
        if u.isdigit():
            return False
        # Reject numeric-only passwords (likely ports or IDs)
        if p.isdigit() and len(p) <= 5:
            return False
        # Reject HTML/XML junk
        junk_markers = ["<em", "//www.", ".dtd", ".org/", "<!doctype", "<html", "xmlns"]
        if any(j in u for j in junk_markers) or any(j in p.lower() for j in junk_markers):
            return False
        # Heuristic: pure alpha usernames that aren't service accounts are likely garbage
        if u.isalpha() and "@" not in u and "." not in u and "_" not in u and "-" not in u:
            if not any(c.isdigit() for c in u):
                service_accounts = {
                    "root", "admin", "app", "postgres", "mysql", "redis", "www",
                    "apache", "nginx", "ubuntu", "centos", "guest", "ftp",
                    "ssh", "git", "jenkins", "tomcat", "oracle", "sa",
                    "nobody", "daemon", "bin", "sys", "sync", "backup",
                    "bkimminich", "mc", "jim", "bender", "morty",
                }
                if u not in service_accounts:
                    return False
        return True

    @staticmethod
    def _map_severity(impact_text: str, exploited: bool = False, has_proof: bool = False) -> str:
        """Map impact text to severity level. Proven exploits of high-impact vuln types → critical."""
        impact_lower = impact_text.lower()
        
        # Vuln types that become CRITICAL when exploitation is proven
        critical_when_proven = [
            "sql injection", "sqli", "command injection", "rce", "remote code",
            "authentication bypass", "auth bypass", "deserialization",
        ]
        
        if 'critical' in impact_lower:
            return 'critical'
        # Upgrade to critical if exploit is proven for high-impact vuln types
        if (exploited or has_proof) and any(p in impact_lower for p in critical_when_proven):
            return 'critical'
        elif 'high' in impact_lower:
            return 'high'
        elif 'medium' in impact_lower:
            return 'medium'
        elif 'low' in impact_lower:
            return 'low'
        # Default: proven exploits are at least high
        if exploited or has_proof:
            return 'high'
        return 'high'
    
    @staticmethod
    def _format_finding_description(raw: str, vuln: dict = None) -> str:
        """Clean raw agent output into human-readable finding descriptions.
        
        The attack agent (GLM-4.7) often dumps bash commands, JSON blobs,
        and code blocks into the 'details' field. This extracts the useful
        info and formats it for the dashboard.
        """
        import re
        
        if not raw:
            # Fall back to structured fields if available
            if vuln:
                parts = []
                if vuln.get("type"):
                    parts.append(f"Type: {vuln['type'].title()}")
                if vuln.get("target"):
                    parts.append(f"Target: {vuln['target']}")
                return ", ".join(parts) if parts else "No details available"
            return "No details available"
        
        # 1. Strip markdown code blocks (```bash ... ```, ```json ... ```, etc.)
        cleaned = re.sub(r'```\w*\n?', '', raw)
        cleaned = cleaned.replace('```', '')
        
        # 2. Try to extract structured info from embedded JSON
        extracted_parts = []
        json_match = re.search(r'\{[^{}]*"(?:target|endpoint|method|token|access)"[^{}]*\}', cleaned)
        if json_match:
            try:
                import json
                obj = json.loads(json_match.group())
                # Flatten nested objects (e.g., {"access": {...}})
                if len(obj) == 1 and isinstance(list(obj.values())[0], dict):
                    obj = list(obj.values())[0]
                if obj.get("endpoint"):
                    extracted_parts.append(f"Endpoint: {obj['endpoint']}")
                if obj.get("method"):
                    extracted_parts.append(f"Method: {obj['method']}")
                if obj.get("target"):
                    extracted_parts.append(f"Target: {obj['target']}")
                if obj.get("role"):
                    extracted_parts.append(f"Role: {obj['role']}")
                if obj.get("token"):
                    token = obj["token"]
                    extracted_parts.append(f"Token: {token[:20]}...")
            except (json.JSONDecodeError, ValueError):
                pass
        
        # 2b. Fallback: extract key-value pairs from partial/truncated JSON via regex
        if not extracted_parts:
            kv_pairs = re.findall(r'"(endpoint|method|target|role)":\s*"([^"]+)"', cleaned)
            for key, val in kv_pairs:
                extracted_parts.append(f"{key.title()}: {val}")
        
        # 3. Strip shell commands (lines starting with common shell prefixes)
        lines = cleaned.split('\n')
        prose_lines = []
        for line in lines:
            stripped = line.strip()
            # Skip shell commands, pipes, and JSON blobs
            if re.match(r'^(bash|echo|curl|wget|cat|grep|awk|sed|python|nmap|sqlmap|hydra|nikto)\s', stripped, re.I):
                continue
            if stripped.startswith(('{', '[', '$', '#', '|', '>', '<')):
                continue
            if re.match(r"^['\"]?\{", stripped):
                continue
            if not stripped:
                continue
            prose_lines.append(stripped)
        
        # 4. Build the description
        description = ""
        
        # Use prose text if we found any meaningful lines
        prose = ' '.join(prose_lines).strip()
        if prose:
            # Truncate long prose
            description = prose[:300]
        
        # Append extracted structured data
        if extracted_parts:
            structured = " | ".join(extracted_parts)
            if description:
                description = f"{description}\n{structured}"
            else:
                description = structured
        
        # 5. Fallback: use vuln metadata
        if not description and vuln:
            parts = []
            if vuln.get("type"):
                parts.append(f"Type: {vuln['type'].title()}")
            if vuln.get("target"):
                parts.append(f"Target: {vuln['target']}")
            if vuln.get("exploit_evidence"):
                ev = vuln["exploit_evidence"][:200]
                parts.append(f"Evidence: {ev}")
            description = " | ".join(parts) if parts else "Vulnerability detected"
        
        return description[:500] if description else "Vulnerability detected"

    @staticmethod
    def _coerce_evidence_strings(findings: list) -> list:
        """Coerce evidence/proof_of_concept fields to strings (API expects str, agent sometimes returns list)."""
        if not findings:
            return findings or []
        for f in findings:
            if not isinstance(f, dict):
                continue
            for key in ("evidence", "proof_of_concept"):
                val = f.get(key)
                if isinstance(val, list):
                    f[key] = "\n".join(str(v) for v in val)
        return findings

    def _normalize_findings(self, findings: list) -> list:
        """Ensure all findings have required fields (title, severity, etc.)"""
        findings = self._coerce_evidence_strings(findings)
        normalized = []
        allowed_severities = {"critical", "high", "medium", "low", "info"}
        allowed_keys = {
            "title",
            "description",
            "severity",
            "finding_type",
            "type",
            "location",
            "cve_id",
            "cwe_id",
            "mitre_technique",
            "target",
            "evidence",
            "proof_of_concept",
            "remediation",
            # These are persisted in DB and used for accurate counts/UX.
            "verified",
            "is_false_positive",
        }
        for f in findings:
            if not isinstance(f, dict):
                continue
            # Map common aliases to API fields
            if "mitre_technique" not in f:
                if "mitre" in f:
                    f["mitre_technique"] = f.get("mitre")
                elif isinstance(f.get("mitre_techniques"), list) and f["mitre_techniques"]:
                    f["mitre_technique"] = f["mitre_techniques"][0]
            if "evidence" not in f and "proof" in f:
                f["evidence"] = f.get("proof")
            if "proof_of_concept" not in f and "poc" in f:
                f["proof_of_concept"] = f.get("poc")
            # Remove noisy aliases after mapping
            if "mitre" in f:
                f.pop("mitre", None)
            if "proof" in f:
                f.pop("proof", None)
            # Ensure title exists - required by API
            if 'title' not in f or not f['title']:
                # Generate title from other fields
                ftype = f.get('name') or f.get('type', 'Finding')
                location = f.get('location', f.get('target', f.get('endpoint', 'unknown')))
                f['title'] = f"{ftype} — {location}"
            # Ensure severity exists
            sev = f.get('severity') if f.get('severity') is not None else ""
            if isinstance(sev, str):
                sev = sev.strip().lower()
            else:
                sev = ""
            if not sev or sev not in allowed_severities:
                sev = self._map_severity(f.get('impact', f.get('description', '')))
            f['severity'] = sev
            # Require proof for high/critical: downgrade if evidence is weak or speculative
            try:
                desc_text = str(f.get("description", "") or "")
                ev_text = f.get("evidence") or f.get("proof_of_concept") or ""
                ev_text = str(ev_text).strip()
                speculative = any(k in desc_text.lower() for k in ["potential", "possible", "may be", "likely", "suspected", "could be"])
                if sev in {"critical", "high"}:
                    if (not ev_text) or len(ev_text) < 12 or speculative:
                        f['severity'] = "medium"
                        note = "UNVERIFIED: High/critical severity requires concrete proof; downgraded."
                        if desc_text:
                            f["description"] = (desc_text + " " + note)[:500]
                        else:
                            f["description"] = note
            except Exception:
                pass
            # Ensure finding_type exists
            if 'finding_type' not in f:
                f['finding_type'] = f.get('type', 'vulnerability')
            # Strip unknown keys to avoid 422 validation errors
            cleaned = {k: v for k, v in f.items() if k in allowed_keys and v is not None}
            normalized.append(cleaned)
        return normalized
    
    def _stream_line_sync(self, job_id: str, line: str):
        """Stream a line to Redis pubsub and buffer list (sync, for use in executor threads)

        SECURITY: redact secrets before they ever hit Redis/UI.
        """
        import redis as sync_redis
        import re
        try:
            # Redact common secrets (defense-in-depth)
            safe_line = line
            safe_line = re.sub(r"\bsk-[A-Za-z0-9_-]{10,}\b", "sk-***REDACTED***", safe_line)
            safe_line = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._-]{10,}\b", "Bearer ***REDACTED***", safe_line)
            safe_line = re.sub(r"\b[a-f0-9]{32}\.[A-Za-z0-9_-]{10,}\b", "***REDACTED_ZHIPU_KEY***", safe_line, flags=re.IGNORECASE)

            r = sync_redis.from_url(REDIS_URL, decode_responses=True)
            timestamp = datetime.utcnow().isoformat()
            msg = json.dumps({"line": safe_line, "timestamp": timestamp})
            # Publish for live WebSocket subscribers
            r.publish(f"job:{job_id}:output", msg)
            # Also buffer in a list for late-joining clients (keep last 1000 lines)
            r.rpush(f"job:{job_id}:log", msg)
            r.ltrim(f"job:{job_id}:log", -1000, -1)
            # Expire buffer after 24h
            r.expire(f"job:{job_id}:log", 86400)
            
            # Track live findings from [REMEMBER:] tags
            line_lower = line.lower()
            if "[remember:" in line_lower:
                # Increment live finding counters in Redis
                if "credential_found" in line_lower:
                    r.hincrby(f"job:{job_id}:live_stats", "credentials", 1)
                elif "vulnerability_found" in line_lower or "vulnerability_proven" in line_lower:
                    r.hincrby(f"job:{job_id}:live_stats", "vulnerabilities", 1)
                elif "access_gained" in line_lower:
                    r.hincrby(f"job:{job_id}:live_stats", "access_gained", 1)
                r.hincrby(f"job:{job_id}:live_stats", "total_findings", 1)
                # Fix #9: Track findings_this_run separately from inherited findings
                r.hincrby(f"job:{job_id}:live_stats", "findings_this_run", 1)
                r.expire(f"job:{job_id}:live_stats", 86400)
            
            # Track iteration count
            if "=== iteration" in line_lower and "/" in line:
                import re as _re
                m = _re.search(r'iteration\s+(\d+)/(\d+)', line_lower)
                if m:
                    r.hset(f"job:{job_id}:live_stats", "current_iteration", m.group(1))
                    r.hset(f"job:{job_id}:live_stats", "max_iterations", m.group(2))
                    r.expire(f"job:{job_id}:live_stats", 86400)
            
            r.close()
        except Exception as e:
            # Don't let streaming errors kill the job
            pass

    async def start(self):
        self.redis = redis.from_url(REDIS_URL, decode_responses=True)
        logger.info("worker_started", worker_id=WORKER_ID, llm_provider=LLM_PROVIDER)
        
        # Subscribe to kill signals
        pubsub = self.redis.pubsub()
        asyncio.create_task(self._listen_control(pubsub))
        
        while True:
            try:
                await self._process_jobs()
            except Exception as e:
                logger.error("worker_error", error=str(e))
            await asyncio.sleep(1)
    
    async def _listen_control(self, pubsub):
        """Listen for kill signals"""
        while True:
            try:
                await pubsub.psubscribe("job:*:control")
                async for message in pubsub.listen():
                    if message["type"] == "pmessage":
                        job_id = message["channel"].split(":")[1]
                        command = message["data"]
                        if command == "CANCEL" and self.current_job == job_id:
                            logger.info("job_cancel_received", job_id=job_id)
                            self._cancel_event.set()
            except Exception as e:
                logger.warn("control_listener_error", error=str(e))
                try:
                    await pubsub.close()
                except Exception:
                    pass
                # Reconnect pubsub after a short backoff
                await asyncio.sleep(2)
                self.redis = redis.from_url(REDIS_URL, decode_responses=True)
                pubsub = self.redis.pubsub()
    
    async def _process_jobs(self):
        # Get job from queue (blocking pop with timeout)
        result = await self.redis.brpop("worker:job_queue", timeout=5)
        
        if result:
            _, job_data = result
            job = json.loads(job_data)
            await self._execute_job(job)
    
    async def _execute_job(self, job: dict):
        job_id = job["job_id"]
        tenant_id = job["tenant_id"]
        # Fix #2: Validate job_id is a proper UUID to prevent injection
        import re as _re_validate
        if not _re_validate.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', str(job_id)):
            logger.error("invalid_job_id", job_id=str(job_id)[:50])
            return
        # N2: Check if job is already in a terminal state (prevents cancel-bounce re-dispatch)
        try:
            terminal = await self.redis.get(f"job:{job_id}:terminal")
            if terminal:
                logger.info("job_skipped_terminal", job_id=job_id, terminal_status=terminal)
                return
        except Exception:
            pass
        self.current_job = job_id
        self._cancel_event.clear()
        
        logger.info("job_executing", job_id=job_id, tenant_id=tenant_id)
        container = None  # Set once we successfully reserve a Kali executor container

        try:
            # Check if this is a resume
            is_resume = False
            try:
                resume_flag = await self.redis.get(f"job:{job_id}:resume")
                if resume_flag == "true":
                    is_resume = True
                    await self.redis.delete(f"job:{job_id}:resume")
                    logger.info("job_resuming", job_id=job_id)
            except Exception:
                pass
            
            # Get job details from control plane
            headers = {"Authorization": f"Bearer {INTERNAL_AUTH}"}
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}", headers=headers)
                if resp.status_code != 200:
                    raise Exception(f"Failed to get job details: {resp.status_code}")
                job_details = resp.json()

            phase = job_details.get("phase", "RECON")
            target_type = job_details.get("target_type", "lab")
            exploit_mode = job_details.get("exploit_mode", "explicit_only")

            # Enforce exploit mode policy
            if exploit_mode == "disabled" and phase in ("EXPLOIT", "POST_EXPLOIT", "LATERAL", "FULL"):
                msg = "Exploit mode disabled; exploit, post-exploit, lateral, and full phases are not allowed"
                logger.warning("exploit_mode_blocked", job_id=job_id, phase=phase)
                await self._update_job_status(job_id, "failed", {"error": msg})
                return

            # Enforce external exploit policy (explicit authorization only)
            if target_type == "external" and phase in ("EXPLOIT", "POST_EXPLOIT", "LATERAL", "FULL"):
                if not job_details.get("authorization_confirmed", False):
                    msg = "External exploit, post-exploit, lateral, and full phases require explicit authorization"
                    logger.warning("external_exploit_blocked", job_id=job_id, phase=phase)
                    await self._update_job_status(job_id, "failed", {"error": msg})
                    return
            
            # Update status to running (include worker_id for forensics).
            await self._update_job_status(job_id, "running", {})
            
            # Find available Kali container
            timeout_seconds = int(job_details.get("timeout_seconds", DEFAULT_TIMEOUT) or DEFAULT_TIMEOUT)
            container = await self._get_kali_container(job_id=job_id, ttl_seconds=timeout_seconds + 600)
            # Record container mapping on the job as soon as we have it (for forensics/debugging).
            try:
                await self._update_job_status(job_id, "running", {}, container_id=container.id)
            except Exception:
                pass
            
            # Execute via direct exec into container
            output_dir = f"/pentest/output/{job_id}"
            result = await self._run_in_container(container, job_details, job_id, tenant_id, resume=is_resume)
            result["job_phase"] = phase
            
            # Post structured findings to API
            await self._post_findings_and_loot(job_id, tenant_id, result, container, output_dir)
            
            # Extract token usage from llm_stats
            llm_stats = result.get("llm_stats", {})
            tokens_used = llm_stats.get("total_tokens", 0)
            cost_usd = llm_stats.get("total_cost_usd", 0.0)
            result["tokens_used"] = tokens_used
            result["cost_usd"] = cost_usd
            result_findings = len(result.get("findings", []) or [])
            live_findings = int(result.get("live_findings_count") or 0)
            summary_findings = max(result_findings, live_findings)

            # If agent was stopped (pause), mark as paused (stop/resume flow)
            paused_flag = bool(result.get("paused") or str(result.get("status") or "").lower() == "paused")

            # N2: If cancel was triggered during execution, mark as completed_by_cancel
            if self._cancel_event.is_set():
                await self._update_job_status(job_id, "cancelled", result, container_id=getattr(container, "id", None))
                await self.redis.set(f"job:{job_id}:terminal", "cancelled", ex=86400)
                logger.info(
                    "job_completed_by_cancel",
                    job_id=job_id,
                    findings=summary_findings,
                    result_findings=result_findings,
                    live_findings=live_findings,
                )
            elif paused_flag:
                await self._update_job_status(job_id, "paused", result, container_id=getattr(container, "id", None))
                await self.redis.set(f"job:{job_id}:terminal", "paused", ex=86400)
                logger.info(
                    "job_paused",
                    job_id=job_id,
                    findings=summary_findings,
                    iteration=result.get("iterations"),
                )
            else:
                # Update job status with full result
                await self._update_job_status(job_id, "completed", result, container_id=getattr(container, "id", None))
                await self.redis.set(f"job:{job_id}:terminal", "completed", ex=86400)
                logger.info(
                    "job_completed",
                    job_id=job_id,
                    findings=summary_findings,
                    result_findings=result_findings,
                    live_findings=live_findings,
                )
            
        except Exception as e:
            logger.error("job_failed", job_id=job_id, error=str(e))
            await self._update_job_status(job_id, "failed", {"error": str(e)})
            try:
                await self.redis.set(f"job:{job_id}:terminal", "failed", ex=86400)
            except Exception:
                pass
        
        finally:
            # Release Kali executor reservation (prevents multiple jobs colliding in the same container)
            try:
                if container is not None and self.redis is not None:
                    key = f"kali:{container.id}:lock"
                    val = await self.redis.get(key)
                    if val == str(job_id):
                        await self.redis.delete(key)
            except Exception:
                pass
            self.current_job = None
    
    async def _get_kali_container(self, job_id: str = None, ttl_seconds: int = None):
        """Get an available Kali container from the pool.

        IMPORTANT: we reserve containers with a Redis lock so multiple workers don't pick the same
        Kali executor concurrently (cross-job interference and unsafe pkill side-effects).
        """
        # If Redis isn't ready yet, fall back to best-effort selection.
        can_lock = bool(job_id and self.redis is not None)
        ttl = int(ttl_seconds or DEFAULT_TIMEOUT or 3600)
        wait_s = int(os.getenv("KALI_ACQUIRE_WAIT_SECONDS", "60"))
        sleep_s = float(os.getenv("KALI_ACQUIRE_RETRY_SECONDS", "1"))
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(1, wait_s)

        def _candidate_kali_containers():
            # Try multiple strategies to find running Kali containers
            containers = self.docker_client.containers.list(
                filters={"label": "tazosploit.role=kali-executor", "status": "running"}
            )
            if containers:
                return containers

            all_running = self.docker_client.containers.list(filters={"status": "running"})
            kali_containers = [
                c for c in all_running
                if any(pat in c.name.lower() for pat in ["kali-executor", "tazosploit-kali-", "tazosploit_kali"])
            ]
            if kali_containers:
                return kali_containers

            # Fallback by image tag match
            out = []
            for c in all_running:
                try:
                    img_tags = c.image.tags
                    if any("kali" in t.lower() for t in img_tags):
                        out.append(c)
                except Exception:
                    pass
            return out

        while True:
            candidates = list(_candidate_kali_containers())
            # Stable ordering avoids stampedes (both workers grabbing the same "first" container).
            candidates.sort(key=lambda c: c.name)

            if not candidates:
                raise Exception("No Kali containers available. Is the kali service running?")

            if not can_lock:
                return candidates[0]

            for c in candidates:
                key = f"kali:{c.id}:lock"
                try:
                    ok = await self.redis.set(key, str(job_id), nx=True, ex=ttl)
                except Exception:
                    ok = None
                if ok:
                    return c

            if loop.time() >= deadline:
                raise Exception("No free Kali containers available (all locked). Try scaling kali executors.")
            await asyncio.sleep(max(0.1, sleep_s))
    
    async def _run_in_container(self, container, job_details: dict, job_id: str, tenant_id: str, resume: bool = False) -> dict:
        """Execute job in Kali container by directly exec'ing the dynamic agent"""
        # Publish container mapping for supervisor actions
        try:
            await self.redis.set(f"job:{job_id}:kali_container", container.id, ex=86400)
            await self.redis.set(f"job:{job_id}:kali_container_name", container.name, ex=86400)
            await self.redis.set(f"job:{job_id}:kali_log_dir", f"/pentest/output/{job_id}", ex=86400)
        except Exception:
            pass
        
        target = job_details.get("targets", [""])[0] if job_details.get("targets") else ""
        phase = job_details.get("phase", "RECON")
        target_type = job_details.get("target_type", "lab")
        exploit_mode = job_details.get("exploit_mode", "explicit_only")
        timeout_seconds = job_details.get("timeout_seconds", DEFAULT_TIMEOUT)
        # More iterations for exploit/full phases
        default_iterations = 30 if phase in ("EXPLOIT", "FULL", "POST_EXPLOIT", "LATERAL") else 20
        max_iterations = job_details.get("max_iterations", default_iterations)
        
        # Auto-escalation and restriction relaxation (lab + autonomous by default)
        auto_escalate_recon = job_details.get("auto_escalate_recon")
        if auto_escalate_recon is None:
            auto_escalate_recon = (target_type == "lab" and exploit_mode == "autonomous")
        allow_exploit_any_phase = job_details.get("allow_exploit_any_phase")
        if allow_exploit_any_phase is None:
            allow_exploit_any_phase = auto_escalate_recon
        relax_exploit_restrictions = job_details.get("relax_exploit_restrictions")
        if relax_exploit_restrictions is None:
            relax_exploit_restrictions = (target_type == "lab" and exploit_mode == "autonomous")

        # Build the objective from phase and any custom objective
        description = job_details.get("description", "") or ""
        objective = job_details.get("objective", "") or description
        # If this is a focused exploit subjob, force the description as objective.
        if description and "Exploit focus:" in description:
            objective = description
        if not objective:
            if target_type == "external":
                # External targets: adapt objectives for internet-facing scanning
                phase_objectives = {
                    "RECON": f"Perform reconnaissance on external target {target}. Start with passive recon (WHOIS, DNS, certificate transparency, web tech fingerprinting). Then do careful active scanning (nmap with reasonable rate limits, HTTP header analysis, directory enumeration). This is an internet-facing target - be methodical and avoid overwhelming the target.",
                    "VULN_SCAN": f"Scan external target {target} for vulnerabilities. Use nikto, nuclei, or similar tools. Check for common web vulnerabilities, misconfigurations, and outdated software. Rate-limit your requests.",
                    "EXPLOIT": f"Attempt to exploit discovered vulnerabilities on external target {target}. Focus on web application attacks (SQL injection, XSS, SSRF, etc.). Be careful and targeted - this is a real internet-facing system.",
                    "POST_EXPLOIT": f"After gaining access to {target}, enumerate internal resources, attempt privilege escalation, and document findings.",
                    "LATERAL": f"After initial access to {target}, attempt lateral movement within approved scope and document privilege escalation and data access.",
                    "FULL": f"Run an end-to-end assessment of external target {target}. Perform recon and vuln scanning, then validate exploitation and post-exploit steps only if explicitly authorized.",
                    "REPORT": f"Generate comprehensive security assessment report for external target {target}."
                }
            else:
                phase_objectives = {
                    "RECON": f"Perform full reconnaissance on {target}. Discover services, technologies, and potential vulnerabilities.",
                    "VULN_SCAN": f"Scan {target} for vulnerabilities using nikto, nmap scripts, and other vulnerability scanners.",
                    "EXPLOIT": f"Exploit discovered vulnerabilities on {target}. Attempt SQL injection, XSS, command injection, and other web attacks.",
                    "POST_EXPLOIT": f"After gaining access on {target}, enumerate internal resources, attempt lateral movement, and document privilege escalation and data access.",
                    "LATERAL": f"After initial access on {target}, attempt lateral movement, privilege escalation, and data exfiltration.",
                    "FULL": f"Complete penetration test of {target}. Recon, exploit, persist, and exfiltrate."
                }
            objective = phase_objectives.get(phase, f"Security assessment of {target}")

        if auto_escalate_recon and phase == "RECON" and exploit_mode == "autonomous":
            objective += " If recon stalls or vulnerabilities are hinted, pivot to exploitation and capture proof (data dump, file read, or command execution)."

        if exploit_mode == "disabled":
            objective = f"[Exploit mode disabled] {objective} Focus on safe validation only."
        
        # Create output directory in the container
        output_dir = f"/pentest/output/{job_id}"
        container.exec_run(cmd=["mkdir", "-p", output_dir])
        
        # Build the command to run dynamic_agent.py with CLI args
        cmd = [
            "python3", "/opt/tazosploit/dynamic_agent.py",
            "--target", target,
            "--objective", objective,
            "--max-iterations", str(max_iterations),
            "--output-dir", output_dir
        ]
        
        # If resuming, find the session file and add --resume flag
        if resume:
            try:
                session_find = container.exec_run(
                    cmd=["find", output_dir, "-name", "session_*.json", "-type", "f"],
                    workdir="/pentest"
                )
                session_files = [f.strip() for f in session_find.output.decode().strip().split("\n") if f.strip()]
                if session_files:
                    # Get the session ID from the filename (session_<id>.json)
                    import re
                    session_file = session_files[-1]  # Most recent
                    match = re.search(r'session_(session_\d{8}_\d{6})\.json', session_file)
                    if match:
                        session_id = match.group(1)
                        cmd.extend(["--resume", session_id])
                        logger.info("resume_session_found", session_id=session_id, file=session_file)
                    else:
                        logger.warn("resume_session_id_not_parsed", file=session_file)
                else:
                    logger.warn("resume_no_session_file", output_dir=output_dir)
            except Exception as e:
                logger.warn("resume_session_lookup_error", error=str(e))
        
        logger.info("container_exec_start", 
                     container=container.name, 
                     target=target, 
                     objective=objective[:100])

        llm_provider_override = (job_details.get("llm_provider") or "").strip()

        # Pass --llm-provider CLI arg so DynamicAgent initializes the right provider class
        if llm_provider_override:
            # Map job-level provider names to CLI-accepted choices
            _cli_provider_map = {
                "zai": "openai", "openai": "openai", "anthropic": "anthropic",
                "ollama": "ollama", "lmstudio": "lmstudio", "lm-studio": "lmstudio",
            }
            _cli_provider = _cli_provider_map.get(llm_provider_override.lower())
            if _cli_provider:
                cmd.extend(["--llm-provider", _cli_provider])

        # Run in a thread to not block the event loop, with streaming
        loop = asyncio.get_event_loop()
        
        try:
            allow_command_chaining = phase in ("EXPLOIT", "FULL", "POST_EXPLOIT", "LATERAL")
            strict_evidence_only = phase in ("VULN_SCAN", "EXPLOIT", "POST_EXPLOIT", "LATERAL", "FULL")
            config_block = job_details.get("config") if isinstance(job_details.get("config"), dict) else {}
            thinking_enabled = bool(config_block.get("thinking_enabled")) or os.getenv("LLM_THINKING_ENABLED", "").strip().lower() in ("true", "1")
            llm_api_base_override = str(config_block.get("llm_api_base") or "").strip()
            llm_model_override = str(job_details.get("llm_model") or config_block.get("llm_model") or "").strip()
            llm_profile_value = job_details.get("llm_profile") or config_block.get("llm_profile")
            agent_freedom_value = job_details.get("agent_freedom")
            if agent_freedom_value is None:
                agent_freedom_value = config_block.get("agent_freedom")

            # Auto-complete defaults:
            # The agent supports auto-completing after N "idle" iterations once proof exists.
            # For long runs (e.g. 24h/5000 iters), that behavior is typically undesirable.
            auto_complete_idle_iterations = config_block.get("auto_complete_idle_iterations")
            if auto_complete_idle_iterations is None:
                auto_complete_idle_iterations = 0 if int(max_iterations or 0) >= 2000 else 50
            auto_complete_min_iterations = config_block.get("auto_complete_min_iterations")
            if auto_complete_min_iterations is None:
                auto_complete_min_iterations = 50
            # Start exec with streaming
            exec_handle = container.client.api.exec_create(
                container.id,
                cmd,
                workdir="/pentest",
                environment={
                    "LOG_DIR": f"/pentest/logs/{job_id}",
                    "OUTPUT_DIR": output_dir,
                    "JOB_ID": job_id,
                    # JobResponse does not include tenant_id; rely on the queue payload.
                    "TENANT_ID": str(tenant_id or ""),
                    "TARGET_TYPE": target_type,
                    "JOB_PHASE": phase,
                    "EFFECTIVE_PHASE": "FULL" if (auto_escalate_recon and phase == "RECON" and exploit_mode == "autonomous") else phase,
                    "JOB_INTENSITY": job_details.get("intensity", "medium"),
                    "EXPLOIT_MODE": exploit_mode,
                    "SKILLS_DIR": "/opt/tazosploit/skills",
                    "ALLOW_PERSISTENCE": str(bool(job_details.get("allow_persistence", False) or relax_exploit_restrictions)).lower(),
                    "ALLOW_DEFENSE_EVASION": str(bool(job_details.get("allow_defense_evasion", False) or relax_exploit_restrictions)).lower(),
                    "ALLOW_SCOPE_EXPANSION": str(bool(job_details.get("allow_scope_expansion", False))).lower(),
                    "ENABLE_SESSION_HANDOFF": str(bool(job_details.get("enable_session_handoff", False))).lower(),
                    "ENABLE_TARGET_ROTATION": str(bool(job_details.get("enable_target_rotation", True))).lower(),
                    "TARGET_FOCUS_WINDOW": str(job_details.get("target_focus_window", 6)),
                    "TARGET_FOCUS_LIMIT": str(job_details.get("target_focus_limit", 30)),
                    "TARGET_MIN_COMMANDS": str(job_details.get("target_min_commands", 8)),
                    "ALLOWED_TARGETS": ",".join(job_details.get("targets", []) or []),
                    "AUTO_ESCALATE_RECON": str(bool(auto_escalate_recon)).lower(),
                    "ALLOW_EXPLOIT_ANY_PHASE": str(bool(allow_exploit_any_phase)).lower(),
                    "ALLOW_COMMAND_CHAINING": str(bool(allow_command_chaining)).lower(),
                    "EXPLOIT_TOOLCHAIN": "true" if phase in ("EXPLOIT", "FULL") else "false",
                    "STRICT_EVIDENCE_ONLY": str(bool(strict_evidence_only)).lower(),
                    "ALLOW_SELF_REGISTRATION": "true" if relax_exploit_restrictions else "false",
                    "AUTO_COMPLETE_IDLE_ITERATIONS": str(auto_complete_idle_iterations),
                    "AUTO_COMPLETE_MIN_ITERATIONS": str(auto_complete_min_iterations),
                    **({"LLM_PROVIDER": llm_provider_override} if llm_provider_override else {}),
                    **({"LLM_PROVIDER_OVERRIDE": llm_provider_override} if llm_provider_override else {}),
                    **({"LLM_THINKING_ENABLED": "true"} if thinking_enabled else {}),
                    **({"LLM_API_BASE": llm_api_base_override} if llm_api_base_override else {}),
                    **({"LLM_MODEL_OVERRIDE": llm_model_override} if llm_model_override else {}),
                    **({"LLM_MODEL": llm_model_override} if llm_model_override else {}),
                    # LLM Profile system — controls agent freedom/strictness
                    **({"LLM_PROFILE": llm_profile_value} if llm_profile_value else {}),
                    **({"AGENT_FREEDOM": str(agent_freedom_value)} if agent_freedom_value is not None else {}),
                }
            )
            exec_id = exec_handle["Id"]
            
            # Start the exec and stream output
            output_stream = container.client.api.exec_start(exec_id, stream=True)
            
            # Collect output with timeout, streaming lines to Redis
            full_output = b""
            line_buffer = b""
            
            def collect_output():
                nonlocal full_output, line_buffer
                for chunk in output_stream:
                    # Check cancel flag
                    if self._cancel_event.is_set():
                        logger.info("cancel_detected_in_stream", job_id=job_id)
                        break
                    full_output += chunk
                    line_buffer += chunk
                    # Process complete lines for streaming
                    while b"\n" in line_buffer:
                        line, line_buffer = line_buffer.split(b"\n", 1)
                        decoded_line = line.decode(errors="replace").rstrip()
                        if decoded_line:
                            self._stream_line_sync(job_id, decoded_line)
                # Flush remaining buffer
                if line_buffer:
                    decoded = line_buffer.decode(errors="replace").rstrip()
                    if decoded:
                        self._stream_line_sync(job_id, decoded)
            
            # Run the blocking stream in executor with timeout
            # Also monitor cancel event AND periodically push findings
            last_findings_push = 0
            pushed_findings_count = 0
            
            async def run_with_cancel():
                nonlocal last_findings_push, pushed_findings_count
                task = loop.run_in_executor(None, collect_output)
                tick = 0
                while not task.done():
                    if self._cancel_event.is_set():
                        logger.info("cancel_killing_process", job_id=job_id)
                        try:
                            # Targeted kill first (job_id / output_dir), then fallback to broad tool-name kills.
                            for pat in [output_dir, job_id]:
                                container.exec_run(cmd=["pkill", "-15", "-f", pat])
                            for proc in ["dynamic_agent.py", "sqlmap", "nikto", "hydra"]:
                                container.exec_run(cmd=["pkill", "-15", "-f", proc])
                            logger.info("sigterm_sent", job_id=job_id)
                        except Exception:
                            pass
                        # Wait up to 10s for graceful exit, then SIGKILL
                        for _wait in range(10):
                            await asyncio.sleep(1)
                            if task.done():
                                break
                        if not task.done():
                            try:
                                for pat in [output_dir, job_id]:
                                    container.exec_run(cmd=["pkill", "-9", "-f", pat])
                                for proc in ["dynamic_agent.py", "sqlmap", "nikto", "hydra"]:
                                    container.exec_run(cmd=["pkill", "-9", "-f", proc])
                                logger.info("sigkill_sent", job_id=job_id)
                            except Exception:
                                pass
                        break
                    
                    # 🎰 REAL-TIME FINDINGS + LOOT: Push every 30 seconds
                    tick += 1
                    if tick >= 30 and tick - last_findings_push >= 30:
                        try:
                            new_count = await self._push_live_findings(
                                job_id,
                                str(tenant_id or ""),
                                container, 
                                output_dir,
                                pushed_findings_count
                            )
                            pushed_findings_count = new_count  # 🐛 FIX: track what we've already pushed
                            # Also push loot (credentials/tokens found)
                            await self._push_live_loot(
                                job_id,
                                str(tenant_id or ""),
                                container,
                                output_dir
                            )
                            last_findings_push = tick
                            # 📊 REAL-TIME TOKEN TRACKING: Aggregate from llm_interactions.jsonl
                            await self._push_live_tokens(job_id, container, output_dir)
                        except Exception as e:
                            logger.warn("live_findings_push_error", error=str(e))
                    
                    await asyncio.sleep(1)

                # IMPORTANT: if the stream collector exited early due to CANCEL, the exec'ed process can still
                # be running. Ensure we terminate job processes even when `collect_output()` stops.
                if self._cancel_event.is_set():
                    logger.info("cancel_killing_process", job_id=job_id, reason="stream_task_done")
                    try:
                        for pat in [output_dir, job_id]:
                            container.exec_run(cmd=["pkill", "-15", "-f", pat])
                        await asyncio.sleep(2)
                        for pat in [output_dir, job_id]:
                            container.exec_run(cmd=["pkill", "-9", "-f", pat])
                    except Exception:
                        pass
                try:
                    await asyncio.wait_for(task, timeout=5)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    pass
            
            try:
                await asyncio.wait_for(
                    run_with_cancel(),
                    timeout=timeout_seconds
                )
            except asyncio.TimeoutError:
                logger.warn("job_timeout", job_id=job_id, timeout=timeout_seconds)
                try:
                    # N8: SIGTERM first, then SIGKILL after 10s
                    for pat in [output_dir, job_id]:
                        container.exec_run(cmd=["pkill", "-15", "-f", pat])
                    for proc in ["dynamic_agent.py", "sqlmap", "nikto", "hydra"]:
                        container.exec_run(cmd=["pkill", "-15", "-f", proc])
                    await asyncio.sleep(10)
                    for pat in [output_dir, job_id]:
                        container.exec_run(cmd=["pkill", "-9", "-f", pat])
                    for proc in ["dynamic_agent.py", "sqlmap", "nikto", "hydra"]:
                        container.exec_run(cmd=["pkill", "-9", "-f", proc])
                except Exception:
                    pass
            
            # Check exit code
            exec_inspect = container.client.api.exec_inspect(exec_id)
            exit_code = exec_inspect.get("ExitCode", -1)
            
            # N12: Treat exit_code None as a crash (process died without status)
            if exit_code is None:
                logger.warn("exit_code_null_treating_as_crash", job_id=job_id, container=container.name)
                exit_code = 1
            
            output_text = full_output.decode(errors="replace")
            
            logger.info("container_exec_done",
                        container=container.name,
                        exit_code=exit_code,
                        output_len=len(output_text))
            
            # Try to read the structured JSON report from the output directory
            result = self._read_container_results(container, output_dir, output_text)
            result["exit_code"] = exit_code
            result["raw_output"] = output_text[-5000:]  # Last 5KB of output
            result["live_findings_count"] = int(pushed_findings_count or 0)
            
            return result
            
        except Exception as e:
            logger.error("container_exec_error", error=str(e))
            return {
                "error": str(e),
                "findings": [],
                "output": ""
            }
    
    def _read_container_results(self, container, output_dir: str, raw_output: str) -> dict:
        """Read structured results from the container's output directory"""
        result = {"findings": [], "evidence": [], "output": raw_output[-2000:]}

        def _load_json_forgiving(raw: str):
            """Parse JSON with support for concatenated objects or NDJSON."""
            raw = (raw or "").strip()
            if not raw:
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                # Try NDJSON (one object per line)
                objs = []
                for line in raw.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        objs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
                if objs:
                    return objs[-1]
                # Try concatenated JSON objects (take the last)
                try:
                    decoder = json.JSONDecoder()
                    idx = 0
                    last = None
                    while idx < len(raw):
                        while idx < len(raw) and raw[idx].isspace():
                            idx += 1
                        if idx >= len(raw):
                            break
                        obj, end = decoder.raw_decode(raw, idx)
                        last = obj
                        idx = end
                    return last
                except Exception:
                    return None
        
        try:
            # 1. First try the evidence/findings.json — most structured source
            try:
                findings_result = container.exec_run(
                    cmd=["cat", f"{output_dir}/evidence/findings.json"],
                    workdir="/pentest"
                )
                if findings_result.exit_code == 0:
                    evidence_findings = json.loads(findings_result.output.decode())
                    if isinstance(evidence_findings, list):
                        result["findings"] = evidence_findings
                        logger.info("loaded_evidence_findings", count=len(evidence_findings))
            except Exception:
                pass
            
            # 2. Read the main report JSON files
            exec_result = container.exec_run(
                cmd=["find", output_dir, "-maxdepth", "1", "-name", "*.json", "-type", "f"],
                workdir="/pentest"
            )
            json_files = exec_result.output.decode().strip().split("\n")
            
            for json_file in json_files:
                if not json_file.strip():
                    continue
                try:
                    file_result = container.exec_run(cmd=["cat", json_file.strip()])
                    data = _load_json_forgiving(file_result.output.decode())
                    if data is None:
                        raise json.JSONDecodeError("Could not parse JSON", file_result.output.decode(), 0)

                    # Preserve pause/resume state from the agent report. Without this, a user stop
                    # signal (dynamic_agent returns {status:"paused", paused:true}) gets lost and the
                    # worker incorrectly marks the job as completed.
                    if "status" in data and "status" not in result:
                        result["status"] = data.get("status")
                    if "paused" in data and "paused" not in result:
                        result["paused"] = bool(data.get("paused"))
                    
                    # Merge findings (if we didn't get them from evidence dir)
                    if "findings" in data and not result["findings"]:
                        result["findings"] = data["findings"]
                    if "comprehensive_findings" in data:
                        result["comprehensive_findings"] = data["comprehensive_findings"]
                    if "exploitation_results" in data:
                        result["exploitation_results"] = data["exploitation_results"]
                    if "iterations" in data:
                        result["iterations"] = data["iterations"]
                    if "total_executions" in data:
                        result["execution_count"] = data["total_executions"]
                        result["successful_executions"] = data.get("successful_executions", 0)
                    if "tools_used" in data:
                        result["tools_used"] = data["tools_used"]
                    if "llm_stats" in data:
                        result["llm_stats"] = data["llm_stats"]
                except (json.JSONDecodeError, Exception) as e:
                    logger.warn("result_parse_error", file=json_file, error=str(e))
            
            # 3. Read credential evidence
            try:
                creds_result = container.exec_run(
                    cmd=["cat", f"{output_dir}/evidence/credentials.json"],
                    workdir="/pentest"
                )
                if creds_result.exit_code == 0:
                    creds = json.loads(creds_result.output.decode())
                    if creds:
                        result["credentials"] = creds
                        logger.info("loaded_credentials", count=len(creds))
            except Exception:
                pass

            # 3b. Read session handoff instructions (best-effort)
            try:
                handoff_result = container.exec_run(
                    cmd=["cat", f"{output_dir}/handoff.json"],
                    workdir="/pentest"
                )
                if handoff_result.exit_code == 0:
                    handoff = json.loads(handoff_result.output.decode())
                    if handoff:
                        result["session_handoff"] = handoff
                        logger.info("loaded_session_handoff")
            except Exception:
                pass
            
            # 4. List evidence files
            exec_result = container.exec_run(
                cmd=["find", f"{output_dir}/evidence", "-type", "f"],
                workdir="/pentest"
            )
            evidence_files = [f.strip() for f in exec_result.output.decode().strip().split("\n") if f.strip()]
            result["evidence"] = evidence_files
            
        except Exception as e:
            logger.warn("result_read_error", error=str(e))
        
        return result
    
    async def _push_live_findings(self, job_id: str, tenant_id: str, container, output_dir: str, already_pushed: int) -> int:
        """🎰 REAL-TIME: Push findings to API during execution (not just at end)
        
        Reads from multiple sources the dynamic agent writes to:
        - findings.json (list format)
        - vuln_tracker.json (dict format: {key: {type, target, details, ...}})
        - creds.json (credential findings)
        """
        headers = {"Authorization": f"Bearer {INTERNAL_AUTH}"}
        include_unverified = os.getenv("LIVE_FINDINGS_INCLUDE_UNVERIFIED", "false").strip().lower() in ("1", "true", "yes")
        
        try:
            findings = []
            
            # Source 1: findings.json (standard format)
            try:
                result = container.exec_run(
                    cmd=["cat", f"{output_dir}/findings.json"],
                    workdir="/pentest"
                )
                if result.exit_code == 0:
                    data = json.loads(result.output.decode())
                    if isinstance(data, dict) and "findings" in data:
                        findings = data["findings"]
                    elif isinstance(data, list):
                        findings = data
            except Exception:
                pass
            
            # Source 2: vuln_tracker.json (dict format from dynamic_agent)
            # Proof-aware: uses proof/exploit_evidence when available, upgrades severity for proven vulns
            try:
                result = container.exec_run(
                    cmd=["cat", f"{output_dir}/vuln_tracker.json"],
                    workdir="/pentest"
                )
                if result.exit_code == 0:
                    data = json.loads(result.output.decode())
                    if isinstance(data, dict):
                        for key, vuln in data.items():
                            if not isinstance(vuln, dict):
                                continue
                            
                            is_exploited = vuln.get("exploited", False)
                            has_proof = bool(vuln.get("proof"))
                            vuln_type = vuln.get("type", "Unknown")
                            if not (is_exploited or has_proof) and not include_unverified:
                                continue
                            
                            # Build evidence: prefer proof > exploit_evidence > last attempt evidence > details
                            evidence = ""
                            if has_proof:
                                evidence = vuln["proof"]
                            elif vuln.get("exploit_evidence"):
                                evidence = vuln["exploit_evidence"]
                            elif vuln.get("attempts"):
                                # Use the last successful attempt's evidence
                                for att in reversed(vuln["attempts"]):
                                    if att.get("success") and att.get("evidence"):
                                        evidence = att["evidence"]
                                        break
                            if not evidence:
                                evidence = vuln.get("details", "")
                            if not evidence and not include_unverified:
                                continue
                            
                            # Severity: proven exploits get their real severity, unproven get downgraded
                            if is_exploited or has_proof:
                                severity = self._map_severity(vuln_type, exploited=is_exploited, has_proof=has_proof)
                                status_tag = "✅ VERIFIED"
                            else:
                                severity = "medium"  # Downgrade unproven
                                status_tag = "⏳ UNVERIFIED"
                            
                            # Build rich description
                            desc_parts = []
                            if is_exploited:
                                desc_parts.append(f"Auto-detected {vuln_type} auth bypass from command.")
                            desc_parts.append(self._format_finding_description(vuln.get("details", ""), vuln))
                            if is_exploited and not has_proof:
                                desc_parts.append(f"The finding is {status_tag}. High/critical severity requires concrete proof; downgraded.")
                            elif has_proof:
                                desc_parts.append(f"The finding is {status_tag}. Exploitation confirmed with evidence.")
                            else:
                                desc_parts.append(f"The finding is {status_tag}. High/critical severity requires concrete proof; downgraded.")
                            
                            attempt_count = vuln.get("attempt_count", 0)
                            if attempt_count > 0:
                                desc_parts.append(f"Exploit attempts: {attempt_count}")
                            
                            findings.append({
                                "title": f"{vuln_type.title()} — {vuln.get('target', 'unknown')}",
                                "description": " ".join(desc_parts)[:500],
                                "severity": severity,
                                "finding_type": "vulnerability",
                                "target": vuln.get("target", ""),
                                "evidence": str(evidence)[:1000],
                                "verified": bool(is_exploited or has_proof),
                                "is_false_positive": False,
                                "_vuln_key": key,  # Track for dedup
                                "_exploited": is_exploited,
                                "_has_proof": has_proof,
                            })
            except Exception:
                pass
            
            # Source 3: creds.json (credential findings → trophy!)
            try:
                result = container.exec_run(
                    cmd=["cat", f"{output_dir}/creds.json"],
                    workdir="/pentest"
                )
                if result.exit_code == 0:
                    data = json.loads(result.output.decode())
                    if isinstance(data, dict) and data.get("credential_found"):
                        findings.append({
                            "title": f"Credential Access — {data.get('technique', 'unknown')}",
                            "description": f"Credential: {data['credential_found']}, Role: {data.get('role', 'unknown')}",
                            "severity": "critical",
                            "finding_type": "credential_access",
                            "target": data.get("credential_found", "").split(":")[0] if ":" in data.get("credential_found", "") else "",
                            "evidence": data.get("evidence", ""),
                            "verified": True,
                            "is_false_positive": False,
                        })
                    elif isinstance(data, list):
                        for cred in data:
                            if isinstance(cred, dict):
                                findings.append({
                                    "title": f"Credential Access — {cred.get('technique', cred.get('service', 'unknown'))}",
                                    "description": f"Credential: {cred.get('credential_found', cred.get('username', ''))}, Role: {cred.get('role', 'unknown')}",
                                    "severity": "critical",
                                    "finding_type": "credential_access",
                                    "evidence": cred.get("evidence", ""),
                                    "verified": True,
                                    "is_false_positive": False,
                                })
            except Exception:
                pass
            
            # Build content hash for each finding to detect changes (e.g. vuln got proven)
            import hashlib
            current_hashes = {}
            for f in findings:
                # Hash on title + severity + evidence (so proof upgrades trigger re-push)
                hash_input = f"{f.get('title','')}|{f.get('severity','')}|{f.get('evidence','')[:200]}"
                h = hashlib.md5(hash_input.encode()).hexdigest()[:12]
                current_hashes[h] = f
            
            # Compare with previously pushed hashes (stored in Redis)
            pushed_key = f"job:{job_id}:pushed_finding_hashes"
            try:
                already_pushed_hashes = set()
                raw = await self.redis.smembers(pushed_key)
                if raw:
                    already_pushed_hashes = {x.decode() if isinstance(x, bytes) else x for x in raw}
            except Exception:
                already_pushed_hashes = set()
            
            new_hashes = set(current_hashes.keys()) - already_pushed_hashes
            if new_hashes:
                new_findings = [current_hashes[h] for h in new_hashes]
                # Strip internal fields before sending
                for f in new_findings:
                    f.pop("_vuln_key", None)
                    f.pop("_exploited", None)
                    f.pop("_has_proof", None)
                normalized = self._normalize_findings(new_findings)
                
                if normalized:
                    async with httpx.AsyncClient() as client:
                        resp = await client.post(
                            f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}/findings",
                            json=normalized,
                            headers=headers,
                            timeout=15.0
                        )
                        if resp.status_code in (200, 201):
                            logger.info("live_findings_pushed", job_id=job_id, count=len(normalized), new_hashes=len(new_hashes))
                            # Record pushed hashes
                            if new_hashes:
                                await self.redis.sadd(pushed_key, *new_hashes)
                                await self.redis.expire(pushed_key, 86400 * 2)
                            return len(findings)
                        else:
                            logger.warn("live_findings_push_failed", status=resp.status_code, body=resp.text[:200])
            
            return already_pushed
            
        except Exception as e:
            logger.warn("live_findings_error", error=str(e))
            return already_pushed
    
    async def _push_live_loot(self, job_id: str, tenant_id: str, container, output_dir: str):
        """🏆 REAL-TIME: Push loot (credentials/tokens) to API during execution"""
        headers = {"Authorization": f"Bearer {INTERNAL_AUTH}"}
        
        # Track what we've already pushed to avoid duplicates (Fix #11: persist in Redis across resumes)
        if not hasattr(self, '_pushed_loot'):
            self._pushed_loot = {}
        pushed_key = f"{job_id}:loot"
        pushed_hashes = self._pushed_loot.get(pushed_key, set())
        # Fix #11: Load persisted loot hashes from Redis for cross-resume dedup
        if not pushed_hashes:
            try:
                import redis as sync_redis
                r = sync_redis.from_url(REDIS_URL, decode_responses=True)
                existing = r.smembers(f"job:{job_id}:pushed_loot_hashes")
                if existing:
                    pushed_hashes = set(existing)
                    self._pushed_loot[pushed_key] = pushed_hashes
                r.close()
            except Exception:
                pass
        
        try:
            # Read access.json from container
            creds = []
            try:
                result = container.exec_run(
                    cmd=["cat", f"{output_dir}/access.json"],
                    workdir="/pentest"
                )
                if result.exit_code == 0:
                    data = json.loads(result.output.decode())
                    if "access" in data:
                        access = data["access"]
                        # Handle both single dict and list of dicts
                        items = access if isinstance(access, list) else [access]
                        for item in items:
                            if not isinstance(item, dict):
                                continue
                            creds.append({
                                "username": item.get("username", item.get("email", "")),
                                "password": item.get("password", item.get("credential", item.get("token", "")[:50])),
                                "service": item.get("service", item.get("target", "unknown")),
                                "type": item.get("type", "token" if item.get("token") else "credential"),
                            })
            except Exception:
                pass
            
            # Also read creds.json
            try:
                result = container.exec_run(
                    cmd=["cat", f"{output_dir}/creds.json"],
                    workdir="/pentest"
                )
                if result.exit_code == 0:
                    data = json.loads(result.output.decode())
                    items = data if isinstance(data, list) else [data]
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        if item.get("credential_found"):
                            cred_parts = item["credential_found"].split(":", 1)
                            creds.append({
                                "username": cred_parts[0] if len(cred_parts) > 0 else "",
                                "password": cred_parts[1] if len(cred_parts) > 1 else "",
                                "service": item.get("technique", "cracked credential"),
                                "type": "credential",
                            })
            except Exception:
                pass
            
            if creds:
                async with httpx.AsyncClient() as client:
                    for cred in creds:
                        # Create hash to track duplicates
                        username = str(cred.get("username", "")).strip()
                        password = str(cred.get("password", cred.get("credential", cred.get("token", "")))).strip()
                        cred_hash = f"{username}:{cred.get('service')}:{cred.get('type')}"
                        if cred_hash in pushed_hashes:
                            continue
                        # Validate before posting
                        if not self._is_valid_credential(username, password):
                            logger.debug("live_loot_skipped", user=username, reason="failed validation")
                            continue
                        
                        loot_data = {
                            "job_id": job_id,
                            "loot_type": cred.get("type", "credential"),
                            "source": "access.json",
                            "value": {
                                "username": username,
                                "password": password,
                                "service": cred.get("service", ""),
                                "access_level": "admin" if "admin" in str(cred).lower() else "user",
                            },
                            "description": f"{cred.get('type', 'Credential')} for {cred.get('service', 'unknown')}"
                        }
                        try:
                            resp = await client.post(
                                f"{CONTROL_PLANE_URL}/api/v1/loot",
                                json=loot_data,
                                headers=headers,
                                timeout=10.0
                            )
                            if resp.status_code in (200, 201):
                                pushed_hashes.add(cred_hash)
                                logger.info("live_loot_pushed", job_id=job_id, type=cred.get("type"), service=cred.get("service"))
                        except Exception as e:
                            logger.debug("live_loot_push_error", error=str(e))
                    
                    self._pushed_loot[pushed_key] = pushed_hashes
                    # Fix #11: Persist loot hashes to Redis for cross-resume dedup
                    try:
                        import redis as sync_redis
                        r = sync_redis.from_url(REDIS_URL, decode_responses=True)
                        if pushed_hashes:
                            r.sadd(f"job:{job_id}:pushed_loot_hashes", *pushed_hashes)
                            r.expire(f"job:{job_id}:pushed_loot_hashes", 86400)
                        r.close()
                    except Exception:
                        pass
                    
        except Exception as e:
            logger.warn("live_loot_error", error=str(e))
    
    async def _push_live_tokens(self, job_id: str, container, output_dir: str):
        """📊 REAL-TIME: Aggregate token usage from llm_interactions.jsonl and update job + Redis"""
        try:
            result = container.exec_run(
                cmd=["cat", f"{output_dir}/llm_interactions.jsonl"],
                workdir="/pentest"
            )
            if result.exit_code != 0:
                return
            
            total_tokens = 0
            total_cost = 0.0
            for line in result.output.decode(errors="replace").strip().split("\n"):
                try:
                    d = json.loads(line)
                    total_tokens += d.get("total_tokens", 0)
                    total_cost += d.get("cost_usd", 0.0)
                except (json.JSONDecodeError, ValueError):
                    continue
            
            if total_tokens > 0:
                # Update Redis live_stats
                await self.redis.hset(f"job:{job_id}:live_stats", "tokens_used", str(total_tokens))
                await self.redis.hset(f"job:{job_id}:live_stats", "cost_usd", f"{total_cost:.4f}")
                
                # Update API job record
                headers = {"Authorization": f"Bearer {INTERNAL_AUTH}"}
                async with httpx.AsyncClient() as client:
                    await client.patch(
                        f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}",
                        json={"tokens_used": total_tokens, "cost_usd": round(total_cost, 4)},
                        headers=headers,
                        timeout=10.0
                    )
                logger.info("live_tokens_pushed", job_id=job_id, tokens=total_tokens, cost=f"${total_cost:.4f}")
        except Exception as e:
            logger.warn("live_tokens_error", error=str(e))
    
    async def _post_findings_and_loot(self, job_id: str, tenant_id: str, result: dict, container, output_dir: str):
        """Post structured findings to the control plane API and upload evidence to MinIO"""
        headers = {"Authorization": f"Bearer {INTERNAL_AUTH}"}
        
        try:
            # 1. Read evidence/findings.json from the container
            findings = result.get("findings", [])
            if findings:
                findings = self._normalize_findings(findings)
                # Findings posted at job completion are treated as verified outputs.
                for f in findings:
                    f.setdefault("verified", True)
                    f.setdefault("is_false_positive", False)
            
            # Prefer root findings.json if present (agent writes here)
            try:
                container, exec_result = await self._exec_run_retry(
                    container,
                    cmd=["cat", f"{output_dir}/findings.json"],
                    workdir="/pentest",
                    retries=1,
                )
                if exec_result.exit_code == 0:
                    root_findings = json.loads(exec_result.output.decode())
                    if isinstance(root_findings, dict) and "findings" in root_findings:
                        root_findings = root_findings.get("findings", [])
                    if isinstance(root_findings, list) and root_findings:
                        findings = self._normalize_findings(root_findings)
                        for f in findings:
                            f.setdefault("verified", True)
                            f.setdefault("is_false_positive", False)
                        result["findings"] = findings
                        logger.info("findings_from_root", count=len(findings))
            except Exception as e:
                logger.warn("root_findings_read_error", error=str(e))

            # Also try reading from the container's evidence directory
            try:
                container, exec_result = await self._exec_run_retry(
                    container,
                    cmd=["cat", f"{output_dir}/evidence/findings.json"],
                    workdir="/pentest",
                    retries=1,
                )
                if exec_result.exit_code == 0:
                    evidence_findings = json.loads(exec_result.output.decode())
                    if isinstance(evidence_findings, list) and len(evidence_findings) > len(findings):
                        # Normalize findings to ensure they have required fields (title, severity)
                        findings = self._normalize_findings(evidence_findings)
                        for f in findings:
                            f.setdefault("verified", True)
                            f.setdefault("is_false_positive", False)
                        result["findings"] = findings
                        logger.info("findings_from_evidence", count=len(findings))
            except Exception as e:
                logger.warn("evidence_findings_read_error", error=str(e))
            
            if not findings:
                # Try extracting from comprehensive_findings
                comp = result.get("comprehensive_findings", {})
                if comp:
                    vulns = comp.get("vulnerabilities", [])
                    db_access = comp.get("database_access", [])
                    shell_access = comp.get("shell_access", [])
                    chains = comp.get("attack_chains", [])
                    
                    for v in vulns:
                        findings.append({
                            "title": f"{v.get('type', 'Unknown')} — {v.get('endpoint', v.get('service', 'unknown'))}",
                            "description": self._format_finding_description(v.get('impact', ''), v),
                            "severity": self._map_severity(v.get('impact', '')),
                            "finding_type": "vulnerability",
                            "target": v.get('endpoint', ''),
                            "evidence": v.get('evidence', ''),
                            "extraction_command": v.get('extraction_command', ''),
                            "iteration": v.get('iteration', 0),
                        })
                    
                    for db in db_access:
                        findings.append({
                            "title": f"Database Access — {db.get('db_type', 'Unknown')} @ {db.get('host', 'unknown')}",
                            "description": f"Databases: {', '.join(db.get('databases', []))}, Tables: {len(db.get('tables_dumped', []))}",
                            "severity": "critical",
                            "finding_type": "database_access",
                            "target": db.get('host', ''),
                            "evidence": f"Credentials: {db.get('credentials', '')}",
                            "extraction_command": db.get('extraction_command', ''),
                        })
                    
                    for shell in shell_access:
                        findings.append({
                            "title": f"Shell Access — {shell.get('type', 'unknown')} on {shell.get('host', 'unknown')}",
                            "description": f"User: {shell.get('user', 'unknown')}, Method: {shell.get('method', '')[:100]}",
                            "severity": "critical",
                            "finding_type": "shell_access",
                            "target": shell.get('host', ''),
                            "evidence": shell.get('method', '')[:500],
                        })
                    
                    for chain in chains:
                        findings.append({
                            "title": f"⛓️ Attack Chain: {chain.get('title', 'Unknown')}",
                            "description": chain.get('summary', ''),
                            "severity": chain.get('severity', 'high'),
                            "finding_type": "attack_chain",
                            "target": "",
                            "evidence": json.dumps(chain.get('steps', []), indent=2)[:500],
                        })
                    
                    # NOTE: Credentials are NOT added as findings — they go to the
                    # credentials table via _post_findings_and_loot() to avoid duplicates.
                    
                    result["findings"] = findings
            
            # 2. POST findings to API
            if findings:
                async with httpx.AsyncClient() as client:
                    try:
                        resp = await client.post(
                            f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}/findings",
                            json=findings,
                            headers=headers,
                            timeout=30.0
                        )
                        if resp.status_code in (200, 201):
                            logger.info("findings_posted", job_id=job_id, count=len(findings))
                        else:
                            logger.warn("findings_post_failed", status=resp.status_code, body=resp.text[:200])
                    except Exception as e:
                        logger.warn("findings_post_error", error=str(e))
            
            # 3. POST loot items (credentials)
            creds = []
            
            # Try multiple sources for credentials
            cred_sources = [
                f"{output_dir}/evidence/credentials.json",
                f"{output_dir}/access.json",
            ]
            
            for cred_file in cred_sources:
                if creds:  # Already found credentials
                    break
                try:
                    container, exec_result = await self._exec_run_retry(
                        container,
                        cmd=["cat", cred_file],
                        workdir="/pentest",
                        retries=1,
                    )
                    if exec_result.exit_code == 0:
                        data = json.loads(exec_result.output.decode())
                        # Handle access.json format: {"access": [...]}
                        if "access" in data:
                            for item in data["access"]:
                                cred = {
                                    "username": item.get("username", item.get("credential", "")[:50] if item.get("type") == "api_token" else ""),
                                    "password": item.get("password", item.get("credential", "")),
                                    "service": item.get("service", "unknown"),
                                    "source": cred_file,
                                    "access_level": "admin" if "admin" in str(item).lower() else "user",
                                    "loot_type": item.get("type", "credential"),
                                }
                                creds.append(cred)
                            logger.info("loot_loaded_from_access_json", count=len(creds))
                        # Handle credentials.json format: [...]
                        elif isinstance(data, list):
                            creds = data
                except Exception as e:
                    logger.debug("cred_file_read_failed", file=cred_file, error=str(e))
            
            # Fall back to comprehensive_findings
            if not creds:
                comp = result.get("comprehensive_findings", {})
                creds = comp.get("credentials", [])
            
            if creds:
                async with httpx.AsyncClient() as client:
                    for cred in creds:
                        # Validate credential before posting — reject garbage from LLM parsing
                        username = str(cred.get("username", "")).strip()
                        password = str(cred.get("password", "")).strip()
                        if not self._is_valid_credential(username, password):
                            logger.debug("loot_skipped_invalid", user=username, reason="failed validation")
                            continue
                        try:
                            loot_data = {
                                "job_id": job_id,
                                "loot_type": "credential",
                                "source": cred.get("source", "pentest"),
                                "value": {
                                    "username": username,
                                    "password": password,
                                    "service": cred.get("service", ""),
                                    "access_level": cred.get("access_level", "unknown"),
                                },
                                "description": f"Credential for {cred.get('service', 'unknown')}"
                            }
                            resp = await client.post(
                                f"{CONTROL_PLANE_URL}/api/v1/loot",
                                json=loot_data,
                                headers=headers,
                                timeout=10.0
                            )
                            if resp.status_code in (200, 201):
                                logger.info("loot_posted", type="credential", user=username)
                        except Exception as e:
                            logger.warn("loot_post_error", error=str(e))
            
            # 4. Upload evidence files to MinIO
            await self._upload_evidence_to_minio(container, output_dir, job_id, tenant_id)

            # 5. Validate report artifacts for REPORT phase
            if (result.get("job_phase") or "").upper() == "REPORT":
                await self._validate_report_artifacts(container, output_dir, job_id, result)
            
        except Exception as e:
            logger.error("post_findings_error", job_id=job_id, error=str(e))
    
    async def _upload_evidence_to_minio(self, container, output_dir: str, job_id: str, tenant_id: str):
        """Upload evidence files to MinIO"""
        try:
            import io
            from minio import Minio
            
            minio_url = os.getenv("MINIO_URL", "minio:9000")
            minio_access = os.getenv("MINIO_ACCESS_KEY", "tazosploit")
            minio_secret = os.getenv("MINIO_SECRET_KEY", "tazosploit-secret")
            bucket = os.getenv("MINIO_BUCKET", "evidence")
            
            client = Minio(minio_url, access_key=minio_access, secret_key=minio_secret, secure=False)
            
            # Ensure bucket exists
            if not client.bucket_exists(bucket):
                client.make_bucket(bucket)
            
            # List evidence files in container
            container, exec_result = await self._exec_run_retry(
                container,
                # Only upload JSON artifacts plus newline-delimited JSON from evidence/
                # (do NOT upload large run logs like agent_executions.jsonl).
                cmd=[
                    "sh",
                    "-lc",
                    f"find '{output_dir}' -type f \\( -name '*.json' -o -path '{output_dir}/evidence/*.jsonl' \\)",
                ],
                workdir="/pentest",
                retries=1,
            )
            
            files = [f.strip() for f in exec_result.output.decode().strip().split("\n") if f.strip()]
            
            for filepath in files:
                try:
                    container, file_content = await self._exec_run_retry(
                        container,
                        cmd=["cat", filepath],
                        retries=1,
                    )
                    if file_content.exit_code == 0:
                        data = file_content.output
                        relpath = os.path.relpath(filepath, output_dir).lstrip("./")
                        object_name = f"{tenant_id}/{job_id}/{relpath}"
                        content_type = "application/json"
                        if relpath.endswith(".jsonl"):
                            content_type = "application/x-ndjson"
                        
                        client.put_object(
                            bucket,
                            object_name,
                            io.BytesIO(data),
                            len(data),
                            content_type=content_type
                        )
                        logger.info("evidence_uploaded", file=relpath, bucket=bucket)
                except Exception as e:
                    logger.warn("evidence_upload_error", file=filepath, error=str(e))
                    
        except ImportError:
            logger.warn("minio_not_available", msg="minio package not installed, skipping evidence upload")
        except Exception as e:
            logger.warn("minio_upload_error", error=str(e))

    async def _validate_report_artifacts(self, container, output_dir: str, job_id: str, result: dict = None):
        """Ensure report.md/report.json exist after REPORT phase."""
        try:
            report_md = f"{output_dir}/report.md"
            report_json = f"{output_dir}/report.json"
            md_ok = container.exec_run(cmd=["test", "-f", report_md]).exit_code == 0
            json_ok = container.exec_run(cmd=["test", "-f", report_json]).exit_code == 0
            report_status = {
                "report_md": md_ok,
                "report_json": json_ok,
                "ok": md_ok and json_ok,
            }
            if result is not None:
                result["report_artifacts"] = report_status
            if not report_status["ok"]:
                logger.warning(
                    "report_artifact_missing",
                    job_id=job_id,
                    report_md=md_ok,
                    report_json=json_ok,
                )
        except Exception as e:
            logger.warning("report_validation_error", job_id=job_id, error=str(e))
    
    async def _update_job_status(self, job_id: str, status: str, result: dict, container_id: str = None):
        """Update job status in control plane and Redis"""
        try:
            # Update via control plane API
            headers = {"Authorization": f"Bearer {INTERNAL_AUTH}"}
            payload = {"status": status, "result": result, "worker_id": WORKER_ID}
            if container_id:
                payload["container_id"] = container_id
            async with httpx.AsyncClient() as client:
                await client.patch(
                    f"{CONTROL_PLANE_URL}/api/v1/jobs/{job_id}",
                    json=payload,
                    headers=headers
                )
        except Exception as e:
            logger.error("status_update_failed", job_id=job_id, error=str(e))
        
        # Also publish to Redis for real-time subscribers
        try:
            await self.redis.publish(
                f"job:{job_id}:status",
                json.dumps({"status": status, "timestamp": datetime.utcnow().isoformat()})
            )
        except Exception:
            pass


worker = Worker()

if __name__ == "__main__":
    asyncio.run(worker.start())
