"""kali-executor/open-interpreter/knowledge_graph.py

Sprint 2: TazoSploit Knowledge Graph (Neo4j).

Design goals:
- Persist attack surface data (hosts/services/vulns/creds/attempts) across an agent run.
- Enable "what haven't I tried?" queries.
- OPTIONAL dependency: fail-open when Neo4j (or the neo4j Python driver) is unavailable.

Notes:
- This module is dependency-light at import time. The neo4j driver is imported lazily.
- All operations are best-effort; any errors degrade to no-ops.
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DRIVER: Any = None


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def get_driver() -> Any:
    """Get or create the Neo4j driver singleton.

    Returns:
        neo4j.Driver | None
    """

    global _DRIVER
    if _DRIVER is not None:
        return _DRIVER

    # Allow callers to disable KG entirely without touching compose/deps.
    enabled = _env("KNOWLEDGE_GRAPH_ENABLED", "true").lower() in ("1", "true", "yes")
    if not enabled:
        return None

    try:
        from neo4j import GraphDatabase  # type: ignore

        uri = _env("NEO4J_URI", "bolt://neo4j:7687")
        user = _env("NEO4J_USER", "neo4j")
        password = _env("NEO4J_PASSWORD", "changeme123")

        driver = GraphDatabase.driver(uri, auth=(user, password))

        # Ensure we fail fast when the service is down (avoid later surprises).
        try:
            driver.verify_connectivity()
        except Exception:
            try:
                driver.close()
            except Exception:
                pass
            raise

        _DRIVER = driver
        logger.info("neo4j_connected uri=%s", uri)
        return _DRIVER
    except Exception as exc:
        # Neo4j is optional; degrade to no-op.
        logger.warning("neo4j_unavailable err=%s", exc)
        _DRIVER = None
        return None


def close_driver() -> None:
    """Close the Neo4j driver singleton."""

    global _DRIVER
    if _DRIVER is None:
        return
    try:
        _DRIVER.close()
    except Exception:
        pass
    _DRIVER = None


class KnowledgeGraph:
    """TazoSploit knowledge graph interface."""

    def __init__(self, job_id: str, user_id: str = "default"):
        self.job_id = str(job_id or "").strip()
        self.user_id = str(user_id or "").strip() or "default"
        self.driver = get_driver()
        if self.driver:
            self._init_schema()

    @property
    def available(self) -> bool:
        return self.driver is not None

    def _run(self, cypher: str, **params: Any) -> List[Dict[str, Any]]:
        if not self.driver:
            return []
        try:
            with self.driver.session() as session:
                res = session.run(cypher, **params)
                return [dict(r) for r in res]
        except Exception as exc:
            logger.debug("neo4j_query_failed job_id=%s err=%s", self.job_id, exc)
            return []

    def _init_schema(self) -> None:
        """Initialize constraints and indexes (best-effort)."""

        if not self.driver:
            return

        constraints = [
            "CREATE CONSTRAINT host_unique IF NOT EXISTS FOR (h:Host) REQUIRE (h.ip, h.job_id) IS UNIQUE",
            "CREATE CONSTRAINT service_unique IF NOT EXISTS FOR (s:Service) REQUIRE (s.port, s.host_ip, s.job_id) IS UNIQUE",
            "CREATE CONSTRAINT vuln_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            "CREATE CONSTRAINT cred_unique IF NOT EXISTS FOR (c:Credential) REQUIRE c.id IS UNIQUE",
            "CREATE CONSTRAINT exploit_unique IF NOT EXISTS FOR (e:ExploitAttempt) REQUIRE e.id IS UNIQUE",
        ]

        try:
            with self.driver.session() as session:
                for q in constraints:
                    try:
                        session.run(q)
                    except Exception:
                        # Constraint already exists or server restricted; ignore.
                        pass
        except Exception as exc:
            logger.warning("neo4j_schema_init_failed job_id=%s err=%s", self.job_id, exc)

    # ---------------------------------------------------------------------
    # Write operations
    # ---------------------------------------------------------------------

    def add_host(self, ip: str, hostname: Optional[str] = None, os_info: Optional[str] = None) -> None:
        if not self.driver or not ip:
            return
        self._run(
            """
            MERGE (h:Host {ip: $ip, job_id: $job_id})
            SET h.hostname = COALESCE($hostname, h.hostname),
                h.os = COALESCE($os, h.os),
                h.user_id = $user_id,
                h.updated_at = datetime()
            """,
            ip=str(ip),
            job_id=self.job_id,
            user_id=self.user_id,
            hostname=str(hostname) if hostname else None,
            os=str(os_info) if os_info else None,
        )

    def add_service(
        self,
        host_ip: str,
        port: int,
        protocol: str = "tcp",
        name: Optional[str] = None,
        version: Optional[str] = None,
        banner: Optional[str] = None,
    ) -> None:
        if not self.driver or not host_ip or not port:
            return

        try:
            port_int = int(port)
        except Exception:
            return

        self._run(
            """
            MERGE (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
            SET s.protocol = $protocol,
                s.name = COALESCE($name, s.name),
                s.version = COALESCE($version, s.version),
                s.banner = COALESCE($banner, s.banner),
                s.user_id = $user_id,
                s.updated_at = datetime()
            """,
            port=port_int,
            host_ip=str(host_ip),
            job_id=self.job_id,
            protocol=str(protocol or "tcp"),
            name=str(name) if name else None,
            version=str(version) if version else None,
            banner=str(banner) if banner else None,
            user_id=self.user_id,
        )

        # Link to host (best-effort; host may not exist yet).
        self._run(
            """
            MATCH (h:Host {ip: $host_ip, job_id: $job_id})
            MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
            MERGE (h)-[:RUNS]->(s)
            """,
            host_ip=str(host_ip),
            port=port_int,
            job_id=self.job_id,
        )

    def add_vulnerability(
        self,
        host_ip: str,
        port: int,
        vuln_type: str,
        cve: Optional[str] = None,
        severity: str = "medium",
        details: Optional[str] = None,
    ) -> None:
        if not self.driver or not host_ip or not port or not vuln_type:
            return

        try:
            port_int = int(port)
        except Exception:
            return

        vuln_id = f"vuln-{host_ip}-{port_int}-{vuln_type}-{self.job_id}"[:80]

        self._run(
            """
            MERGE (v:Vulnerability {id: $vuln_id})
            SET v.type = $vuln_type,
                v.cve = $cve,
                v.severity = $severity,
                v.details = $details,
                v.host_ip = $host_ip,
                v.port = $port,
                v.job_id = $job_id,
                v.user_id = $user_id,
                v.verified = false,
                v.updated_at = datetime()
            """,
            vuln_id=vuln_id,
            vuln_type=str(vuln_type),
            cve=str(cve) if cve else None,
            severity=str(severity or "medium").lower(),
            details=str(details)[:4000] if details else None,
            host_ip=str(host_ip),
            port=port_int,
            job_id=self.job_id,
            user_id=self.user_id,
        )

        # Link to service (best-effort).
        self._run(
            """
            MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
            MATCH (v:Vulnerability {id: $vuln_id})
            MERGE (s)-[:HAS_VULN]->(v)
            """,
            port=port_int,
            host_ip=str(host_ip),
            job_id=self.job_id,
            vuln_id=vuln_id,
        )

    def add_credential(
        self,
        username: str,
        password: Optional[str] = None,
        hash_value: Optional[str] = None,
        source: Optional[str] = None,
        service_port: Optional[int] = None,
        host_ip: Optional[str] = None,
    ) -> None:
        if not self.driver or not username:
            return

        cred_id = f"cred-{username}-{host_ip or 'any'}-{service_port or 0}-{self.job_id}"[:80]

        self._run(
            """
            MERGE (c:Credential {id: $cred_id})
            SET c.username = $username,
                c.password = $password,
                c.hash = $hash_value,
                c.source = $source,
                c.job_id = $job_id,
                c.user_id = $user_id,
                c.updated_at = datetime()
            """,
            cred_id=cred_id,
            username=str(username),
            password=str(password) if password else None,
            hash_value=str(hash_value) if hash_value else None,
            source=str(source)[:200] if source else None,
            job_id=self.job_id,
            user_id=self.user_id,
        )

        if host_ip and service_port:
            try:
                port_int = int(service_port)
            except Exception:
                port_int = 0
            if port_int > 0:
                self._run(
                    """
                    MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
                    MATCH (c:Credential {id: $cred_id})
                    MERGE (c)-[:WORKS_ON]->(s)
                    """,
                    port=port_int,
                    host_ip=str(host_ip),
                    job_id=self.job_id,
                    cred_id=cred_id,
                )

    def record_exploit_attempt(
        self,
        host_ip: str,
        port: int,
        tool: str,
        command: str,
        success: bool,
        evidence: Optional[str] = None,
        cve: Optional[str] = None,
    ) -> None:
        if not self.driver or not host_ip or not tool:
            return

        try:
            port_int = int(port or 0)
        except Exception:
            port_int = 0

        time_bucket = int(time.time()) // 300  # 5-min bucket for idempotency
        attempt_id = f"attempt-{host_ip}-{port_int}-{tool}-{time_bucket}-{self.job_id}"[:100]

        self._run(
            """
            MERGE (a:ExploitAttempt {id: $attempt_id})
            SET a.tool = $tool,
                a.command = $command,
                a.success = $success,
                a.evidence = $evidence,
                a.cve = $cve,
                a.host_ip = $host_ip,
                a.port = $port,
                a.job_id = $job_id,
                a.user_id = $user_id,
                a.timestamp = datetime()
            """,
            attempt_id=attempt_id,
            tool=str(tool)[:120],
            command=str(command)[:2000],
            success=bool(success),
            evidence=str(evidence)[:4000] if evidence else None,
            cve=str(cve) if cve else None,
            host_ip=str(host_ip),
            port=port_int,
            job_id=self.job_id,
            user_id=self.user_id,
        )

        if cve:
            # Link attempt to any vuln with matching CVE marker (best-effort).
            self._run(
                """
                MATCH (v:Vulnerability {job_id: $job_id})
                WHERE v.cve = $cve OR v.type CONTAINS $cve
                MATCH (a:ExploitAttempt {id: $attempt_id})
                MERGE (v)-[:EXPLOITED_BY]->(a)
                """,
                job_id=self.job_id,
                cve=str(cve),
                attempt_id=attempt_id,
            )

    # ---------------------------------------------------------------------
    # Read operations (for agent context)
    # ---------------------------------------------------------------------

    def get_unexploited_services(self) -> List[Dict[str, Any]]:
        if not self.driver:
            return []
        rows = self._run(
            """
            MATCH (h:Host {job_id: $job_id})-[:RUNS]->(s:Service)
            WHERE NOT EXISTS {
                MATCH (s)-[:HAS_VULN]->(v:Vulnerability)-[:EXPLOITED_BY]->(a:ExploitAttempt)
                WHERE a.success = true
            }
            OPTIONAL MATCH (s)-[:HAS_VULN]->(v:Vulnerability)
            RETURN h.ip AS ip,
                   s.port AS port,
                   s.name AS service,
                   s.version AS version,
                   collect(DISTINCT v.type) AS vulns,
                   collect(DISTINCT v.cve) AS cves
            ORDER BY size(vulns) DESC
            """,
            job_id=self.job_id,
        )
        return rows

    def get_unattempted_services(self) -> List[Dict[str, Any]]:
        if not self.driver:
            return []
        return self._run(
            """
            MATCH (h:Host {job_id: $job_id})-[:RUNS]->(s:Service)
            WHERE NOT EXISTS {
                MATCH (a:ExploitAttempt {host_ip: h.ip, port: s.port, job_id: $job_id})
            }
            RETURN h.ip AS ip, s.port AS port, s.name AS service, s.version AS version
            """,
            job_id=self.job_id,
        )

    def get_all_credentials(self) -> List[Dict[str, Any]]:
        if not self.driver:
            return []
        return self._run(
            """
            MATCH (c:Credential {job_id: $job_id})
            OPTIONAL MATCH (c)-[:WORKS_ON]->(s:Service)
            RETURN c.username AS username,
                   c.password AS password,
                   c.hash AS hash,
                   c.source AS source,
                   s.port AS port,
                   s.host_ip AS host_ip
            """,
            job_id=self.job_id,
        )

    def get_attack_surface_summary(self, max_chars: int = 4500) -> str:
        """Return a text summary for LLM context."""

        if not self.driver:
            return "Knowledge graph not available."

        lines: List[str] = ["=== ATTACK SURFACE SUMMARY ==="]

        # Hosts and services
        hosts = self._run(
            """
            MATCH (h:Host {job_id: $job_id})-[:RUNS]->(s:Service)
            RETURN h.ip AS ip,
                   h.hostname AS hostname,
                   h.os AS os,
                   collect({port: s.port, name: s.name, version: s.version}) AS services
            """,
            job_id=self.job_id,
        )

        for h in hosts[:25]:
            ip = h.get("ip")
            if not ip:
                continue
            hostname = h.get("hostname")
            os_info = h.get("os")
            lines.append("")
            lines.append(f"[HOST] {ip}" + (f" ({hostname})" if hostname else ""))
            if os_info:
                lines.append(f"  OS: {os_info}")
            for svc in (h.get("services") or [])[:30]:
                try:
                    port = svc.get("port")
                    name = svc.get("name") or "unknown"
                    version = svc.get("version") or ""
                    lines.append(f"  Port {port}: {name} {version}".rstrip())
                except Exception:
                    continue

        # Vulnerabilities
        vulns = self._run(
            """
            MATCH (v:Vulnerability {job_id: $job_id})
            OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(a:ExploitAttempt)
            RETURN v.type AS type,
                   v.cve AS cve,
                   v.severity AS severity,
                   v.host_ip AS ip,
                   v.port AS port,
                   v.verified AS verified,
                   collect(DISTINCT CASE WHEN a IS NOT NULL THEN {tool: a.tool, success: a.success} END) AS attempts
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high' THEN 1
                    WHEN 'medium' THEN 2
                    ELSE 3
                END
            """,
            job_id=self.job_id,
        )

        if vulns:
            lines.append("")
            lines.append("=== VULNERABILITIES ===")
            for v in vulns[:40]:
                attempts = [a for a in (v.get("attempts") or []) if a]
                exploited = any(a.get("success") for a in attempts if isinstance(a, dict))
                status = "EXPLOITED" if exploited else ("ATTEMPTED" if attempts else "NOT ATTEMPTED")
                sev = str(v.get("severity") or "medium").upper()
                desc = f"[{sev}] {v.get('type')}"
                if v.get("cve"):
                    desc += f" ({v.get('cve')})"
                desc += f" on {v.get('ip')}:{v.get('port')} - {status}"
                lines.append("  " + desc)

        creds = self.get_all_credentials()
        if creds:
            lines.append("")
            lines.append("=== CREDENTIALS ===")
            for c in creds[:30]:
                secret = c.get("password") or c.get("hash") or "???"
                tail = ""
                if c.get("host_ip") and c.get("port"):
                    tail += f" @ {c.get('host_ip')}:{c.get('port')}"
                if c.get("source"):
                    tail += f" (from {c.get('source')})"
                lines.append(f"  {c.get('username')}:{secret}{tail}")

        unexploited = self.get_unexploited_services()
        if unexploited:
            lines.append("")
            lines.append(f"=== UNEXPLOITED SERVICES ({len(unexploited)}) ===")
            for svc in unexploited[:10]:
                name = svc.get("service") or "unknown"
                line = f"  {svc.get('ip')}:{svc.get('port')} ({name})"
                vulns_list = [v for v in (svc.get("vulns") or []) if v]
                if vulns_list:
                    line += " - vulns: " + ", ".join(vulns_list[:6])
                lines.append(line)

        out = "\n".join(lines).strip()
        return out[: int(max_chars or 4500)]

    def extract_metasploit_info(self, executions: list) -> Dict[str, Any]:
        """Extract metasploit module/payload from execution history."""

        info: Dict[str, Any] = {"module": None, "payload": None, "commands": []}
        for ex in executions or []:
            cmd = getattr(ex, "content", None) or str(ex)
            cmd_low = cmd.lower()
            if "msfconsole" in cmd_low or "metasploit" in cmd_low:
                info["commands"].append(cmd)
                use_match = re.search(r"use\s+(exploit/\S+|auxiliary/\S+)", cmd)
                if use_match:
                    info["module"] = use_match.group(1)
                payload_match = re.search(r"set\s+PAYLOAD\s+(\S+)", cmd, re.IGNORECASE)
                if payload_match:
                    info["payload"] = payload_match.group(1)
        return info
