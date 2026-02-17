"""kali-executor/open-interpreter/knowledge_graph.py

TazoSploit Knowledge Graph (Neo4j) — Enhanced Pipeline.

Node types:
    Target      — each IP being tested (dual-labeled Target:Host for backward compat)
    Port        — open ports per target
    Service     — detected services (HTTP, SSH, FTP, SMB, etc.)
    Technology  — detected tech stack (Apache, nginx, PHP, Node.js, etc.)
    Vulnerability — discovered vulnerabilities with severity
    CVE         — CVE references linked to vulnerabilities (global, not job-scoped)
    Exploit     — successful exploitation attempts (dual-labeled Exploit:ExploitAttempt)
    Credential  — harvested credentials (values REDACTED before storage)
    Endpoint    — discovered URL endpoints
    MitreTechnique — MITRE ATT&CK technique IDs used (global, not job-scoped)

Relationships:
    Target -[:HAS_PORT]-> Port
    Port -[:RUNS]-> Service
    Service -[:USES_TECH]-> Technology
    Target -[:HAS_VULNERABILITY]-> Vulnerability
    Vulnerability -[:REFERENCES]-> CVE
    Vulnerability -[:EXPLOITED_BY]-> Exploit
    Exploit -[:YIELDED]-> Credential
    Service -[:HAS_ENDPOINT]-> Endpoint
    Exploit -[:USES_TECHNIQUE]-> MitreTechnique

Design goals:
    - Persist attack surface data across an agent run.
    - Enable rich attack graph UI visualization.
    - OPTIONAL dependency: fail-open when Neo4j (or the driver) is unavailable.
    - Credential values are REDACTED before storage — originals never enter the graph.
"""

from __future__ import annotations

import logging
import os
import re
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_DRIVER: Any = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _redact(value: Optional[str], keep_chars: int = 2) -> Optional[str]:
    """Redact a sensitive value for safe graph storage.

    Keeps first and last *keep_chars* characters, replaces the middle with
    asterisks.  Short values are fully redacted.
    """
    if not value:
        return None
    v = str(value)
    if len(v) <= keep_chars * 2 + 2:
        return "*" * len(v)
    return v[:keep_chars] + "*" * (len(v) - keep_chars * 2) + v[-keep_chars:]


# ---------------------------------------------------------------------------
# Driver singleton
# ---------------------------------------------------------------------------

def get_driver() -> Any:
    """Get or create the Neo4j driver singleton.

    Returns ``neo4j.Driver | None``.
    """
    global _DRIVER
    if _DRIVER is not None:
        return _DRIVER

    enabled = _env("KNOWLEDGE_GRAPH_ENABLED", "true").lower() in ("1", "true", "yes")
    if not enabled:
        return None

    try:
        from neo4j import GraphDatabase  # type: ignore

        uri = _env("NEO4J_URI", "bolt://neo4j:7687")
        user = _env("NEO4J_USER", "neo4j")
        password = _env("NEO4J_PASSWORD", "changeme123")

        driver = GraphDatabase.driver(uri, auth=(user, password))

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


# ---------------------------------------------------------------------------
# KnowledgeGraph
# ---------------------------------------------------------------------------

class KnowledgeGraph:
    """TazoSploit knowledge graph interface.

    Provides methods to create and query all ten node types and nine
    relationship types needed for the attack graph UI.
    """

    def __init__(self, job_id: str, user_id: str = "default"):
        self.job_id = str(job_id or "").strip()
        self.user_id = str(user_id or "").strip() or "default"
        self.driver = get_driver()
        if self.driver:
            self._init_schema()

    @property
    def available(self) -> bool:
        return self.driver is not None

    # -- low-level helpers --------------------------------------------------

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
        """Create constraints and indexes (best-effort, idempotent)."""
        if not self.driver:
            return

        stmts = [
            # -- constraints ---------------------------------------------------
            # Target (backward-compat: Host label shares the constraint)
            "CREATE CONSTRAINT target_unique IF NOT EXISTS "
            "FOR (t:Target) REQUIRE (t.ip, t.job_id) IS UNIQUE",
            # Port
            "CREATE CONSTRAINT port_unique IF NOT EXISTS "
            "FOR (p:Port) REQUIRE (p.number, p.protocol, p.target_ip, p.job_id) IS UNIQUE",
            # Service (keep old key for backward compat)
            "CREATE CONSTRAINT service_unique IF NOT EXISTS "
            "FOR (s:Service) REQUIRE (s.port, s.host_ip, s.job_id) IS UNIQUE",
            # Technology
            "CREATE CONSTRAINT tech_unique IF NOT EXISTS "
            "FOR (tech:Technology) REQUIRE (tech.name, tech.job_id) IS UNIQUE",
            # Vulnerability
            "CREATE CONSTRAINT vuln_unique IF NOT EXISTS "
            "FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
            # CVE (global)
            "CREATE CONSTRAINT cve_unique IF NOT EXISTS "
            "FOR (c:CVE) REQUIRE c.cve_id IS UNIQUE",
            # Exploit (dual-labeled Exploit:ExploitAttempt)
            "CREATE CONSTRAINT exploit_v2_unique IF NOT EXISTS "
            "FOR (e:Exploit) REQUIRE e.id IS UNIQUE",
            # Credential
            "CREATE CONSTRAINT cred_unique IF NOT EXISTS "
            "FOR (c:Credential) REQUIRE c.id IS UNIQUE",
            # Endpoint
            "CREATE CONSTRAINT endpoint_unique IF NOT EXISTS "
            "FOR (ep:Endpoint) REQUIRE (ep.path, ep.target_ip, ep.port_number, ep.job_id) IS UNIQUE",
            # MitreTechnique (global)
            "CREATE CONSTRAINT mitre_unique IF NOT EXISTS "
            "FOR (mt:MitreTechnique) REQUIRE mt.technique_id IS UNIQUE",

            # -- indexes -------------------------------------------------------
            "CREATE INDEX target_job_idx IF NOT EXISTS FOR (t:Target) ON (t.job_id)",
            "CREATE INDEX port_job_idx IF NOT EXISTS FOR (p:Port) ON (p.job_id)",
            "CREATE INDEX service_job_idx IF NOT EXISTS FOR (s:Service) ON (s.job_id)",
            "CREATE INDEX vuln_job_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.job_id)",
            "CREATE INDEX exploit_job_idx IF NOT EXISTS FOR (e:Exploit) ON (e.job_id)",
            "CREATE INDEX cred_job_idx IF NOT EXISTS FOR (c:Credential) ON (c.job_id)",
            "CREATE INDEX endpoint_job_idx IF NOT EXISTS FOR (ep:Endpoint) ON (ep.job_id)",
            "CREATE INDEX tech_job_idx IF NOT EXISTS FOR (tech:Technology) ON (tech.job_id)",
        ]

        try:
            with self.driver.session() as session:
                for q in stmts:
                    try:
                        session.run(q)
                    except Exception:
                        pass
        except Exception as exc:
            logger.warning("neo4j_schema_init_failed job_id=%s err=%s", self.job_id, exc)

    # =====================================================================
    # WRITE: Target  (backward-compat: Host)
    # =====================================================================

    def add_target(self, ip: str, hostname: Optional[str] = None,
                   os_info: Optional[str] = None) -> None:
        """Create or update a Target node (dual-labeled ``Target:Host``)."""
        if not self.driver or not ip:
            return
        self._run(
            """
            MERGE (t:Target:Host {ip: $ip, job_id: $job_id})
            SET t.hostname = COALESCE($hostname, t.hostname),
                t.os       = COALESCE($os, t.os),
                t.user_id  = $user_id,
                t.updated_at = datetime()
            """,
            ip=str(ip).strip(),
            job_id=self.job_id,
            user_id=self.user_id,
            hostname=str(hostname).strip() if hostname else None,
            os=str(os_info).strip()[:200] if os_info else None,
        )

    # Backward-compat alias
    add_host = add_target

    # =====================================================================
    # WRITE: Port
    # =====================================================================

    def add_port(self, target_ip: str, port: int, protocol: str = "tcp",
                 state: str = "open") -> None:
        """Create a Port node and link ``Target -[:HAS_PORT]-> Port``."""
        if not self.driver or not target_ip or not port:
            return
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            return

        tip = str(target_ip).strip()
        proto = str(protocol or "tcp").lower()

        self._run(
            """
            MERGE (p:Port {number: $port, protocol: $protocol,
                           target_ip: $target_ip, job_id: $job_id})
            SET p.state      = $state,
                p.user_id    = $user_id,
                p.updated_at = datetime()
            """,
            port=port_int, protocol=proto, target_ip=tip,
            job_id=self.job_id, state=str(state or "open").lower(),
            user_id=self.user_id,
        )

        # Target -[:HAS_PORT]-> Port
        self._run(
            """
            MATCH (t:Target {ip: $target_ip, job_id: $job_id})
            MATCH (p:Port {number: $port, protocol: $protocol,
                           target_ip: $target_ip, job_id: $job_id})
            MERGE (t)-[:HAS_PORT]->(p)
            """,
            target_ip=tip, port=port_int, protocol=proto, job_id=self.job_id,
        )

    # =====================================================================
    # WRITE: Service
    # =====================================================================

    def add_service(self, host_ip: str, port: int, protocol: str = "tcp",
                    name: Optional[str] = None, version: Optional[str] = None,
                    banner: Optional[str] = None) -> None:
        """Create a Service node linked through Port to Target.

        Automatically creates Target and Port nodes if they don't exist.
        """
        if not self.driver or not host_ip or not port:
            return
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            return

        tip = str(host_ip).strip()
        proto = str(protocol or "tcp").lower()
        svc_name = str(name or "unknown").strip().lower()

        # Ensure Target + Port exist
        self.add_target(ip=tip)
        self.add_port(target_ip=tip, port=port_int, protocol=proto)

        # Create / update Service (keep old MERGE key for backward compat)
        self._run(
            """
            MERGE (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
            SET s.protocol   = $protocol,
                s.name       = COALESCE($name, s.name),
                s.version    = COALESCE($version, s.version),
                s.banner     = COALESCE($banner, s.banner),
                s.user_id    = $user_id,
                s.updated_at = datetime()
            """,
            port=port_int, host_ip=tip, job_id=self.job_id,
            protocol=proto,
            name=svc_name,
            version=str(version).strip()[:200] if version else None,
            banner=str(banner).strip()[:500] if banner else None,
            user_id=self.user_id,
        )

        # Port -[:RUNS]-> Service
        self._run(
            """
            MATCH (p:Port {number: $port, protocol: $protocol,
                           target_ip: $host_ip, job_id: $job_id})
            MATCH (s:Service {port: $port, host_ip: $host_ip, job_id: $job_id})
            MERGE (p)-[:RUNS]->(s)
            """,
            port=port_int, protocol=proto, host_ip=tip, job_id=self.job_id,
        )

    # =====================================================================
    # WRITE: Technology
    # =====================================================================

    def add_technology(self, name: str, version: Optional[str] = None,
                       category: Optional[str] = None,
                       target_ip: Optional[str] = None,
                       port: Optional[int] = None) -> None:
        """Create a Technology node and optionally link ``Service -[:USES_TECH]-> Technology``."""
        if not self.driver or not name:
            return
        tech_name = str(name).strip()
        if not tech_name:
            return

        self._run(
            """
            MERGE (tech:Technology {name: $name, job_id: $job_id})
            SET tech.version    = COALESCE($version, tech.version),
                tech.category   = COALESCE($category, tech.category),
                tech.user_id    = $user_id,
                tech.updated_at = datetime()
            """,
            name=tech_name, job_id=self.job_id,
            version=str(version).strip()[:100] if version else None,
            category=str(category).strip()[:50] if category else None,
            user_id=self.user_id,
        )

        # Service -[:USES_TECH]-> Technology
        if target_ip and port:
            try:
                port_int = int(port)
            except (ValueError, TypeError):
                return
            self._run(
                """
                MATCH (s:Service {port: $port, host_ip: $target_ip, job_id: $job_id})
                MATCH (tech:Technology {name: $tech_name, job_id: $job_id})
                MERGE (s)-[:USES_TECH]->(tech)
                """,
                port=port_int, target_ip=str(target_ip).strip(),
                tech_name=tech_name, job_id=self.job_id,
            )

    # =====================================================================
    # WRITE: Vulnerability
    # =====================================================================

    def add_vulnerability(self, host_ip: str, port: int, vuln_type: str,
                          cve: Optional[str] = None, severity: str = "medium",
                          details: Optional[str] = None) -> None:
        """Create a Vulnerability node linked to Target, and optionally to a CVE node."""
        if not self.driver or not host_ip or not port or not vuln_type:
            return
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            return

        tip = str(host_ip).strip()
        vuln_id = f"vuln-{tip}-{port_int}-{vuln_type}-{self.job_id}"[:120]

        self._run(
            """
            MERGE (v:Vulnerability {id: $vuln_id})
            SET v.type       = $vuln_type,
                v.severity   = $severity,
                v.details    = $details,
                v.host_ip    = $host_ip,
                v.port       = $port,
                v.job_id     = $job_id,
                v.user_id    = $user_id,
                v.verified   = false,
                v.updated_at = datetime()
            """,
            vuln_id=vuln_id,
            vuln_type=str(vuln_type).strip()[:200],
            severity=str(severity or "medium").lower().strip(),
            details=str(details)[:4000] if details else None,
            host_ip=tip, port=port_int,
            job_id=self.job_id, user_id=self.user_id,
        )

        # Target -[:HAS_VULNERABILITY]-> Vulnerability
        self._run(
            """
            MATCH (t:Target {ip: $target_ip, job_id: $job_id})
            MATCH (v:Vulnerability {id: $vuln_id})
            MERGE (t)-[:HAS_VULNERABILITY]->(v)
            """,
            target_ip=tip, vuln_id=vuln_id, job_id=self.job_id,
        )

        # Vulnerability -[:REFERENCES]-> CVE
        if cve:
            self.add_cve(cve_id=cve, vuln_id=vuln_id)

        return  # noqa: implicit None

    # =====================================================================
    # WRITE: CVE
    # =====================================================================

    def add_cve(self, cve_id: str, vuln_id: Optional[str] = None,
                description: Optional[str] = None) -> None:
        """Create a CVE node and optionally link ``Vulnerability -[:REFERENCES]-> CVE``."""
        if not self.driver or not cve_id:
            return

        cve_upper = str(cve_id).strip().upper()
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve_upper):
            return

        self._run(
            """
            MERGE (c:CVE {cve_id: $cve_id})
            SET c.description = COALESCE($description, c.description),
                c.updated_at  = datetime()
            """,
            cve_id=cve_upper,
            description=str(description)[:2000] if description else None,
        )

        if vuln_id:
            self._run(
                """
                MATCH (v:Vulnerability {id: $vuln_id})
                MATCH (c:CVE {cve_id: $cve_id})
                MERGE (v)-[:REFERENCES]->(c)
                """,
                vuln_id=vuln_id, cve_id=cve_upper,
            )

    # =====================================================================
    # WRITE: Exploit  (backward-compat: ExploitAttempt)
    # =====================================================================

    def add_exploit(self, host_ip: str, port: int, tool: str, command: str,
                    success: bool, evidence: Optional[str] = None,
                    cve: Optional[str] = None,
                    mitre_techniques: Optional[List[str]] = None) -> str:
        """Create an Exploit node (dual-labeled ``Exploit:ExploitAttempt``).

        Returns the exploit node ID for downstream linking.
        """
        if not self.driver or not host_ip or not tool:
            return ""

        try:
            port_int = int(port or 0)
        except (ValueError, TypeError):
            port_int = 0

        tip = str(host_ip).strip()
        time_bucket = int(time.time()) // 300
        exploit_id = (
            f"exploit-{tip}-{port_int}-{tool}-{time_bucket}-{self.job_id}"[:120]
        )

        self._run(
            """
            MERGE (e:Exploit:ExploitAttempt {id: $exploit_id})
            SET e.tool      = $tool,
                e.command   = $command,
                e.success   = $success,
                e.evidence  = $evidence,
                e.host_ip   = $host_ip,
                e.port      = $port,
                e.job_id    = $job_id,
                e.user_id   = $user_id,
                e.timestamp = datetime()
            """,
            exploit_id=exploit_id,
            tool=str(tool).strip().lower()[:120],
            command=str(command)[:2000],
            success=bool(success),
            evidence=str(evidence)[:4000] if evidence else None,
            host_ip=tip, port=port_int,
            job_id=self.job_id, user_id=self.user_id,
        )

        # Link to Vulnerability nodes via CVE match
        if cve:
            cve_upper = str(cve).strip().upper()
            # Try linking via CVE reference relationship
            self._run(
                """
                MATCH (v:Vulnerability {job_id: $job_id})
                WHERE v.host_ip = $host_ip
                MATCH (v)-[:REFERENCES]->(:CVE {cve_id: $cve})
                MATCH (e:Exploit {id: $exploit_id})
                MERGE (v)-[:EXPLOITED_BY]->(e)
                """,
                job_id=self.job_id, host_ip=tip, cve=cve_upper,
                exploit_id=exploit_id,
            )
            # Fallback: direct vuln type/id containing CVE string
            self._run(
                """
                MATCH (v:Vulnerability {job_id: $job_id})
                WHERE (v.type CONTAINS $cve OR v.id CONTAINS $cve)
                  AND v.host_ip = $host_ip
                MATCH (e:Exploit {id: $exploit_id})
                MERGE (v)-[:EXPLOITED_BY]->(e)
                """,
                job_id=self.job_id, cve=cve_upper, host_ip=tip,
                exploit_id=exploit_id,
            )

        # Link MITRE techniques
        for tech_id in (mitre_techniques or []):
            if tech_id:
                self.link_exploit_technique(exploit_id=exploit_id,
                                            technique_id=str(tech_id))

        return exploit_id

    def record_exploit_attempt(self, host_ip: str, port: int, tool: str,
                               command: str, success: bool,
                               evidence: Optional[str] = None,
                               cve: Optional[str] = None) -> None:
        """Backward-compatible wrapper for :meth:`add_exploit`."""
        self.add_exploit(
            host_ip=host_ip, port=port, tool=tool, command=command,
            success=success, evidence=evidence, cve=cve,
        )

    # =====================================================================
    # WRITE: Credential  (REDACTED)
    # =====================================================================

    def add_credential(self, username: str, password: Optional[str] = None,
                       hash_value: Optional[str] = None,
                       source: Optional[str] = None,
                       service_port: Optional[int] = None,
                       host_ip: Optional[str] = None,
                       exploit_id: Optional[str] = None) -> None:
        """Create a Credential node with **REDACTED** sensitive values.

        Passwords and hashes are redacted before storage in the graph.
        The original values are NEVER stored in Neo4j.
        """
        if not self.driver or not username:
            return

        cred_id = (
            f"cred-{username}-{host_ip or 'any'}-{service_port or 0}"
            f"-{self.job_id}"
        )[:120]

        # REDACT sensitive values
        redacted_pw = _redact(password) if password else None
        redacted_hash = _redact(hash_value) if hash_value else None

        # Detect hash type prefix (e.g. $6$ for sha512crypt)
        hash_type = None
        if hash_value:
            hm = re.match(r"^\$(\w+)\$", str(hash_value))
            if hm:
                hash_type = hm.group(1)

        self._run(
            """
            MERGE (c:Credential {id: $cred_id})
            SET c.username          = $username,
                c.password_redacted = $password,
                c.hash_redacted     = $hash_value,
                c.hash_type         = $hash_type,
                c.source            = $source,
                c.host_ip           = $host_ip,
                c.service_port      = $service_port,
                c.job_id            = $job_id,
                c.user_id           = $user_id,
                c.updated_at        = datetime()
            """,
            cred_id=cred_id,
            username=str(username).strip(),
            password=redacted_pw,
            hash_value=redacted_hash,
            hash_type=hash_type,
            source=str(source)[:200] if source else None,
            host_ip=str(host_ip).strip() if host_ip else None,
            service_port=int(service_port) if service_port else None,
            job_id=self.job_id, user_id=self.user_id,
        )

        # Exploit -[:YIELDED]-> Credential
        if exploit_id:
            self._run(
                """
                MATCH (e:Exploit {id: $exploit_id})
                MATCH (c:Credential {id: $cred_id})
                MERGE (e)-[:YIELDED]->(c)
                """,
                exploit_id=exploit_id, cred_id=cred_id,
            )
        elif host_ip and service_port:
            # Link to most recent successful exploit on same host:port
            try:
                port_int = int(service_port)
            except (ValueError, TypeError):
                port_int = 0
            if port_int > 0:
                self._run(
                    """
                    MATCH (e:Exploit {host_ip: $host_ip, port: $port,
                                      job_id: $job_id})
                    WHERE e.success = true
                    WITH e ORDER BY e.timestamp DESC LIMIT 1
                    MATCH (c:Credential {id: $cred_id})
                    MERGE (e)-[:YIELDED]->(c)
                    """,
                    host_ip=str(host_ip).strip(), port=port_int,
                    job_id=self.job_id, cred_id=cred_id,
                )

    # =====================================================================
    # WRITE: Endpoint
    # =====================================================================

    def add_endpoint(self, path: str, target_ip: str, port: int,
                     method: str = "GET", status_code: Optional[int] = None,
                     content_length: Optional[int] = None) -> None:
        """Create an Endpoint node linked ``Service -[:HAS_ENDPOINT]-> Endpoint``."""
        if not self.driver or not path or not target_ip or not port:
            return
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            return

        clean_path = str(path).strip()[:500]
        if not clean_path.startswith("/"):
            clean_path = "/" + clean_path
        tip = str(target_ip).strip()

        self._run(
            """
            MERGE (ep:Endpoint {path: $path, target_ip: $target_ip,
                                port_number: $port, job_id: $job_id})
            SET ep.method         = $method,
                ep.status_code    = $status_code,
                ep.content_length = $content_length,
                ep.user_id        = $user_id,
                ep.updated_at     = datetime()
            """,
            path=clean_path, target_ip=tip, port=port_int,
            job_id=self.job_id,
            method=str(method or "GET").upper()[:10],
            status_code=int(status_code) if status_code else None,
            content_length=int(content_length) if content_length else None,
            user_id=self.user_id,
        )

        # Service -[:HAS_ENDPOINT]-> Endpoint
        self._run(
            """
            MATCH (s:Service {port: $port, host_ip: $target_ip,
                              job_id: $job_id})
            MATCH (ep:Endpoint {path: $path, target_ip: $target_ip,
                                port_number: $port, job_id: $job_id})
            MERGE (s)-[:HAS_ENDPOINT]->(ep)
            """,
            port=port_int, target_ip=tip, path=clean_path,
            job_id=self.job_id,
        )

    # =====================================================================
    # WRITE: MitreTechnique
    # =====================================================================

    def add_mitre_technique(self, technique_id: str,
                            name: Optional[str] = None,
                            tactic: Optional[str] = None) -> None:
        """Create a MitreTechnique node (global, not job-scoped)."""
        if not self.driver or not technique_id:
            return

        tid = str(technique_id).strip().upper()
        if not re.match(r"^T\d{4}(\.\d{3})?$", tid):
            return

        self._run(
            """
            MERGE (mt:MitreTechnique {technique_id: $tid})
            SET mt.name       = COALESCE($name, mt.name),
                mt.tactic     = COALESCE($tactic, mt.tactic),
                mt.updated_at = datetime()
            """,
            tid=tid,
            name=str(name).strip()[:200] if name else None,
            tactic=str(tactic).strip()[:100] if tactic else None,
        )

    def link_exploit_technique(self, exploit_id: str,
                               technique_id: str) -> None:
        """Link ``Exploit -[:USES_TECHNIQUE]-> MitreTechnique``."""
        if not self.driver or not exploit_id or not technique_id:
            return

        tid = str(technique_id).strip().upper()
        # Ensure the technique node exists
        self.add_mitre_technique(technique_id=tid)

        self._run(
            """
            MATCH (e:Exploit {id: $exploit_id})
            MATCH (mt:MitreTechnique {technique_id: $tid})
            MERGE (e)-[:USES_TECHNIQUE]->(mt)
            """,
            exploit_id=exploit_id, tid=tid,
        )

    # =====================================================================
    # READ: Agent context helpers
    # =====================================================================

    def get_unexploited_services(self) -> List[Dict[str, Any]]:
        """Services without a successful exploit."""
        if not self.driver:
            return []
        return self._run(
            """
            MATCH (t:Target {job_id: $job_id})-[:HAS_PORT]->(p:Port)-[:RUNS]->(s:Service)
            WHERE NOT EXISTS {
                MATCH (t)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:EXPLOITED_BY]->(e:Exploit)
                WHERE e.success = true AND e.host_ip = t.ip AND e.port = p.number
            }
            OPTIONAL MATCH (t)-[:HAS_VULNERABILITY]->(v:Vulnerability)
            WHERE v.port = p.number
            RETURN t.ip AS ip,
                   p.number AS port,
                   s.name AS service,
                   s.version AS version,
                   collect(DISTINCT v.type) AS vulns
            ORDER BY size(collect(DISTINCT v.type)) DESC
            """,
            job_id=self.job_id,
        )

    def get_unattempted_services(self) -> List[Dict[str, Any]]:
        """Services not yet targeted by any exploit attempt."""
        if not self.driver:
            return []
        return self._run(
            """
            MATCH (t:Target {job_id: $job_id})-[:HAS_PORT]->(p:Port)-[:RUNS]->(s:Service)
            WHERE NOT EXISTS {
                MATCH (e:Exploit {host_ip: t.ip, port: p.number, job_id: $job_id})
            }
            RETURN t.ip AS ip, p.number AS port,
                   s.name AS service, s.version AS version
            """,
            job_id=self.job_id,
        )

    def get_all_credentials(self) -> List[Dict[str, Any]]:
        """All credentials for the job (values are already redacted)."""
        if not self.driver:
            return []
        return self._run(
            """
            MATCH (c:Credential {job_id: $job_id})
            OPTIONAL MATCH (e:Exploit)-[:YIELDED]->(c)
            RETURN c.username          AS username,
                   c.password_redacted AS password,
                   c.hash_redacted     AS hash,
                   c.hash_type         AS hash_type,
                   c.source            AS source,
                   c.host_ip           AS host_ip,
                   c.service_port      AS port,
                   e.tool              AS exploit_tool
            """,
            job_id=self.job_id,
        )

    def get_attack_surface_summary(self, max_chars: int = 4500) -> str:
        """Return a text summary of the full attack surface for LLM context."""
        if not self.driver:
            return "Knowledge graph not available."

        lines: List[str] = ["=== ATTACK SURFACE SUMMARY ==="]

        # -- Targets with ports and services --------------------------------
        targets = self._run(
            """
            MATCH (t:Target {job_id: $job_id})
            OPTIONAL MATCH (t)-[:HAS_PORT]->(p:Port)-[:RUNS]->(s:Service)
            WITH t,
                 collect({port: p.number, proto: p.protocol,
                          name: s.name, version: s.version}) AS services
            RETURN t.ip AS ip, t.hostname AS hostname, t.os AS os, services
            """,
            job_id=self.job_id,
        )

        for h in targets[:25]:
            ip = h.get("ip")
            if not ip:
                continue
            hostname = h.get("hostname")
            os_info = h.get("os")
            lines.append("")
            lines.append(
                f"[TARGET] {ip}" + (f" ({hostname})" if hostname else "")
            )
            if os_info:
                lines.append(f"  OS: {os_info}")
            for svc in (h.get("services") or [])[:30]:
                try:
                    port = svc.get("port")
                    if not port:
                        continue
                    name = svc.get("name") or "unknown"
                    version = svc.get("version") or ""
                    proto = svc.get("proto") or "tcp"
                    lines.append(
                        f"  Port {port}/{proto}: {name} {version}".rstrip()
                    )
                except Exception:
                    continue

        # -- Technologies ----------------------------------------------------
        techs = self._run(
            """
            MATCH (tech:Technology {job_id: $job_id})
            OPTIONAL MATCH (s:Service)-[:USES_TECH]->(tech)
            RETURN tech.name AS name, tech.version AS version,
                   tech.category AS category,
                   collect(DISTINCT s.host_ip + ':' + toString(s.port)) AS seen_on
            """,
            job_id=self.job_id,
        )
        if techs:
            lines.append("")
            lines.append("=== TECHNOLOGIES ===")
            for t in techs[:30]:
                ver = f" {t.get('version')}" if t.get("version") else ""
                seen = ", ".join(
                    s for s in (t.get("seen_on") or [])
                    if s and "null" not in str(s)
                )[:100]
                loc = f" @ {seen}" if seen else ""
                lines.append(f"  {t.get('name')}{ver}{loc}")

        # -- Vulnerabilities -------------------------------------------------
        vulns = self._run(
            """
            MATCH (v:Vulnerability {job_id: $job_id})
            OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(e:Exploit)
            OPTIONAL MATCH (v)-[:REFERENCES]->(c:CVE)
            RETURN v.type AS type,
                   collect(DISTINCT c.cve_id) AS cves,
                   v.severity AS severity,
                   v.host_ip AS ip,
                   v.port AS port,
                   v.verified AS verified,
                   collect(DISTINCT CASE WHEN e IS NOT NULL
                       THEN {tool: e.tool, success: e.success} END) AS attempts
            ORDER BY
                CASE v.severity
                    WHEN 'critical' THEN 0
                    WHEN 'high'     THEN 1
                    WHEN 'medium'   THEN 2
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
                exploited = any(
                    a.get("success") for a in attempts if isinstance(a, dict)
                )
                status = (
                    "EXPLOITED" if exploited
                    else ("ATTEMPTED" if attempts else "NOT ATTEMPTED")
                )
                sev = str(v.get("severity") or "medium").upper()
                desc = f"[{sev}] {v.get('type')}"
                cves = [c for c in (v.get("cves") or []) if c]
                if cves:
                    desc += f" ({', '.join(cves)})"
                desc += f" on {v.get('ip')}:{v.get('port')} - {status}"
                lines.append("  " + desc)

        # -- Credentials (redacted) -----------------------------------------
        creds = self.get_all_credentials()
        if creds:
            lines.append("")
            lines.append("=== CREDENTIALS (REDACTED) ===")
            for c in creds[:30]:
                secret = c.get("password") or c.get("hash") or "[no value]"
                tail = ""
                if c.get("host_ip") and c.get("port"):
                    tail += f" @ {c.get('host_ip')}:{c.get('port')}"
                if c.get("source"):
                    tail += f" (from {c.get('source')})"
                lines.append(f"  {c.get('username')}:{secret}{tail}")

        # -- Endpoints -------------------------------------------------------
        endpoints = self._run(
            """
            MATCH (ep:Endpoint {job_id: $job_id})
            RETURN ep.path AS path, ep.target_ip AS ip,
                   ep.port_number AS port,
                   ep.status_code AS status, ep.method AS method
            ORDER BY ep.path
            LIMIT 50
            """,
            job_id=self.job_id,
        )
        if endpoints:
            lines.append("")
            lines.append(f"=== ENDPOINTS ({len(endpoints)}+) ===")
            for ep in endpoints[:20]:
                st = f" [{ep.get('status')}]" if ep.get("status") else ""
                lines.append(
                    f"  {ep.get('method', 'GET')} "
                    f"{ep.get('ip')}:{ep.get('port')}{ep.get('path')}{st}"
                )

        # -- Unexploited services -------------------------------------------
        unexploited = self.get_unexploited_services()
        if unexploited:
            lines.append("")
            lines.append(
                f"=== UNEXPLOITED SERVICES ({len(unexploited)}) ==="
            )
            for svc in unexploited[:10]:
                name = svc.get("service") or "unknown"
                line = f"  {svc.get('ip')}:{svc.get('port')} ({name})"
                vulns_list = [v for v in (svc.get("vulns") or []) if v]
                if vulns_list:
                    line += " - vulns: " + ", ".join(vulns_list[:6])
                lines.append(line)

        out = "\n".join(lines).strip()
        return out[: int(max_chars or 4500)]

    # =====================================================================
    # Metasploit helper (kept for backward compat)
    # =====================================================================

    def extract_metasploit_info(self, executions: list) -> Dict[str, Any]:
        """Extract metasploit module/payload from execution history."""
        info: Dict[str, Any] = {
            "module": None, "payload": None, "commands": [],
        }
        for ex in executions or []:
            cmd = getattr(ex, "content", None) or str(ex)
            cmd_low = cmd.lower()
            if "msfconsole" in cmd_low or "metasploit" in cmd_low:
                info["commands"].append(cmd)
                use_match = re.search(
                    r"use\s+(exploit/\S+|auxiliary/\S+)", cmd
                )
                if use_match:
                    info["module"] = use_match.group(1)
                payload_match = re.search(
                    r"set\s+PAYLOAD\s+(\S+)", cmd, re.IGNORECASE
                )
                if payload_match:
                    info["payload"] = payload_match.group(1)
        return info
