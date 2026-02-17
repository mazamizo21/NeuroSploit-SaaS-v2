"""kali-executor/open-interpreter/graph_queries.py

Helper functions for common Neo4j graph queries.

Used by the API layer to serve the attack graph UI.  Every function
accepts a neo4j ``Driver`` (or ``None``) and a ``job_id``, returns
plain dicts/lists — never raw Neo4j objects.

All functions are fail-safe: return empty structures when the driver
is unavailable or the query fails.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _run(driver: Any, cypher: str, **params: Any) -> List[Dict[str, Any]]:
    """Execute a Cypher query and return a list of dicts."""
    if not driver:
        return []
    try:
        with driver.session() as session:
            result = session.run(cypher, **params)
            return [dict(record) for record in result]
    except Exception as exc:
        logger.debug("graph_query_failed err=%s", exc)
        return []


def _run_single(driver: Any, cypher: str,
                **params: Any) -> Optional[Dict[str, Any]]:
    """Execute a query and return the first row or None."""
    rows = _run(driver, cypher, **params)
    return rows[0] if rows else None


# ===================================================================
# 1. Full graph for UI rendering (nodes + edges)
# ===================================================================

def get_full_graph(driver: Any, job_id: str) -> Dict[str, List]:
    """Return the complete graph for a job as nodes + edges.

    Returns::

        {
            "nodes": [
                {"id": "...", "label": "Target", "properties": {...}},
                ...
            ],
            "edges": [
                {"source": "...", "target": "...", "type": "HAS_PORT"},
                ...
            ]
        }
    """
    if not driver or not job_id:
        return {"nodes": [], "edges": []}

    nodes: Dict[str, Dict] = {}
    edges: List[Dict] = []

    # --- Targets ---
    for row in _run(driver, """
        MATCH (t:Target {job_id: $job_id})
        RETURN t.ip AS ip, t.hostname AS hostname, t.os AS os
    """, job_id=job_id):
        nid = f"target-{row['ip']}"
        nodes[nid] = {
            "id": nid, "label": "Target",
            "properties": {
                "ip": row["ip"],
                "hostname": row.get("hostname"),
                "os": row.get("os"),
            },
        }

    # --- Ports ---
    for row in _run(driver, """
        MATCH (t:Target {job_id: $job_id})-[:HAS_PORT]->(p:Port)
        RETURN t.ip AS target_ip, p.number AS port,
               p.protocol AS protocol, p.state AS state
    """, job_id=job_id):
        nid = f"port-{row['target_ip']}-{row['port']}-{row['protocol']}"
        nodes[nid] = {
            "id": nid, "label": "Port",
            "properties": {
                "number": row["port"],
                "protocol": row["protocol"],
                "state": row.get("state"),
            },
        }
        src = f"target-{row['target_ip']}"
        if src in nodes:
            edges.append({"source": src, "target": nid, "type": "HAS_PORT"})

    # --- Services ---
    for row in _run(driver, """
        MATCH (p:Port {job_id: $job_id})-[:RUNS]->(s:Service)
        RETURN p.target_ip AS target_ip, p.number AS port_num,
               p.protocol AS protocol,
               s.name AS name, s.version AS version, s.port AS sport,
               s.host_ip AS host_ip
    """, job_id=job_id):
        svc_ip = row.get("host_ip") or row.get("target_ip")
        svc_port = row.get("sport") or row.get("port_num")
        nid = f"service-{svc_ip}-{svc_port}-{row.get('name', 'unknown')}"
        nodes[nid] = {
            "id": nid, "label": "Service",
            "properties": {
                "name": row.get("name"),
                "version": row.get("version"),
                "port": svc_port,
                "host_ip": svc_ip,
            },
        }
        port_nid = f"port-{row['target_ip']}-{row['port_num']}-{row['protocol']}"
        if port_nid in nodes:
            edges.append({"source": port_nid, "target": nid, "type": "RUNS"})

    # --- Technologies ---
    for row in _run(driver, """
        MATCH (tech:Technology {job_id: $job_id})
        OPTIONAL MATCH (s:Service)-[:USES_TECH]->(tech)
        RETURN tech.name AS name, tech.version AS version,
               tech.category AS category,
               collect(DISTINCT {ip: s.host_ip, port: s.port}) AS services
    """, job_id=job_id):
        nid = f"tech-{row['name']}"
        nodes[nid] = {
            "id": nid, "label": "Technology",
            "properties": {
                "name": row["name"],
                "version": row.get("version"),
                "category": row.get("category"),
            },
        }
        for svc in (row.get("services") or []):
            if svc and svc.get("ip") and svc.get("port"):
                # Find matching service node
                for sid, snode in nodes.items():
                    if (snode["label"] == "Service"
                            and snode["properties"].get("host_ip") == svc["ip"]
                            and snode["properties"].get("port") == svc["port"]):
                        edges.append({
                            "source": sid, "target": nid,
                            "type": "USES_TECH",
                        })
                        break

    # --- Vulnerabilities ---
    for row in _run(driver, """
        MATCH (v:Vulnerability {job_id: $job_id})
        RETURN v.id AS vid, v.type AS type, v.severity AS severity,
               v.host_ip AS host_ip, v.port AS port, v.verified AS verified
    """, job_id=job_id):
        nid = f"vuln-{row['vid']}"
        nodes[nid] = {
            "id": nid, "label": "Vulnerability",
            "properties": {
                "type": row.get("type"),
                "severity": row.get("severity"),
                "host_ip": row.get("host_ip"),
                "port": row.get("port"),
                "verified": row.get("verified"),
            },
        }
        # Target -[:HAS_VULNERABILITY]-> Vulnerability
        tgt = f"target-{row.get('host_ip')}"
        if tgt in nodes:
            edges.append({
                "source": tgt, "target": nid,
                "type": "HAS_VULNERABILITY",
            })

    # --- CVEs ---
    for row in _run(driver, """
        MATCH (v:Vulnerability {job_id: $job_id})-[:REFERENCES]->(c:CVE)
        RETURN v.id AS vid, c.cve_id AS cve_id, c.description AS description
    """, job_id=job_id):
        cid = f"cve-{row['cve_id']}"
        if cid not in nodes:
            nodes[cid] = {
                "id": cid, "label": "CVE",
                "properties": {
                    "cve_id": row["cve_id"],
                    "description": row.get("description"),
                },
            }
        vid = f"vuln-{row['vid']}"
        if vid in nodes:
            edges.append({
                "source": vid, "target": cid, "type": "REFERENCES",
            })

    # --- Exploits ---
    for row in _run(driver, """
        MATCH (e:Exploit {job_id: $job_id})
        RETURN e.id AS eid, e.tool AS tool, e.success AS success,
               e.host_ip AS host_ip, e.port AS port,
               e.timestamp AS timestamp
    """, job_id=job_id):
        nid = f"exploit-{row['eid']}"
        nodes[nid] = {
            "id": nid, "label": "Exploit",
            "properties": {
                "tool": row.get("tool"),
                "success": row.get("success"),
                "host_ip": row.get("host_ip"),
                "port": row.get("port"),
                "timestamp": str(row.get("timestamp") or ""),
            },
        }

    # Vulnerability -[:EXPLOITED_BY]-> Exploit
    for row in _run(driver, """
        MATCH (v:Vulnerability {job_id: $job_id})-[:EXPLOITED_BY]->(e:Exploit)
        RETURN v.id AS vid, e.id AS eid
    """, job_id=job_id):
        vid = f"vuln-{row['vid']}"
        eid = f"exploit-{row['eid']}"
        if vid in nodes and eid in nodes:
            edges.append({
                "source": vid, "target": eid, "type": "EXPLOITED_BY",
            })

    # --- Credentials ---
    for row in _run(driver, """
        MATCH (c:Credential {job_id: $job_id})
        RETURN c.id AS cid, c.username AS username,
               c.password_redacted AS password,
               c.hash_redacted AS hash,
               c.source AS source,
               c.host_ip AS host_ip, c.service_port AS port
    """, job_id=job_id):
        nid = f"cred-{row['cid']}"
        nodes[nid] = {
            "id": nid, "label": "Credential",
            "properties": {
                "username": row.get("username"),
                "password_redacted": row.get("password"),
                "hash_redacted": row.get("hash"),
                "source": row.get("source"),
                "host_ip": row.get("host_ip"),
                "port": row.get("port"),
            },
        }

    # Exploit -[:YIELDED]-> Credential
    for row in _run(driver, """
        MATCH (e:Exploit {job_id: $job_id})-[:YIELDED]->(c:Credential)
        RETURN e.id AS eid, c.id AS cid
    """, job_id=job_id):
        eid = f"exploit-{row['eid']}"
        cid = f"cred-{row['cid']}"
        if eid in nodes and cid in nodes:
            edges.append({
                "source": eid, "target": cid, "type": "YIELDED",
            })

    # --- Endpoints ---
    for row in _run(driver, """
        MATCH (ep:Endpoint {job_id: $job_id})
        RETURN ep.path AS path, ep.target_ip AS target_ip,
               ep.port_number AS port, ep.method AS method,
               ep.status_code AS status_code
    """, job_id=job_id):
        nid = f"endpoint-{row['target_ip']}-{row['port']}-{row['path']}"
        nodes[nid] = {
            "id": nid, "label": "Endpoint",
            "properties": {
                "path": row.get("path"),
                "method": row.get("method"),
                "status_code": row.get("status_code"),
                "target_ip": row.get("target_ip"),
                "port": row.get("port"),
            },
        }

    # Service -[:HAS_ENDPOINT]-> Endpoint
    for row in _run(driver, """
        MATCH (s:Service {job_id: $job_id})-[:HAS_ENDPOINT]->(ep:Endpoint)
        RETURN s.host_ip AS host_ip, s.port AS port, s.name AS svc_name,
               ep.path AS path, ep.target_ip AS ep_ip,
               ep.port_number AS ep_port
    """, job_id=job_id):
        svc_nid = f"service-{row['host_ip']}-{row['port']}-{row.get('svc_name', 'unknown')}"
        ep_nid = f"endpoint-{row['ep_ip']}-{row['ep_port']}-{row['path']}"
        if svc_nid in nodes and ep_nid in nodes:
            edges.append({
                "source": svc_nid, "target": ep_nid,
                "type": "HAS_ENDPOINT",
            })

    # --- MITRE Techniques ---
    for row in _run(driver, """
        MATCH (e:Exploit {job_id: $job_id})-[:USES_TECHNIQUE]->(mt:MitreTechnique)
        RETURN e.id AS eid, mt.technique_id AS tid,
               mt.name AS name, mt.tactic AS tactic
    """, job_id=job_id):
        mid = f"mitre-{row['tid']}"
        if mid not in nodes:
            nodes[mid] = {
                "id": mid, "label": "MitreTechnique",
                "properties": {
                    "technique_id": row["tid"],
                    "name": row.get("name"),
                    "tactic": row.get("tactic"),
                },
            }
        eid = f"exploit-{row['eid']}"
        if eid in nodes:
            edges.append({
                "source": eid, "target": mid,
                "type": "USES_TECHNIQUE",
            })

    # Also include standalone MITRE technique nodes recorded via parsers
    for row in _run(driver, """
        MATCH (mt:MitreTechnique)
        WHERE NOT EXISTS {
            MATCH (e:Exploit {job_id: $job_id})-[:USES_TECHNIQUE]->(mt)
        }
        AND EXISTS {
            MATCH (mt) WHERE mt.technique_id IS NOT NULL
        }
        RETURN mt.technique_id AS tid, mt.name AS name, mt.tactic AS tactic
    """, job_id=job_id):
        mid = f"mitre-{row['tid']}"
        if mid not in nodes:
            nodes[mid] = {
                "id": mid, "label": "MitreTechnique",
                "properties": {
                    "technique_id": row["tid"],
                    "name": row.get("name"),
                    "tactic": row.get("tactic"),
                },
            }

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
    }


# ===================================================================
# 2. Get all nodes for a job (flat list)
# ===================================================================

def get_all_nodes_for_job(driver: Any, job_id: str) -> List[Dict[str, Any]]:
    """Return every node associated with a job, across all labels.

    Each entry includes ``label`` and ``properties`` keys.
    """
    if not driver or not job_id:
        return []

    full = get_full_graph(driver, job_id)
    return full.get("nodes", [])


# ===================================================================
# 3. Attack paths  (Target → Vuln → Exploit chains)
# ===================================================================

def get_attack_paths(driver: Any, job_id: str) -> List[Dict[str, Any]]:
    """Return attack path chains: Target → Vulnerability → Exploit.

    Each result is a dict with target, vulnerability, exploit, and
    optional credential/technique info.
    """
    return _run(driver, """
        MATCH (t:Target {job_id: $job_id})
              -[:HAS_VULNERABILITY]->(v:Vulnerability)
              -[:EXPLOITED_BY]->(e:Exploit)
        OPTIONAL MATCH (e)-[:YIELDED]->(c:Credential)
        OPTIONAL MATCH (e)-[:USES_TECHNIQUE]->(mt:MitreTechnique)
        OPTIONAL MATCH (v)-[:REFERENCES]->(cve:CVE)
        RETURN t.ip                AS target_ip,
               t.hostname          AS target_hostname,
               v.type              AS vuln_type,
               v.severity          AS vuln_severity,
               collect(DISTINCT cve.cve_id) AS cves,
               e.tool              AS exploit_tool,
               e.success           AS exploit_success,
               e.timestamp         AS exploit_time,
               collect(DISTINCT c.username)    AS credentials,
               collect(DISTINCT mt.technique_id) AS mitre_techniques
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                ELSE 3
            END,
            e.timestamp DESC
    """, job_id=job_id)


# ===================================================================
# 4. Most connected targets
# ===================================================================

def get_most_connected_targets(driver: Any, job_id: str,
                               limit: int = 20) -> List[Dict[str, Any]]:
    """Rank targets by total relationship count (ports, vulns, exploits)."""
    return _run(driver, """
        MATCH (t:Target {job_id: $job_id})
        OPTIONAL MATCH (t)-[:HAS_PORT]->(p:Port)
        OPTIONAL MATCH (t)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(e:Exploit)
        WHERE e.success = true
        RETURN t.ip          AS ip,
               t.hostname    AS hostname,
               t.os          AS os,
               count(DISTINCT p) AS port_count,
               count(DISTINCT v) AS vuln_count,
               count(DISTINCT e) AS exploit_count,
               count(DISTINCT p) + count(DISTINCT v) + count(DISTINCT e)
                   AS total_connections
        ORDER BY total_connections DESC
        LIMIT $limit
    """, job_id=job_id, limit=int(limit))


# ===================================================================
# 5. Vulnerability summary (by severity)
# ===================================================================

def get_vulnerability_summary(driver: Any,
                              job_id: str) -> Dict[str, Any]:
    """Return vulnerability counts grouped by severity + total."""
    rows = _run(driver, """
        MATCH (v:Vulnerability {job_id: $job_id})
        OPTIONAL MATCH (v)-[:EXPLOITED_BY]->(e:Exploit)
        WHERE e.success = true
        RETURN v.severity AS severity,
               count(v) AS total,
               count(DISTINCT e) AS exploited
        ORDER BY
            CASE v.severity
                WHEN 'critical' THEN 0
                WHEN 'high'     THEN 1
                WHEN 'medium'   THEN 2
                WHEN 'low'      THEN 3
                ELSE 4
            END
    """, job_id=job_id)

    by_severity = {}
    grand_total = 0
    grand_exploited = 0
    for r in rows:
        sev = r.get("severity") or "unknown"
        total = r.get("total", 0)
        exploited = r.get("exploited", 0)
        by_severity[sev] = {"total": total, "exploited": exploited}
        grand_total += total
        grand_exploited += exploited

    return {
        "by_severity": by_severity,
        "total": grand_total,
        "total_exploited": grand_exploited,
    }


# ===================================================================
# 6. Service map (grouped by target)
# ===================================================================

def get_service_map(driver: Any, job_id: str) -> List[Dict[str, Any]]:
    """Return services grouped by target IP."""
    return _run(driver, """
        MATCH (t:Target {job_id: $job_id})-[:HAS_PORT]->(p:Port)-[:RUNS]->(s:Service)
        OPTIONAL MATCH (s)-[:USES_TECH]->(tech:Technology)
        RETURN t.ip AS target_ip,
               t.hostname AS hostname,
               collect(DISTINCT {
                   port: p.number,
                   protocol: p.protocol,
                   service: s.name,
                   version: s.version,
                   technologies: collect(DISTINCT tech.name)
               }) AS services
        ORDER BY t.ip
    """, job_id=job_id)


# ===================================================================
# 7. Credential map (all redacted)
# ===================================================================

def get_credential_map(driver: Any, job_id: str) -> List[Dict[str, Any]]:
    """Return all credentials for a job (values already redacted in graph)."""
    return _run(driver, """
        MATCH (c:Credential {job_id: $job_id})
        OPTIONAL MATCH (e:Exploit)-[:YIELDED]->(c)
        RETURN c.username          AS username,
               c.password_redacted AS password_redacted,
               c.hash_redacted     AS hash_redacted,
               c.hash_type         AS hash_type,
               c.source            AS source,
               c.host_ip           AS host_ip,
               c.service_port      AS port,
               e.tool              AS found_by_tool,
               e.success           AS exploit_success
        ORDER BY c.username
    """, job_id=job_id)


# ===================================================================
# 8. MITRE technique coverage
# ===================================================================

def get_technique_coverage(driver: Any,
                           job_id: str) -> List[Dict[str, Any]]:
    """Return MITRE ATT&CK techniques used in this job.

    Includes both tool-based (from parsers) and exploit-linked techniques.
    """
    return _run(driver, """
        MATCH (mt:MitreTechnique)
        OPTIONAL MATCH (e:Exploit {job_id: $job_id})-[:USES_TECHNIQUE]->(mt)
        WITH mt, collect(DISTINCT e.tool) AS tools,
             count(DISTINCT e) AS exploit_count
        RETURN mt.technique_id  AS technique_id,
               mt.name          AS name,
               mt.tactic        AS tactic,
               tools,
               exploit_count
        ORDER BY mt.tactic, mt.technique_id
    """, job_id=job_id)


# ===================================================================
# 9. Endpoint map
# ===================================================================

def get_endpoint_map(driver: Any, job_id: str,
                     limit: int = 200) -> List[Dict[str, Any]]:
    """Return discovered endpoints for a job."""
    return _run(driver, """
        MATCH (ep:Endpoint {job_id: $job_id})
        OPTIONAL MATCH (s:Service)-[:HAS_ENDPOINT]->(ep)
        RETURN ep.path           AS path,
               ep.target_ip      AS target_ip,
               ep.port_number    AS port,
               ep.method         AS method,
               ep.status_code    AS status_code,
               ep.content_length AS content_length,
               s.name            AS service_name
        ORDER BY ep.target_ip, ep.port_number, ep.path
        LIMIT $limit
    """, job_id=job_id, limit=int(limit))


# ===================================================================
# 10. Technology map
# ===================================================================

def get_technology_map(driver: Any, job_id: str) -> List[Dict[str, Any]]:
    """Return all detected technologies for a job."""
    return _run(driver, """
        MATCH (tech:Technology {job_id: $job_id})
        OPTIONAL MATCH (s:Service)-[:USES_TECH]->(tech)
        RETURN tech.name     AS name,
               tech.version  AS version,
               tech.category AS category,
               collect(DISTINCT {ip: s.host_ip, port: s.port}) AS seen_on
        ORDER BY tech.category, tech.name
    """, job_id=job_id)


# ===================================================================
# 11. Job statistics (overview dashboard)
# ===================================================================

def get_job_statistics(driver: Any, job_id: str) -> Dict[str, int]:
    """Return counts of each node type for a job."""
    if not driver or not job_id:
        return {}

    counts = {}
    for label in ("Target", "Port", "Service", "Technology",
                  "Vulnerability", "CVE", "Exploit", "Credential",
                  "Endpoint", "MitreTechnique"):
        row = _run_single(driver, f"""
            MATCH (n:{label})
            WHERE n.job_id = $job_id
               OR (NOT EXISTS(n.job_id) AND '{label}' IN ['CVE', 'MitreTechnique'])
            RETURN count(n) AS cnt
        """, job_id=job_id)
        counts[label.lower()] = (row or {}).get("cnt", 0)

    return counts


# ===================================================================
# 12. Delete all data for a job (cleanup)
# ===================================================================

def delete_job_data(driver: Any, job_id: str) -> int:
    """Delete all job-scoped nodes and their relationships.

    Returns the number of nodes deleted.  Global nodes (CVE,
    MitreTechnique) are NOT deleted as they may be shared.
    """
    if not driver or not job_id:
        return 0

    rows = _run(driver, """
        MATCH (n)
        WHERE n.job_id = $job_id
        DETACH DELETE n
        RETURN count(*) AS deleted
    """, job_id=job_id)

    return (rows[0] if rows else {}).get("deleted", 0)
