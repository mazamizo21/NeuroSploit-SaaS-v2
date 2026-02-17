/**
 * TazoSploit Neo4j Client — Server-side only
 *
 * Connects to the Neo4j knowledge graph to fetch attack surface data
 * for the force-graph visualization. This module is used exclusively
 * by Next.js API route handlers (runs on the Node.js server, never in the browser).
 *
 * Neo4j credentials are sourced from docker-compose.yml:
 *   - Host: tazosploit-neo4j (Docker) / localhost (dev)
 *   - Bolt port: 7687
 *   - User: neo4j
 *   - Password: changeme123 (NEO4J_PASSWORD env)
 */

import neo4j, { Driver, Session, Record as Neo4jRecord } from "neo4j-driver";
import {
  GraphNode,
  GraphLink,
  GraphData,
  GraphNodeType,
  NODE_COLORS,
  NODE_SIZES,
} from "./graphTypes";

// ─── Singleton driver ──────────────────────────────────────────────────────
let _driver: Driver | null = null;

function getDriver(): Driver {
  if (_driver) return _driver;

  const uri = process.env.NEO4J_URI || "bolt://localhost:7687";
  const user = process.env.NEO4J_USER || "neo4j";
  const password = process.env.NEO4J_PASSWORD || "changeme123";

  _driver = neo4j.driver(uri, neo4j.auth.basic(user, password), {
    maxConnectionPoolSize: 10,
    connectionAcquisitionTimeout: 10000,
    connectionTimeout: 5000,
  });

  return _driver;
}

export function closeDriver(): void {
  if (_driver) {
    _driver.close().catch(() => {});
    _driver = null;
  }
}

// ─── Query helper ──────────────────────────────────────────────────────────
async function runQuery<T>(
  cypher: string,
  params: Record<string, unknown> = {}
): Promise<T[]> {
  const driver = getDriver();
  const session: Session = driver.session({ database: "neo4j" });
  try {
    const result = await session.run(cypher, params);
    return result.records.map((r: Neo4jRecord) => r.toObject() as T);
  } finally {
    await session.close();
  }
}

// ─── Safe integer extraction from Neo4j Integer type ───────────────────────
function safeInt(value: unknown): number {
  if (value === null || value === undefined) return 0;
  if (typeof value === "number") return value;
  // neo4j-driver Integer type has .toNumber()
  if (typeof value === "object" && value !== null && "toNumber" in value) {
    return (value as { toNumber: () => number }).toNumber();
  }
  return Number(value) || 0;
}

// ─── Fetch full knowledge graph for a job ──────────────────────────────────
export async function fetchGraphForJob(jobId: string): Promise<GraphData> {
  const nodeMap = new Map<string, GraphNode>();
  const links: GraphLink[] = [];

  // 1) Fetch all Hosts for this job
  const hosts = await runQuery<{
    ip: string;
    hostname: string | null;
    os: string | null;
  }>(
    `MATCH (h:Host {job_id: $jobId})
     RETURN h.ip AS ip, h.hostname AS hostname, h.os AS os`,
    { jobId }
  );

  for (const h of hosts) {
    const id = `host-${h.ip}`;
    nodeMap.set(id, {
      id,
      label: h.hostname || h.ip,
      type: "Target" as GraphNodeType,
      color: NODE_COLORS.Target,
      size: NODE_SIZES.Target,
      description: h.os ? `OS: ${h.os}` : undefined,
      metadata: { ip: h.ip, hostname: h.hostname, os: h.os },
    });
  }

  // 2) Fetch all Services and link to Hosts
  const services = await runQuery<{
    host_ip: string;
    port: unknown;
    protocol: string | null;
    name: string | null;
    version: string | null;
    banner: string | null;
  }>(
    `MATCH (h:Host {job_id: $jobId})-[:RUNS]->(s:Service)
     RETURN s.host_ip AS host_ip, s.port AS port, s.protocol AS protocol,
            s.name AS name, s.version AS version, s.banner AS banner`,
    { jobId }
  );

  for (const s of services) {
    const port = safeInt(s.port);
    const id = `service-${s.host_ip}-${port}`;
    const hostId = `host-${s.host_ip}`;
    const svcName = s.name || `port-${port}`;

    nodeMap.set(id, {
      id,
      label: `${svcName}:${port}`,
      type: "Service" as GraphNodeType,
      color: NODE_COLORS.Service,
      size: NODE_SIZES.Service,
      port,
      protocol: s.protocol || "tcp",
      version: s.version || undefined,
      description: s.banner || undefined,
      metadata: { host_ip: s.host_ip, port, protocol: s.protocol, version: s.version },
    });

    if (nodeMap.has(hostId)) {
      links.push({ source: hostId, target: id, type: "RUNS", label: "runs" });
    }
  }

  // 3) Fetch all Vulnerabilities and link to Services
  const vulns = await runQuery<{
    id: string;
    type: string;
    cve: string | null;
    severity: string | null;
    details: string | null;
    host_ip: string;
    port: unknown;
    verified: boolean | null;
  }>(
    `MATCH (v:Vulnerability {job_id: $jobId})
     RETURN v.id AS id, v.type AS type, v.cve AS cve, v.severity AS severity,
            v.details AS details, v.host_ip AS host_ip, v.port AS port,
            v.verified AS verified`,
    { jobId }
  );

  for (const v of vulns) {
    const port = safeInt(v.port);
    const serviceId = `service-${v.host_ip}-${port}`;

    nodeMap.set(v.id, {
      id: v.id,
      label: v.cve || v.type,
      type: v.cve ? ("CVE" as GraphNodeType) : ("Vulnerability" as GraphNodeType),
      color: v.cve ? NODE_COLORS.CVE : NODE_COLORS.Vulnerability,
      size: v.cve ? NODE_SIZES.CVE : NODE_SIZES.Vulnerability,
      severity: v.severity || undefined,
      cve_id: v.cve || undefined,
      description: v.details || undefined,
      metadata: { host_ip: v.host_ip, port, verified: v.verified },
    });

    if (nodeMap.has(serviceId)) {
      links.push({ source: serviceId, target: v.id, type: "HAS_VULN", label: "has vuln" });
    }
  }

  // 4) Fetch all Credentials and link to Services
  const creds = await runQuery<{
    id: string;
    username: string;
    password: string | null;
    hash: string | null;
    source: string | null;
    host_ip: string | null;
    port: unknown;
  }>(
    `MATCH (c:Credential {job_id: $jobId})
     OPTIONAL MATCH (c)-[:WORKS_ON]->(s:Service)
     RETURN c.id AS id, c.username AS username, c.password AS password,
            c.hash AS hash, c.source AS source,
            s.host_ip AS host_ip, s.port AS port`,
    { jobId }
  );

  for (const c of creds) {
    nodeMap.set(c.id, {
      id: c.id,
      label: c.username,
      type: "Credential" as GraphNodeType,
      color: NODE_COLORS.Credential,
      size: NODE_SIZES.Credential,
      username: c.username,
      source: c.source || undefined,
      description: c.source ? `Source: ${c.source}` : undefined,
      metadata: { username: c.username, has_password: !!c.password, has_hash: !!c.hash },
    });

    if (c.host_ip && c.port) {
      const port = safeInt(c.port);
      const serviceId = `service-${c.host_ip}-${port}`;
      if (nodeMap.has(serviceId)) {
        links.push({ source: c.id, target: serviceId, type: "WORKS_ON", label: "works on" });
      }
    }
  }

  // 5) Fetch all ExploitAttempts and link to Vulnerabilities
  const attempts = await runQuery<{
    id: string;
    tool: string;
    success: boolean;
    cve: string | null;
    host_ip: string;
    port: unknown;
    evidence: string | null;
    command: string | null;
  }>(
    `MATCH (a:ExploitAttempt {job_id: $jobId})
     RETURN a.id AS id, a.tool AS tool, a.success AS success, a.cve AS cve,
            a.host_ip AS host_ip, a.port AS port, a.evidence AS evidence,
            a.command AS command`,
    { jobId }
  );

  for (const a of attempts) {
    nodeMap.set(a.id, {
      id: a.id,
      label: `${a.tool}${a.success ? " ✓" : " ✗"}`,
      type: "Exploit" as GraphNodeType,
      color: a.success ? NODE_COLORS.Exploit : "#666666",
      size: NODE_SIZES.Exploit,
      description: a.command ? `$ ${a.command.slice(0, 200)}` : undefined,
      metadata: {
        tool: a.tool,
        success: a.success,
        cve: a.cve,
        host_ip: a.host_ip,
        port: safeInt(a.port),
        evidence: a.evidence?.slice(0, 500),
      },
    });
  }

  // 6) Fetch EXPLOITED_BY relationships
  const exploitEdges = await runQuery<{ vuln_id: string; attempt_id: string }>(
    `MATCH (v:Vulnerability {job_id: $jobId})-[:EXPLOITED_BY]->(a:ExploitAttempt)
     RETURN v.id AS vuln_id, a.id AS attempt_id`,
    { jobId }
  );

  for (const e of exploitEdges) {
    if (nodeMap.has(e.vuln_id) && nodeMap.has(e.attempt_id)) {
      links.push({ source: e.vuln_id, target: e.attempt_id, type: "EXPLOITED_BY", label: "exploited by" });
    }
  }

  return {
    nodes: Array.from(nodeMap.values()),
    links,
  };
}

// ─── Check Neo4j connectivity ──────────────────────────────────────────────
export async function checkNeo4jHealth(): Promise<boolean> {
  try {
    const driver = getDriver();
    await driver.verifyConnectivity();
    return true;
  } catch {
    return false;
  }
}
