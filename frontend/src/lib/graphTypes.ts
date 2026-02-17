/**
 * TazoSploit Attack Graph — Shared Types
 *
 * Defines the node/edge schema, color palette, and API response shapes
 * used by the interactive force-graph visualization.
 */

// ─── Node type enumeration ─────────────────────────────────────────────────
export type GraphNodeType =
  | "Target"
  | "Service"
  | "Port"
  | "Vulnerability"
  | "CVE"
  | "Exploit"
  | "Credential"
  | "Endpoint"
  | "Technology"
  | "MitreTechnique";

// ─── Color palette keyed by node type ──────────────────────────────────────
export const NODE_COLORS: Record<GraphNodeType, string> = {
  Target: "#ff4444",
  Service: "#4488ff",
  Port: "#44aaff",
  Vulnerability: "#ff8844",
  CVE: "#ffaa44",
  Exploit: "#44ff44",
  Credential: "#ffff44",
  Endpoint: "#8844ff",
  Technology: "#ff44ff",
  MitreTechnique: "#44ffff",
};

// ─── Node sizing by type (visual radius multiplier) ────────────────────────
export const NODE_SIZES: Record<GraphNodeType, number> = {
  Target: 12,
  Service: 8,
  Port: 5,
  Vulnerability: 9,
  CVE: 7,
  Exploit: 10,
  Credential: 8,
  Endpoint: 4,
  Technology: 6,
  MitreTechnique: 7,
};

// ─── Node labels for legend ────────────────────────────────────────────────
export const NODE_LABELS: Record<GraphNodeType, string> = {
  Target: "Target",
  Service: "Service",
  Port: "Port",
  Vulnerability: "Vulnerability",
  CVE: "CVE",
  Exploit: "Exploit",
  Credential: "Credential",
  Endpoint: "Endpoint",
  Technology: "Technology",
  MitreTechnique: "MITRE Technique",
};

// ─── Graph node (for force-graph) ──────────────────────────────────────────
export interface GraphNode {
  id: string;
  label: string;
  type: GraphNodeType;
  color: string;
  size: number;
  // Extended properties
  description?: string;
  risk_score?: number;
  severity?: string;
  cve_id?: string;
  cwe_id?: string;
  confidence?: number;
  detected_by?: string;
  version?: string;
  port?: number;
  protocol?: string;
  username?: string;
  service?: string;
  source?: string;
  mitre_techniques?: string[];
  metadata?: Record<string, unknown>;
  created_at?: string;
  updated_at?: string;
  // Force-graph internal (set at runtime)
  x?: number;
  y?: number;
  z?: number;
  fx?: number | null;
  fy?: number | null;
  fz?: number | null;
  __threeObj?: unknown;
}

// ─── Graph link (for force-graph) ──────────────────────────────────────────
export interface GraphLink {
  source: string | GraphNode;
  target: string | GraphNode;
  type: string;
  label?: string;
  metadata?: Record<string, unknown>;
}

// ─── Complete graph data ───────────────────────────────────────────────────
export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

// ─── API response from /api/v1/attack-graphs/jobs/{jobId} ─────────────────
export interface AttackGraphApiNode {
  id: string;
  type: string;
  name: string;
  description?: string;
  risk_score: number;
  mitre_techniques: string[];
  metadata: Record<string, unknown>;
}

export interface AttackGraphApiEdge {
  id: string;
  source: string;
  target: string;
  type: string;
  technique_id?: string;
  difficulty: string;
  impact: string;
  metadata: Record<string, unknown>;
}

export interface AttackGraphApiResponse {
  job_id: string;
  nodes: AttackGraphApiNode[];
  edges: AttackGraphApiEdge[];
  paths?: Array<{
    id?: string;
    name: string;
    path_nodes: string[];
    risk_score: number;
    length: number;
    is_critical: boolean;
    start_node: string;
    end_node: string;
  }>;
  node_count: number;
  edge_count: number;
  recommendations?: string[];
}

// ─── Neo4j knowledge-graph API response ────────────────────────────────────
export interface Neo4jGraphResponse {
  nodes: GraphNode[];
  links: GraphLink[];
  source: "neo4j";
  timestamp: string;
}

// ─── Helper: map API node type to our GraphNodeType ────────────────────────
export function mapNodeType(apiType: string): GraphNodeType {
  const typeMap: Record<string, GraphNodeType> = {
    // From attack-graph API
    host: "Target",
    service: "Service",
    vulnerability: "Vulnerability",
    exploit: "Exploit",
    // From Neo4j knowledge graph
    Host: "Target",
    Service: "Service",
    Vulnerability: "Vulnerability",
    Credential: "Credential",
    ExploitAttempt: "Exploit",
    // Generic mappings
    port: "Port",
    Port: "Port",
    cve: "CVE",
    CVE: "CVE",
    credential: "Credential",
    endpoint: "Endpoint",
    Endpoint: "Endpoint",
    technology: "Technology",
    Technology: "Technology",
    mitre: "MitreTechnique",
    MitreTechnique: "MitreTechnique",
    technique: "MitreTechnique",
  };
  return typeMap[apiType] || "Target";
}

// ─── Helper: convert AttackGraphApi response to GraphData ──────────────────
export function apiResponseToGraphData(resp: AttackGraphApiResponse): GraphData {
  const nodes: GraphNode[] = resp.nodes.map((n) => {
    const nodeType = mapNodeType(n.type);
    return {
      id: n.id,
      label: n.name,
      type: nodeType,
      color: NODE_COLORS[nodeType],
      size: NODE_SIZES[nodeType],
      description: n.description,
      risk_score: n.risk_score,
      mitre_techniques: n.mitre_techniques,
      metadata: n.metadata,
    };
  });

  const nodeIds = new Set(nodes.map((n) => n.id));

  const links: GraphLink[] = resp.edges
    .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
    .map((e) => ({
      source: e.source,
      target: e.target,
      type: e.type,
      label: e.type.replace(/_/g, " "),
      metadata: { ...e.metadata, difficulty: e.difficulty, impact: e.impact },
    }));

  return { nodes, links };
}
