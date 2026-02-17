/**
 * TazoSploit Attack Graph — Client-side API
 *
 * Fetches graph data and supports real-time polling for live updates.
 */

import { GraphData, GraphNode, GraphLink } from "./graphTypes";
import { getToken } from "./api";

export interface GraphApiResponse extends GraphData {
  source: "neo4j" | "api" | "empty";
  timestamp: string;
  paths?: unknown[];
  recommendations?: string[];
}

/**
 * Fetch the attack graph for a job.
 * Routes through the Next.js API route which queries Neo4j → fallback to backend API.
 */
export async function fetchAttackGraph(
  jobId: string,
  source: "auto" | "neo4j" | "api" = "auto"
): Promise<GraphApiResponse> {
  const token = getToken();
  const params = new URLSearchParams();
  if (source !== "auto") params.set("source", source);

  const res = await fetch(`/api/graph/${jobId}?${params.toString()}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!res.ok) {
    throw new Error(`Graph API error: ${res.status}`);
  }

  return res.json();
}

/**
 * Merge new graph data into existing data, preserving positions of existing nodes.
 * Returns a new GraphData object if anything changed, or null if no changes.
 */
export function mergeGraphData(
  existing: GraphData,
  incoming: GraphData
): { data: GraphData; newNodeIds: string[]; newLinkKeys: string[] } | null {
  const existingNodeMap = new Map(existing.nodes.map((n) => [n.id, n]));
  const existingLinkSet = new Set(
    existing.links.map((l) => {
      const src = typeof l.source === "string" ? l.source : l.source.id;
      const tgt = typeof l.target === "string" ? l.target : l.target.id;
      return `${src}→${tgt}→${l.type}`;
    })
  );

  const newNodeIds: string[] = [];
  const newLinkKeys: string[] = [];
  let changed = false;

  // Merge nodes
  const mergedNodes: GraphNode[] = [...existing.nodes];
  for (const node of incoming.nodes) {
    if (!existingNodeMap.has(node.id)) {
      mergedNodes.push(node);
      newNodeIds.push(node.id);
      changed = true;
    } else {
      // Update existing node properties (but keep position)
      const existingNode = existingNodeMap.get(node.id)!;
      const updated = {
        ...existingNode,
        label: node.label,
        description: node.description,
        risk_score: node.risk_score,
        metadata: node.metadata,
      };
      const idx = mergedNodes.findIndex((n) => n.id === node.id);
      if (idx >= 0) mergedNodes[idx] = updated;
    }
  }

  // Merge links
  const mergedLinks: GraphLink[] = [...existing.links];
  for (const link of incoming.links) {
    const src = typeof link.source === "string" ? link.source : link.source.id;
    const tgt = typeof link.target === "string" ? link.target : link.target.id;
    const key = `${src}→${tgt}→${link.type}`;
    if (!existingLinkSet.has(key)) {
      mergedLinks.push(link);
      newLinkKeys.push(key);
      changed = true;
    }
  }

  if (!changed && newNodeIds.length === 0) return null;

  return {
    data: { nodes: mergedNodes, links: mergedLinks },
    newNodeIds,
    newLinkKeys,
  };
}
