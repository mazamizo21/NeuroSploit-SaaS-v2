/**
 * TazoSploit Attack Graph — Next.js API Route
 *
 * GET /api/graph/{jobId}
 *
 * Fetches the attack graph from Neo4j knowledge graph for a given job.
 * Falls back to the backend AttackGraph API if Neo4j is unavailable.
 *
 * Query params:
 *   ?source=neo4j|api  — force a specific data source (default: auto)
 */

import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(
  request: NextRequest,
  { params }: { params: { jobId: string } }
) {
  const { jobId } = params;
  const source = request.nextUrl.searchParams.get("source") || "auto";

  if (!jobId) {
    return NextResponse.json({ error: "Missing jobId" }, { status: 400 });
  }

  // Try Neo4j first (has richer real-time data from the Kali knowledge graph)
  if (source === "neo4j" || source === "auto") {
    try {
      const { fetchGraphForJob } = await import("@/lib/neo4j");
      const graph = await fetchGraphForJob(jobId);

      if (graph.nodes.length > 0) {
        return NextResponse.json({
          ...graph,
          source: "neo4j",
          timestamp: new Date().toISOString(),
        });
      }
    } catch (err) {
      console.warn("[graph-api] Neo4j query failed, falling back to API:", err);
    }
  }

  // Fall back to backend AttackGraph API
  if (source === "api" || source === "auto") {
    try {
      const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";
      // Forward authorization header from the client
      const authHeader = request.headers.get("authorization") || "";

      const resp = await fetch(
        `${backendUrl}/api/v1/attack-graphs/jobs/${jobId}`,
        {
          headers: {
            "Content-Type": "application/json",
            ...(authHeader ? { Authorization: authHeader } : {}),
          },
          // 10s timeout
          signal: AbortSignal.timeout(10000),
        }
      );

      if (resp.ok) {
        const data = await resp.json();
        // Convert backend format to force-graph format
        const { apiResponseToGraphData } = await import("@/lib/graphTypes");
        const graphData = apiResponseToGraphData(data);

        return NextResponse.json({
          ...graphData,
          paths: data.paths || [],
          recommendations: data.recommendations || [],
          source: "api",
          timestamp: new Date().toISOString(),
        });
      }

      // If 404, the graph hasn't been built yet — try building it
      if (resp.status === 404 || (await resp.json().catch(() => ({})))?.detail?.includes("not found")) {
        const buildResp = await fetch(
          `${backendUrl}/api/v1/attack-graphs/jobs/${jobId}/build`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              ...(authHeader ? { Authorization: authHeader } : {}),
            },
            signal: AbortSignal.timeout(15000),
          }
        );

        if (buildResp.ok) {
          const data = await buildResp.json();
          const { apiResponseToGraphData } = await import("@/lib/graphTypes");
          const graphData = apiResponseToGraphData(data);

          return NextResponse.json({
            ...graphData,
            source: "api",
            timestamp: new Date().toISOString(),
          });
        }
      }
    } catch (err) {
      console.warn("[graph-api] Backend API failed:", err);
    }
  }

  // Return empty graph
  return NextResponse.json({
    nodes: [],
    links: [],
    source: "empty",
    timestamp: new Date().toISOString(),
  });
}
