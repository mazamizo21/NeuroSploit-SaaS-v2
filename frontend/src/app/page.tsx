"use client";
import { useEffect, useState } from "react";
import AppShell from "./AppShell";
import { api } from "@/lib/api";
import { Card, StatCard, Badge } from "@/components/Card";
import MitreHeatmap from "@/components/MitreHeatmap";
import { statusColor, formatDate } from "@/lib/utils";
import {
  Crosshair,
  AlertTriangle,
  Activity,
  Shield,
  Target,
  Zap,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import Link from "next/link";
import { LiveLogViewer } from "@/components/LiveLogViewer";

const SEV_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#eab308",
  low: "#3b82f6",
  info: "#6b7280",
};

export default function Dashboard() {
  return (
    <AppShell>
      <DashboardInner />
    </AppShell>
  );
}

function DashboardInner() {
  const [jobs, setJobs] = useState<any>({ jobs: [], total: 0 });
  const [stats, setStats] = useState<any>(null);
  const [sevDist, setSevDist] = useState<any>(null);
  const [activity, setActivity] = useState<any[]>([]);
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    let cancelled = false;
    const safe =
      <T,>(setter: (v: T) => void) =>
      (v: T) => {
        if (!cancelled) setter(v);
      };

    const load = () => {
      api.get("/api/v1/jobs?page_size=5").then(safe(setJobs)).catch(() => { });
      api.get("/api/v1/dashboard/stats").then(safe(setStats)).catch(() => { });
      api.get("/api/v1/dashboard/severity-distribution").then(safe(setSevDist)).catch(() => { });
      api.get("/api/v1/dashboard/activity?limit=10").then(safe(setActivity)).catch(() => { });
      api.get("/health").then(safe(setHealth)).catch(() => { });
    };

    load();
    const interval = window.setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const pieData = sevDist
    ? Object.entries(sevDist)
      .filter(([, v]) => (v as number) > 0)
      .map(([k, v]) => ({ name: k, value: v as number, color: SEV_COLORS[k] || "#6b7280" }))
    : [];

  return (
    <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-2xl font-bold">Dashboard</h1>
          {health && (
            <Badge className="bg-green-500/20 text-green-400">
              <Activity className="w-3 h-3 mr-1" /> API {health.status}
            </Badge>
          )}
        </div>

        {/* 💻 Row 0: Live Hacker Console */}
        <div className="h-64 md:h-80 w-full">
          <LiveLogViewer />
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <StatCard
            label="Total Pentests"
            value={stats?.total_pentests ?? jobs.total ?? 0}
            icon={<Shield className="w-5 h-5" />}
            color="text-indigo-400"
          />
          <StatCard
            label="Active Scans"
            value={stats?.active_scans ?? 0}
            icon={<Crosshair className="w-5 h-5" />}
            color="text-green-400"
          />
          <StatCard
            label="Total Findings"
            value={stats?.total_findings ?? 0}
            icon={<AlertTriangle className="w-5 h-5" />}
            color="text-yellow-400"
          />
          <StatCard
            label="Critical Findings"
            value={stats?.critical_findings ?? 0}
            icon={<Zap className="w-5 h-5" />}
            color="text-red-400"
          />
        </div>

        {/* Row 2: MITRE Heatmap + Severity Pie */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="lg:col-span-2">
            <h3 className="text-sm font-medium text-[var(--text-dim)] mb-4 flex items-center gap-2">
              <Target className="w-4 h-4" /> MITRE ATT&CK Heatmap
            </h3>
            <MitreHeatmap />
          </Card>

          <Card>
            <h3 className="text-sm font-medium text-[var(--text-dim)] mb-4">
              Finding Severity
            </h3>
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "#1a1a2e",
                      border: "1px solid #2a2a3e",
                      borderRadius: 8,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-sm text-[var(--text-dim)] text-center py-10">No findings yet</p>
            )}
            {pieData.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-2 justify-center">
                {pieData.map((d) => (
                  <span key={d.name} className="flex items-center gap-1 text-xs">
                    <span className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                    {d.name}: {d.value}
                  </span>
                ))}
              </div>
            )}
          </Card>
        </div>

        {/* Row 3: Recent Jobs + Activity Feed */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Recent Jobs */}
          <Card>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-medium text-[var(--text-dim)]">
                Recent Pentests
              </h3>
              <Link href="/pentests" className="text-xs text-indigo-400 hover:underline">
                View All →
              </Link>
            </div>
            {jobs.jobs?.length === 0 ? (
              <p className="text-sm text-[var(--text-dim)]">No jobs yet. Create one!</p>
            ) : (
              <div className="space-y-2">
                {jobs.jobs?.slice(0, 5).map((j: any) => (
                  <Link
                    key={j.id}
                    href={`/pentests/${j.id}`}
                    className="flex items-center justify-between p-3 rounded-lg bg-[var(--surface2)] hover:bg-white/5 transition"
                  >
                    <div>
                      <p className="text-sm font-medium">{j.name}</p>
                      <p className="text-xs text-[var(--text-dim)]">
                        {j.phase} &middot; {formatDate(j.created_at)}
                      </p>
                    </div>
                    <div className="text-right">
                      <span className={`text-sm font-medium ${statusColor(j.status)}`}>
                        {j.status}
                      </span>
                      <p className="text-xs text-[var(--text-dim)]">
                        {j.findings_count} findings
                      </p>
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </Card>

          {/* Activity Feed */}
          <Card>
            <h3 className="text-sm font-medium text-[var(--text-dim)] mb-4">
              Recent Activity
            </h3>
            {activity.length === 0 ? (
              <p className="text-sm text-[var(--text-dim)]">No recent activity</p>
            ) : (
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {activity.map((a: any) => (
                  <div
                    key={a.id}
                    className="flex items-start gap-3 p-2 rounded-lg hover:bg-white/5"
                  >
                    <div className="flex-1 min-w-0">
                      <p className="text-sm truncate">{a.title}</p>
                      <p className="text-xs text-[var(--text-dim)] truncate">{a.detail}</p>
                    </div>
                    <div className="text-right flex-shrink-0">
                      {a.severity && (
                        <span
                          className="text-[9px] uppercase font-bold px-1.5 py-0.5 rounded"
                          style={{
                            background: `${SEV_COLORS[a.severity] || "#6b7280"}33`,
                            color: SEV_COLORS[a.severity] || "#6b7280",
                          }}
                        >
                          {a.severity}
                        </span>
                      )}
                      <p className="text-[10px] text-[var(--text-dim)] mt-0.5">
                        {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : ""}
                      </p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>

    </div>
  );
}
