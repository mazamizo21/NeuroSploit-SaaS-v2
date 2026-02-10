"use client";
import { useEffect, useState } from "react";
import AppShell from "../AppShell";
import { api } from "@/lib/api";
import { Card } from "@/components/Card";
import { FileText, Download } from "lucide-react";
import { formatDate } from "@/lib/utils";

export default function ReportsPage() {
  return (
    <AppShell>
      <ReportsInner />
    </AppShell>
  );
}

function ReportsInner() {
  const [jobs, setJobs] = useState<any[]>([]);

  useEffect(() => {
    api.get("/api/v1/jobs?page_size=50").then((d) => {
      setJobs((d.jobs || []).filter((j: any) => j.status === "completed"));
    }).catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
        <h1 className="text-2xl font-bold">Reports</h1>

        {jobs.length === 0 ? (
          <Card className="text-center py-12">
            <FileText className="w-12 h-12 mx-auto mb-4 text-[var(--text-dim)]" />
            <p className="text-lg">No completed pentests</p>
            <p className="text-sm text-[var(--text-dim)]">Reports are generated when pentests complete</p>
          </Card>
        ) : (
          <div className="space-y-3">
            {jobs.map((j) => (
              <Card key={j.id} className="flex items-center justify-between">
                <div>
                  <h3 className="font-medium">{j.name}</h3>
                  <p className="text-sm text-[var(--text-dim)]">
                    {j.findings_count} findings &middot; Completed {formatDate(j.completed_at)}
                  </p>
                </div>
                <button className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600/20 text-indigo-400 hover:bg-indigo-600/30 transition text-sm">
                  <Download className="w-4 h-4" /> Download
                </button>
              </Card>
            ))}
          </div>
        )}
    </div>
  );
}
