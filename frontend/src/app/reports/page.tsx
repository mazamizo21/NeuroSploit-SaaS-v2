"use client";
import { useEffect, useState } from "react";
import AppShell from "../AppShell";
import { api } from "@/lib/api";
import { Card } from "@/components/Card";
import { FileText, Download, Loader2 } from "lucide-react";
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
  const [downloading, setDownloading] = useState<Record<string, boolean>>({});
  const [error, setError] = useState("");

  useEffect(() => {
    api.get("/api/v1/jobs?page_size=50").then((d) => {
      setJobs((d.jobs || []).filter((j: any) => j.status === "completed"));
    }).catch(() => {});
  }, []);

  async function download(job: any) {
    if (!job?.id) return;
    setError("");
    setDownloading((prev) => ({ ...prev, [job.id]: true }));
    try {
      const blob = await api.getBlob(`/api/v1/dashboard/jobs/${job.id}/report?format=pdf`);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `TazoSploit_Report_${String(job.name || "Report").replace(/\\s+/g, "_")}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: any) {
      setError(e?.message || "Failed to download report");
    } finally {
      setDownloading((prev) => ({ ...prev, [job.id]: false }));
    }
  }

  return (
    <div className="space-y-6">
        <h1 className="text-2xl font-bold">Reports</h1>
        {error && <p className="text-sm text-red-400">{error}</p>}

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
	                <button
                    type="button"
                    onClick={() => download(j)}
                    disabled={!!downloading[j.id]}
                    className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600/20 text-indigo-400 hover:bg-indigo-600/30 transition text-sm disabled:opacity-50"
                  >
                    {downloading[j.id] ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Download className="w-4 h-4" />
                    )}{" "}
                    {downloading[j.id] ? "Downloading..." : "Download"}
	                </button>
	              </Card>
	            ))}
	          </div>
	        )}
    </div>
  );
}
