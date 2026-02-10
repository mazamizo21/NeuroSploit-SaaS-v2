export type ReportArtifacts = {
  ok?: boolean;
  report_md?: boolean;
  report_json?: boolean;
};

export type ReportArtifactsWarning = {
  show: boolean;
  missing: string[];
};

export function getReportArtifactsWarning(
  phase: string,
  status: string,
  reportArtifacts?: ReportArtifacts | null
): ReportArtifactsWarning {
  if (!reportArtifacts || typeof reportArtifacts !== "object") {
    return { show: false, missing: [] };
  }

  const reportMd = reportArtifacts.report_md;
  const reportJson = reportArtifacts.report_json;
  const explicitFailure = reportArtifacts.ok === false || reportMd === false || reportJson === false;
  const show = phase === "REPORT" && status === "completed" && explicitFailure;

  if (!show) {
    return { show: false, missing: [] };
  }

  const missing: string[] = [];
  if (reportMd === false) missing.push("report.md");
  if (reportJson === false) missing.push("report.json");
  if (show && missing.length === 0) missing.push("report.md", "report.json");

  return { show, missing };
}
