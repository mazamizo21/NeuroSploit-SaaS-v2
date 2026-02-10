import { describe, it, expect } from "vitest";
import { getReportArtifactsWarning } from "../src/lib/reportArtifacts";

describe("getReportArtifactsWarning", () => {
  it("does not warn when phase is not REPORT", () => {
    const result = getReportArtifactsWarning("RECON", "completed", { ok: false, report_md: false, report_json: false });
    expect(result.show).toBe(false);
    expect(result.missing.length).toBe(0);
  });

  it("does not warn when status is not completed", () => {
    const result = getReportArtifactsWarning("REPORT", "running", { ok: false, report_md: false, report_json: false });
    expect(result.show).toBe(false);
  });

  it("does not warn when artifacts are absent", () => {
    const result = getReportArtifactsWarning("REPORT", "completed", null);
    expect(result.show).toBe(false);
  });

  it("warns and lists missing report.md", () => {
    const result = getReportArtifactsWarning("REPORT", "completed", { ok: false, report_md: false, report_json: true });
    expect(result.show).toBe(true);
    expect(result.missing).toEqual(["report.md"]);
  });

  it("warns and lists missing report.json", () => {
    const result = getReportArtifactsWarning("REPORT", "completed", { ok: false, report_md: true, report_json: false });
    expect(result.show).toBe(true);
    expect(result.missing).toEqual(["report.json"]);
  });

  it("warns and lists both when ok is false but parts unspecified", () => {
    const result = getReportArtifactsWarning("REPORT", "completed", { ok: false });
    expect(result.show).toBe(true);
    expect(result.missing).toEqual(["report.md", "report.json"]);
  });
});
