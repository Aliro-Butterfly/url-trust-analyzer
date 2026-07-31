import type { AnalysisResponse } from "../types";

export function formatDetail(value: unknown): string {
  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(", ") : "(empty)";
  }
  if (value === null || value === undefined) {
    return "(none)";
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

export function scoreClass(score: number): string {
  if (score >= 70) return "score-green";
  if (score >= 40) return "score-yellow";
  return "score-red";
}

export function hasData(status: string): boolean {
  return status === "success";
}

export function downloadBlob(content: string, mimeType: string, filename: string): void {
  const blob = new Blob([content], { type: mimeType });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
}

export function buildReportLines(analysis: AnalysisResponse): string[] {
  return [
    `URL: ${analysis.url}`,
    `Overall score: ${analysis.overall_score} / 100`,
    `Confidence: ${analysis.confidence}%`,
    "",
    "Reasons:",
    ...analysis.reasons.map((r) => `- ${r}`),
    "",
    "Score breakdown:",
    ...Object.entries(analysis.score_breakdown).map(([d, v]) => `- ${d}: ${v}`),
    "",
    "Providers:",
    ...analysis.results.flatMap((item) => [
      `=== ${item.provider} ===`,
      `Status: ${item.status}`,
      `Summary: ${item.summary}`,
      `Score: ${hasData(item.status) ? item.score : "N/A"}`,
      `Confidence: ${hasData(item.status) ? `${item.confidence}%` : "N/A"}`,
      ...(Object.keys(item.details).length > 0
        ? Object.entries(item.details).map(([k, v]) => `  ${k}: ${formatDetail(v)}`)
        : ["  No additional data."]),
      "",
    ]),
  ];
}
