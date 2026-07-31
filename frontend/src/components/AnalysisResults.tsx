import { useState } from "react";
import type { AnalysisResponse } from "../types";
import { buildReportLines, downloadBlob, formatDetail, hasData, scoreClass } from "../utils/format";

interface Props {
  analysis: AnalysisResponse;
}

export function AnalysisResults({ analysis }: Props) {
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");
  const safeName = analysis.url.replace(/[^a-z0-9]/gi, "_").slice(0, 40);

  const downloadReport = () => {
    downloadBlob(buildReportLines(analysis).join("\n"), "text/plain;charset=utf-8", `${safeName}_report.txt`);
  };

  const downloadCSV = () => {
    const headers = ["Provider", "Status", "Score", "Confidence", "Summary"];
    const rows = analysis.results.map((r) =>
      [
        r.provider,
        r.status,
        hasData(r.status) ? String(r.score) : "N/A",
        hasData(r.status) ? `${r.confidence}%` : "N/A",
        r.summary,
      ]
        .map((c) => `"${c.replace(/"/g, '""')}"`)
        .join(",")
    );
    const csv = "\uFEFF" + [headers.join(","), ...rows].join("\n");
    downloadBlob(csv, "text/csv;charset=utf-8", `${safeName}_report.csv`);
  };

  return (
    <>
      <div className="button-row">
        <button
          type="button"
          onClick={() => setViewMode(viewMode === "cards" ? "table" : "cards")}
          className="secondary-button"
        >
          {viewMode === "cards" ? "Table View" : "Card View"}
        </button>
        <button type="button" onClick={downloadReport} className="secondary-button">
          .TXT Report
        </button>
        <button type="button" onClick={downloadCSV} className="secondary-button">
          .CSV Export
        </button>
      </div>

      <div className="result-header">
        <div>
          <p>Analyzed URL</p>
          <strong>{analysis.url}</strong>
        </div>
        <div>
          <p>Overall score</p>
          <strong>{analysis.overall_score} / 100</strong>
        </div>
        <div>
          <p>Confidence</p>
          <strong>{analysis.confidence}%</strong>
        </div>
      </div>

      <div className="analysis-reasons">
        <h2>Why?</h2>
        <ul>
          {analysis.reasons.map((reason) => (
            <li key={reason}>{reason}</li>
          ))}
        </ul>
      </div>

      <div className="breakdown-card">
        <h2>Score Breakdown</h2>
        <div className="breakdown-list">
          {Object.entries(analysis.score_breakdown).map(([dimension, value]) => (
            <div key={dimension} className="breakdown-item">
              <span>{dimension}</span>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      </div>

      {viewMode === "table" ? (
        <div className="comparison-table-wrapper">
          <table className="comparison-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>Status</th>
                <th>Score</th>
                <th>Confidence</th>
                <th>Summary</th>
              </tr>
            </thead>
            <tbody>
              {analysis.results.map((item) => {
                const available = hasData(item.status);
                return (
                  <tr key={item.provider} className={!available ? "row-error" : ""}>
                    <td>
                      <strong>{item.provider}</strong>
                    </td>
                    <td>
                      <span className={`provider-status provider-status--${item.status}`}>{item.status}</span>
                    </td>
                    <td>
                      {available ? (
                        <span className={`score-badge ${scoreClass(item.score)}`}>{item.score}</span>
                      ) : (
                        <span className="score-na">N/A</span>
                      )}
                    </td>
                    <td>{available ? `${item.confidence}%` : "N/A"}</td>
                    <td className="summary-cell">{item.summary}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="provider-list">
          {analysis.results.map((item) => {
            const available = hasData(item.status);
            return (
              <article
                key={item.provider}
                className={`provider-card ${!available ? "provider-card--error" : ""}`}
              >
                <div className="provider-card-header">
                  <h2>{item.provider}</h2>
                  <span className={`provider-status provider-status--${item.status}`}>{item.status}</span>
                </div>
                <p className="provider-summary">{item.summary}</p>
                <div className="provider-metrics">
                  <span>
                    Score:{" "}
                    {available ? (
                      <strong className={scoreClass(item.score)}>{item.score}</strong>
                    ) : (
                      <strong className="score-na">N/A</strong>
                    )}
                  </span>
                  <span>Confidence: {available ? `${item.confidence}%` : "N/A"}</span>
                </div>
                {Object.keys(item.details).length > 0 && (
                  <div className="provider-details">
                    {Object.entries(item.details).map(([key, value]) => (
                      <div key={key} className="detail-row">
                        <span className="detail-key">{key.replace(/_/g, " ")}</span>
                        <span className="detail-value">{formatDetail(value)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </article>
            );
          })}
        </div>
      )}
    </>
  );
}
