import { useState } from "react";
import type { AnalysisResponse } from "../types";
import {
  getConsensusSummary,
  getRiskExplanation,
  getRiskLabel,
  listContradictions,
} from "../utils/analysis";
import { buildReportLines, downloadBlob, formatDetail, hasData, scoreClass } from "../utils/format";

interface Props {
  analysis: AnalysisResponse;
}

export function AnalysisResults({ analysis }: Props) {
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");
  const [expertMode, setExpertMode] = useState(false);
  const safeName = analysis.url.replace(/[^a-z0-9]/gi, "_").slice(0, 40);
  const consensus = getConsensusSummary(analysis);
  const contradictions = listContradictions(analysis);
  const riskLabel = getRiskLabel(analysis.overall_score);
  const riskExplanation = getRiskExplanation(analysis.overall_score);

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
        <button
          type="button"
          onClick={() => setExpertMode((previous) => !previous)}
          className="secondary-button"
          aria-pressed={expertMode}
        >
          {expertMode ? "Standard mode" : "Expert mode"}
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
          <span className={`risk-chip ${scoreClass(analysis.overall_score)}`}>{riskLabel}</span>
        </div>
        <div>
          <p>Confidence</p>
          <strong>{analysis.confidence}%</strong>
        </div>
      </div>

      <section className="summary-section" aria-label="Résumé de décision">
        <h2>Decision summary</h2>
        <p>{riskExplanation}</p>
        <ul>
          <li>Providers favorables : <strong>{consensus.safe}</strong></li>
          <li>Providers défavorables : <strong>{consensus.risky}</strong></li>
          <li>Providers indisponibles / incertains : <strong>{consensus.unknown}</strong></li>
        </ul>
      </section>

      {consensus.hasDisagreement && (
        <section className="contradictions-card" aria-label="Contradictions entre providers">
          <h2>Provider contradictions detected</h2>
          <p>Certains providers ne donnent pas la même conclusion. Vérifiez ces écarts avant décision.</p>
          <ul>
            {contradictions.map((item, index) => (
              <li key={`${item.safe.provider}-${item.risky.provider}-${index}`}>
                <strong>{item.risky.provider}</strong> indique un risque (score {item.risky.score}),
                alors que <strong>{item.safe.provider}</strong> est favorable (score {item.safe.score}).
              </li>
            ))}
          </ul>
        </section>
      )}

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
        <p className="subtext">Chaque catégorie contribue au score global (0 = très risqué, 100 = très fiable).</p>
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

      {expertMode && (
        <section className="expert-section">
          <h2>Expert details</h2>
          <p className="subtext">Données techniques complètes (mode développeur).</p>
          <details>
            <summary>Raw JSON</summary>
            <pre>{JSON.stringify(analysis, null, 2)}</pre>
          </details>
        </section>
      )}
    </>
  );
}
