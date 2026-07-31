import { FormEvent, useState } from "react";
import type { AnalysisResponse, ApiResponse } from "../types";
import { AnalysisResults } from "./AnalysisResults";

interface Props {
  /** Called after a successful analysis (e.g., to reload the history list). */
  onResult: () => void;
}

export function AnalysisForm({ onResult }: Props) {
  const [url, setUrl] = useState("https://example.com");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [meta, setMeta] = useState<{ processingTime?: number; cached?: boolean } | null>(null);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setAnalysis(null);
    setMeta(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ url }),
      });

      const envelope = (await response.json()) as ApiResponse<AnalysisResponse>;

      if (!response.ok || !envelope.success) {
        const msg = envelope.errors?.length
          ? envelope.errors.join("; ")
          : envelope.message || `HTTP ${response.status}`;
        throw new Error(msg);
      }

      setAnalysis(envelope.data);
      setMeta({
        processingTime: envelope.metadata?.processingTime,
        cached: envelope.metadata?.cached,
      });
      onResult();
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="result-card">
      <form onSubmit={handleSubmit} className="search-form">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? "Analysing..." : "Analyse"}
        </button>
      </form>

      {error && <div className="toast error">{error}</div>}

      {meta && (
        <div className="analysis-meta">
          {meta.cached && <span className="badge cached">Cached</span>}
          {meta.processingTime !== undefined && (
            <span className="badge timing">{meta.processingTime} ms</span>
          )}
        </div>
      )}

      {analysis && <AnalysisResults analysis={analysis} />}
    </section>
  );
}
