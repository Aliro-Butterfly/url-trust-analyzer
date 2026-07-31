import { FormEvent, useState } from "react";
import type { AnalysisResponse } from "../types";
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

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setAnalysis(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const payload = await response.json();
        const msg = Array.isArray(payload.detail)
          ? payload.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join("; ")
          : payload.detail || `HTTP ${response.status}`;
        throw new Error(msg);
      }

      const payload = (await response.json()) as AnalysisResponse;
      setAnalysis(payload);
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
      {analysis && <AnalysisResults analysis={analysis} />}
    </section>
  );
}
