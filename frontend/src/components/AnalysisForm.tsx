import { FormEvent, useEffect, useRef, useState } from "react";
import type { AnalysisResponse, ApiResponse } from "../types";
import { normalizeUrlInput, validateAnalysisUrl } from "../utils/analysis";
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
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [progressLabel, setProgressLabel] = useState<string | null>(null);
  const timerRef = useRef<number | null>(null);

  useEffect(
    () => () => {
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
      }
    },
    []
  );

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const validation = validateAnalysisUrl(url);
    if (!validation.ok) {
      setError(validation.message);
      return;
    }
    const normalizedUrl = validation.normalized;
    if (normalizedUrl !== url) {
      setUrl(normalizedUrl);
    }
    setLoading(true);
    setError(null);
    setAnalysis(null);
    setMeta(null);
    setElapsedSeconds(0);
    setProgressLabel("Préparation de l'analyse...");

    const controller = new AbortController();
    timerRef.current = window.setInterval(() => {
      setElapsedSeconds((previous) => {
        const next = previous + 1;
        if (next === 2) setProgressLabel("Collecte des signaux providers...");
        if (next === 5) setProgressLabel("Agrégation des preuves...");
        if (next === 8) setProgressLabel("Finalisation du score de confiance...");
        return next;
      });
    }, 1000);
    const timeoutId = window.setTimeout(() => controller.abort(), 45000);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ url: normalizedUrl }),
        signal: controller.signal,
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
      setProgressLabel("Analyse terminée.");
      onResult();
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") {
        setError("L'analyse a pris trop de temps. Réessayez ou testez une autre URL.");
      } else {
        setError(err instanceof Error ? err.message : "Une erreur est survenue pendant l'analyse.");
      }
      setProgressLabel("Analyse interrompue.");
    } finally {
      window.clearTimeout(timeoutId);
      if (timerRef.current !== null) {
        window.clearInterval(timerRef.current);
        timerRef.current = null;
      }
      setLoading(false);
    }
  };

  return (
    <section className="result-card">
      <form onSubmit={handleSubmit} className="search-form">
        <label htmlFor="analysis-url" className="sr-only">URL à analyser</label>
        <input
          id="analysis-url"
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          onBlur={(e) => setUrl(normalizeUrlInput(e.target.value))}
          placeholder="https://example.com"
          aria-label="URL à analyser"
          aria-invalid={error ? "true" : "false"}
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? "Analysing..." : "Analyse"}
        </button>
      </form>

      <div className="analysis-progress" aria-live="polite">
        {loading && (
          <>
            <p className="analysis-progress-title">{progressLabel}</p>
            <p className="analysis-progress-meta">Temps écoulé : {elapsedSeconds}s</p>
          </>
        )}
      </div>

      {error && <div className="toast error" role="alert">{error}</div>}

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
