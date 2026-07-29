import { FormEvent, useEffect, useState } from "react";
import logo from "./assets/logo.svg";

interface ProviderResult {
  provider: string;
  status: string;
  score: number;
  confidence: number;
  summary: string;
  details: Record<string, unknown>;
}

interface AnalysisResponse {
  url: string;
  overall_score: number;
  confidence: number;
  reasons: string[];
  score_breakdown: Record<string, number>;
  results: ProviderResult[];
}

interface HistoryItem {
  id: number;
  url: string;
  overall_score: number;
  confidence: number;
  created_at: string;
  report: AnalysisResponse;
}

interface AuthResponse {
  username: string;
}

function App() {
  const [url, setUrl] = useState("https://example.com");
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [user, setUser] = useState<string | null>(null);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [authError, setAuthError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadUser = async () => {
    try {
      const response = await fetch("/api/auth/me", { credentials: "include" });
      if (!response.ok) {
        setUser(null);
        return;
      }
      const payload = (await response.json()) as AuthResponse;
      setUser(payload.username);
    } catch (err) {
      setUser(null);
    }
  };

  const loadHistory = async () => {
    try {
      const response = await fetch("/api/history", { credentials: "include" });
      if (!response.ok) {
        setHistory([]);
        return;
      }
      const historyPayload = await response.json();
      setHistory(historyPayload);
    } catch (err) {
      console.warn("Unable to load history", err);
      setHistory([]);
    }
  };

  useEffect(() => {
    loadUser();
    loadHistory();
  }, []);

  const handleAuthSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setAuthError(null);

    try {
      const response = await fetch(`/api/auth/${authMode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });

      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail || `HTTP ${response.status}`);
      }

      const payload = (await response.json()) as AuthResponse;
      setUser(payload.username);
      setUsername("");
      setPassword("");
      await loadHistory();
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "Authentication error occurred.");
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = async () => {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
    setUser(null);
    setAnalysis(null);
    setHistory([]);
  };

  const downloadReport = async () => {
    if (!analysis) {
      return;
    }

    const reportLines: string[] = [
      `URL: ${analysis.url}`,
      `Overall score: ${analysis.overall_score} / 100`,
      `Confidence: ${analysis.confidence}%`,
      "",
      "Reasons:",
      ...analysis.reasons.map((reason) => `- ${reason}`),
      "",
      "Score breakdown:",
      ...Object.entries(analysis.score_breakdown).map(
        ([dimension, value]) => `- ${dimension}: ${value}`
      ),
      "",
      "Providers:",
      ...analysis.results.flatMap((item) => [
        `=== ${item.provider} ===`,
        `Summary: ${item.summary}`,
        `Score: ${item.score}`,
        `Confidence: ${item.confidence}%`,
        "",
      ]),
    ];

    const blob = new Blob([reportLines.join("\n")], {
      type: "text/plain;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${analysis.url.replace(/[^a-z0-9]/gi, "_").slice(0, 40)}_report.txt`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setAnalysis(null);

    if (!user) {
      setError("Please log in to run an analysis.");
      setLoading(false);
      return;
    }

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        const payload = await response.json();
        throw new Error(payload.detail || `HTTP ${response.status}`);
      }

      const payload = (await response.json()) as AnalysisResponse;
      setAnalysis(payload);
      await loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header>
        <div className="brand">
          <img src={logo} alt="UTA Logo" className="brand-logo" />
          <div>
            <h1>URL Trust Analyzer</h1>
            <p>Fast URL analysis and trust scoring.</p>
          </div>
        </div>
      </header>

      <main>
        {!user ? (
          <section className="result-card">
            <h2>User Login</h2>
            <form onSubmit={handleAuthSubmit} className="search-form">
              <input
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Username"
                required
              />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Password"
                required
              />
              <button type="submit" disabled={loading}>
                {loading ? "Working..." : authMode === "login" ? "Login" : "Register"}
              </button>
            </form>

            <div className="provider-metrics">
              <button type="button" onClick={() => setAuthMode(authMode === "login" ? "register" : "login")}> 
                {authMode === "login" ? "Create account" : "Switch to login"}
              </button>
            </div>
            {authError && <div className="toast error">{authError}</div>}
          </section>
        ) : (
          <section className="result-card">
            <div className="result-header">
              <div>
                <p>Signed in as</p>
                <strong>{user}</strong>
              </div>
              <div>
                <button type="button" onClick={handleLogout}>
                  Logout
                </button>
              </div>
            </div>
          </section>
        )}

        {user && (
          <section className="result-card">
            <form onSubmit={handleSubmit} className="search-form">
              <input
                type="url"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                placeholder="https://example.com"
                required
              />
              <button type="submit" disabled={loading}>
                {loading ? "Analyse en cours…" : "Analyser"}
              </button>
            </form>

            {error && <div className="toast error">{error}</div>}

            {analysis && (
              <>
                <div className="button-row">
                  <button type="button" onClick={downloadReport} className="secondary-button">
                    Create Report
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

                <div className="provider-list">
                  {analysis.results.map((item) => (
                    <article key={item.provider} className="provider-card">
                      <h2>{item.provider}</h2>
                      <p>{item.summary}</p>
                      <div className="provider-metrics">
                        <span>Score: {item.score}</span>
                        <span>Confidence: {item.confidence}%</span>
                      </div>
                    </article>
                  ))}
                </div>
              </>
            )}
          </section>
        )}

        {user && (
          <section className="history-card">
            <h2>Analysis history</h2>
            {history.length === 0 ? (
              <p>No saved analysis yet.</p>
            ) : (
              <ul className="history-list">
                {history.map((item) => (
                  <li key={item.id} className="history-item">
                    <div>
                      <strong>{item.url}</strong>
                      <span>{new Date(item.created_at).toLocaleString()}</span>
                    </div>
                    <div>
                      <span>Score: {item.overall_score}</span>
                      <span>Confidence: {item.confidence}%</span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </main>
    </div>
  );
}

export default App;
