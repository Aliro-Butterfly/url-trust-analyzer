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
  is_admin?: boolean;
}

interface AdminConfig {
  dimension_weights: Record<string, number>;
  providers: Record<string, { coefficient: number; dimensions: Record<string, number> }>;
}

function formatDetail(value: unknown): string {
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

function scoreClass(score: number): string {
  if (score >= 70) return "score-green";
  if (score >= 40) return "score-yellow";
  return "score-red";
}

function hasData(status: string): boolean {
  return status === "success";
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
  const [apiKeyStatus, setApiKeyStatus] = useState({
    has_urlscan: false,
    has_google_safebrowsing: false,
    has_virustotal: false,
    has_abuseipdb: false,
  });
  const [apiKeyLoading, setApiKeyLoading] = useState(false);
  const [viewMode, setViewMode] = useState<"cards" | "table">("cards");
  const [apiKeyMessage, setApiKeyMessage] = useState<string | null>(null);
  const [urlscanKey, setUrlscanKey] = useState("");
  const [googleSafeBrowsingKey, setGoogleSafeBrowsingKey] = useState("");
  const [virusTotalKey, setVirusTotalKey] = useState("");
  const [abuseipdbKey, setAbuseipdbKey] = useState("");
  const [isAdmin, setIsAdmin] = useState(false);
  const [adminConfig, setAdminConfig] = useState<AdminConfig | null>(null);
  const [adminMessage, setAdminMessage] = useState<string | null>(null);

  const loadUser = async () => {
    try {
      const response = await fetch("/api/auth/me", { credentials: "include" });
      if (!response.ok) {
        setUser(null);
        setIsAdmin(false);
        return;
      }
      const payload = (await response.json()) as AuthResponse;
      setUser(payload.username);
      setIsAdmin(payload.is_admin === true);
      if (payload.is_admin) {
        loadAdminConfig();
      }
    } catch (err) {
      setUser(null);
      setIsAdmin(false);
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

  const loadApiKeys = async () => {
    setApiKeyMessage(null);
    try {
      const response = await fetch("/api/auth/api-keys", { credentials: "include" });
      if (!response.ok) {
        setApiKeyStatus({ has_urlscan: false, has_google_safebrowsing: false, has_virustotal: false, has_abuseipdb: false });
        return;
      }
      const payload = await response.json();
      setApiKeyStatus(payload);
    } catch (err) {
      console.warn("Unable to load API key status", err);
    }
  };

  useEffect(() => {
    loadUser();
    loadHistory();
  }, []);

  useEffect(() => {
    if (user) {
      loadApiKeys();
    }
  }, [user]);

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
        const msg = Array.isArray(payload.detail)
          ? payload.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join("; ")
          : payload.detail || `HTTP ${response.status}`;
        throw new Error(msg);
      }

      const payload = (await response.json()) as AuthResponse;
      setUser(payload.username);
      setIsAdmin(payload.is_admin === true);
      setUsername("");
      setPassword("");
      if (payload.is_admin) {
        await loadAdminConfig();
      } else {
        await loadHistory();
      }
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
    setIsAdmin(false);
    setAnalysis(null);
    setHistory([]);
    setAdminConfig(null);
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
        `Status: ${item.status}`,
        `Summary: ${item.summary}`,
        `Score: ${hasData(item.status) ? item.score : "N/A"}`,
        `Confidence: ${hasData(item.status) ? `${item.confidence}%` : "N/A"}`,
        ...(Object.keys(item.details).length > 0
          ? Object.entries(item.details).map(([key, val]) => `  ${key}: ${formatDetail(val)}`)
          : ["  No additional data."]),
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

  const downloadCSV = () => {
    if (!analysis) return;

    const headers = ["Provider", "Status", "Score", "Confidence", "Summary"];
    const rows = analysis.results.map((r) =>
      [r.provider, r.status, hasData(r.status) ? String(r.score) : "N/A", hasData(r.status) ? `${r.confidence}%` : "N/A", r.summary].map((c) =>
        `"${c.replace(/"/g, '""')}"`
      ).join(",")
    );

    const csv = "\uFEFF" + [headers.join(","), ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${analysis.url.replace(/[^a-z0-9]/gi, "_").slice(0, 40)}_report.csv`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  };

  const handleApiKeysSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setApiKeyLoading(true);
    setApiKeyMessage(null);

    try {
      const response = await fetch("/api/auth/api-keys", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          urlscan: urlscanKey || undefined,
          google_safebrowsing: googleSafeBrowsingKey || undefined,
          virustotal: virusTotalKey || undefined,
          abuseipdb: abuseipdbKey || undefined,
        }),
      });

      if (!response.ok) {
        const payload = await response.json();
        const msg = Array.isArray(payload.detail)
          ? payload.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join("; ")
          : payload.detail || `HTTP ${response.status}`;
        throw new Error(msg);
      }

      const payload = await response.json();
      setApiKeyStatus(payload);
      setUrlscanKey("");
      setGoogleSafeBrowsingKey("");
      setVirusTotalKey("");
      setAbuseipdbKey("");
      setApiKeyMessage("API keys updated successfully. Only you can use these keys.");
    } catch (err) {
      setApiKeyMessage(err instanceof Error ? err.message : "Unable to update API keys.");
    } finally {
      setApiKeyLoading(false);
    }
  };

  const loadAdminConfig = async () => {
    try {
      const response = await fetch("/api/admin/config", { credentials: "include" });
      if (!response.ok) {
        setIsAdmin(false);
        return;
      }
      const payload = await response.json();
      setAdminConfig(payload);
    } catch {
      setIsAdmin(false);
    }
  };

  const handleAdminSave = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAdminMessage(null);
    if (!adminConfig) return;
    try {
      const response = await fetch("/api/admin/config", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          dimension_weights: adminConfig.dimension_weights,
          providers: adminConfig.providers,
        }),
      });
      if (!response.ok) {
        const payload = await response.json();
        const msg = Array.isArray(payload.detail)
          ? payload.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join("; ")
          : payload.detail || `HTTP ${response.status}`;
        throw new Error(msg);
      }
      const payload = await response.json();
      setAdminConfig(payload);
      setAdminMessage("Configuration saved successfully.");
    } catch (err) {
      setAdminMessage(err instanceof Error ? err.message : "Save failed");
    }
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
        const msg = Array.isArray(payload.detail)
          ? payload.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join("; ")
          : payload.detail || `HTTP ${response.status}`;
        throw new Error(msg);
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
        ) : isAdmin ? (
          <>
            <section className="result-card">
              <div className="result-header">
                <div>
                  <p>Signed in as</p>
                  <strong>{user} (admin)</strong>
                </div>
                <div>
                  <button type="button" onClick={handleLogout}>Logout</button>
                </div>
              </div>
            </section>
            <section className="result-card">
              <h2>Scoring Configuration</h2>
              {adminConfig && (
                <form onSubmit={handleAdminSave}>
                  <h3>Category Weights</h3>
                  <p className="subtext">Weight of each category in the overall score (sum should be ~100).</p>
                  <div className="breakdown-list">
                    {Object.entries(adminConfig.dimension_weights).map(([key, val]) => (
                      <div key={key} className="breakdown-item">
                        <span>{key}</span>
                        <input type="number" min="0" max="100" value={val}
                          onChange={(e) => setAdminConfig({
                            ...adminConfig,
                            dimension_weights: { ...adminConfig.dimension_weights, [key]: Number(e.target.value) },
                          })} style={{ width: "70px" }} />
                      </div>
                    ))}
                  </div>

                  <h3>Providers</h3>
                  <p className="subtext">Coefficient + coverage per dimension (0–100) for each provider.</p>
                  <div className="provider-list" style={{ marginTop: "0.5rem" }}>
                    {Object.entries(adminConfig.providers).map(([name, prov]) => (
                      <article key={name} className="provider-card" style={{ padding: "0.75rem" }}>
                        <div className="provider-card-header">
                          <h2 style={{ fontSize: "1rem" }}>{name}</h2>
                        </div>
                        <div className="breakdown-item" style={{ marginBottom: "0.4rem" }}>
                          <span style={{ fontWeight: 600 }}>Coefficient</span>
                          <input type="number" step="0.1" min="0" max="10" value={prov.coefficient}
                            onChange={(e) => {
                              const updated = { ...adminConfig.providers, [name]: { ...prov, coefficient: Number(e.target.value) } };
                              setAdminConfig({ ...adminConfig, providers: updated });
                            }} style={{ width: "70px" }} />
                        </div>
                        <div className="breakdown-list">
                          {Object.entries(prov.dimensions).map(([dim, cov]) => (
                            <div key={dim} className="breakdown-item">
                              <span>{dim}</span>
                              <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
                                <span style={{ fontSize: "0.75rem", color: "#888" }}>cov</span>
                                <input type="number" min="0" max="100" value={cov}
                                  onChange={(e) => {
                                    const dims = { ...prov.dimensions, [dim]: Number(e.target.value) };
                                    const updated = { ...adminConfig.providers, [name]: { ...prov, dimensions: dims } };
                                    setAdminConfig({ ...adminConfig, providers: updated });
                                  }} style={{ width: "55px" }} />
                              </div>
                            </div>
                          ))}
                        </div>
                      </article>
                    ))}
                  </div>

                  <button type="submit" style={{ marginTop: "1rem" }}>Save Configuration</button>
                </form>
              )}
              {adminMessage && <div className={`toast ${adminMessage.includes("successfully") ? "success" : "error"}`}>{adminMessage}</div>}
            </section>
          </>
        ) : (
          <>
            <section className="result-card">
              <div className="result-header">
                <div>
                  <p>Signed in as</p>
                  <strong>{user}</strong>
                </div>
                <div>
                  <button type="button" onClick={handleLogout}>Logout</button>
                </div>
              </div>
            </section>
            <section className="result-card">
              <h2>API Keys</h2>
              <p className="subtext">Store your provider API keys securely for your account. Only you can use these keys.</p>
              <form onSubmit={handleApiKeysSubmit} className="search-form">
                <input
                  type="password"
                  value={urlscanKey}
                  onChange={(event) => setUrlscanKey(event.target.value)}
                  placeholder={apiKeyStatus.has_urlscan ? "URLScan key stored — enter new to replace" : "URLScan API key"}
                />
                <input
                  type="password"
                  value={googleSafeBrowsingKey}
                  onChange={(event) => setGoogleSafeBrowsingKey(event.target.value)}
                  placeholder={apiKeyStatus.has_google_safebrowsing ? "Google Safe Browsing key stored — enter new to replace" : "Google Safe Browsing API key"}
                />
                <input
                  type="password"
                  value={virusTotalKey}
                  onChange={(event) => setVirusTotalKey(event.target.value)}
                  placeholder={apiKeyStatus.has_virustotal ? "VirusTotal key stored — enter new to replace" : "VirusTotal API key"}
                />
                <input
                  type="password"
                  value={abuseipdbKey}
                  onChange={(event) => setAbuseipdbKey(event.target.value)}
                  placeholder={apiKeyStatus.has_abuseipdb ? "AbuseIPDB key stored — enter new to replace" : "AbuseIPDB API key"}
                />
                <button type="submit" disabled={apiKeyLoading}>
                  {apiKeyLoading ? "Saving..." : "Save API Keys"}
                </button>
              </form>
              {apiKeyMessage && <div className="toast success">{apiKeyMessage}</div>}
            </section>
          </>
        )}

        {user && !isAdmin && (
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
                {loading ? "Analysing..." : "Analyse"}
              </button>
            </form>

            {error && <div className="toast error">{error}</div>}

            {analysis && (
              <>
                <div className="button-row">
                  <button type="button" onClick={() => setViewMode(viewMode === "cards" ? "table" : "cards")} className="secondary-button">
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
                            <td><strong>{item.provider}</strong></td>
                            <td><span className={`provider-status provider-status--${item.status}`}>{item.status}</span></td>
                            <td>{available ? <span className={`score-badge ${scoreClass(item.score)}`}>{item.score}</span> : <span className="score-na">N/A</span>}</td>
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
                      <article key={item.provider} className={`provider-card ${!available ? "provider-card--error" : ""}`}>
                        <div className="provider-card-header">
                          <h2>{item.provider}</h2>
                          <span className={`provider-status provider-status--${item.status}`}>{item.status}</span>
                        </div>
                        <p className="provider-summary">{item.summary}</p>
                        <div className="provider-metrics">
                          <span>Score: {available ? <strong className={scoreClass(item.score)}>{item.score}</strong> : <strong className="score-na">N/A</strong>}</span>
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
