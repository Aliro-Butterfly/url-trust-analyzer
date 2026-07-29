import { FormEvent, useEffect, useState } from "react";

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
      setAuthError(err instanceof Error ? err.message : "Une erreur d'authentification est survenue.");
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

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setAnalysis(null);

    if (!user) {
      setError("Veuillez vous connecter pour lancer une analyse.");
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
      setError(err instanceof Error ? err.message : "Une erreur est survenue.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header>
        <h1>URL Trust Analyzer</h1>
        <p>Analyse rapide d’une URL et score de confiance.</p>
      </header>

      <main>
        {!user ? (
          <section className="result-card">
            <h2>Connexion utilisateur</h2>
            <form onSubmit={handleAuthSubmit} className="search-form">
              <input
                type="text"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Nom d'utilisateur"
                required
              />
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Mot de passe"
                required
              />
              <button type="submit" disabled={loading}>
                {loading ? "En cours…" : authMode === "login" ? "Se connecter" : "S'inscrire"}
              </button>
            </form>

            <div className="provider-metrics">
              <button type="button" onClick={() => setAuthMode(authMode === "login" ? "register" : "login")}> 
                {authMode === "login" ? "Créer un compte" : "Se connecter"}
              </button>
            </div>
            {authError && <div className="toast error">{authError}</div>}
          </section>
        ) : (
          <section className="result-card">
            <div className="result-header">
              <div>
                <p>Connecté en tant que</p>
                <strong>{user}</strong>
              </div>
              <div>
                <button type="button" onClick={handleLogout}>
                  Se déconnecter
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
                <div className="result-header">
                  <div>
                    <p>URL analysée</p>
                    <strong>{analysis.url}</strong>
                  </div>
                  <div>
                    <p>Score global</p>
                    <strong>{analysis.overall_score} / 100</strong>
                  </div>
                  <div>
                    <p>Confiance</p>
                    <strong>{analysis.confidence}%</strong>
                  </div>
                </div>

                <div className="analysis-reasons">
                  <h2>Pourquoi ?</h2>
                  <ul>
                    {analysis.reasons.map((reason) => (
                      <li key={reason}>{reason}</li>
                    ))}
                  </ul>
                </div>

                <div className="breakdown-card">
                  <h2>Répartition du score</h2>
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
                        <span>Confiance: {item.confidence}%</span>
                      </div>
                      <pre>{JSON.stringify(item.details, null, 2)}</pre>
                    </article>
                  ))}
                </div>
              </>
            )}
          </section>
        )}

        {user && (
          <section className="history-card">
            <h2>Historique des analyses</h2>
            {history.length === 0 ? (
              <p>Aucune analyse enregistrée pour le moment.</p>
            ) : (
              <ul className="history-list">
                {history.map((item) => (
                  <li key={item.id} className="history-item">
                    <div>
                      <strong>{item.url}</strong>
                      <span>{new Date(item.created_at).toLocaleString()}</span>
                    </div>
                    <div>
                      <span>Score : {item.overall_score}</span>
                      <span>Confiance : {item.confidence}%</span>
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
