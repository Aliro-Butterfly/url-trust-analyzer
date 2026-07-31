import { FormEvent, useEffect, useState } from "react";
import logo from "./assets/logo.svg";
import { AdminPanel } from "./components/AdminPanel";
import { AnalysisForm } from "./components/AnalysisForm";
import { ApiKeysForm } from "./components/ApiKeysForm";
import { AuthForm } from "./components/AuthForm";
import { HistoryList } from "./components/HistoryList";
import type { AdminConfig, ApiKeysStatus, ApiResponse, AuthResponse, HistoryItem } from "./types";

function App() {
  const [user, setUser] = useState<string | null>(null);
  const [isAdmin, setIsAdmin] = useState(false);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [apiKeyStatus, setApiKeyStatus] = useState<ApiKeysStatus>({
    has_urlscan: false,
    has_google_safebrowsing: false,
    has_virustotal: false,
    has_abuseipdb: false,
  });
  const [adminConfig, setAdminConfig] = useState<AdminConfig | null>(null);
  const [adminMessage, setAdminMessage] = useState<string | null>(null);

  const loadHistory = async (): Promise<void> => {
    try {
      const response = await fetch("/api/history", { credentials: "include" });
      if (!response.ok) { setHistory([]); return; }
      const envelope = (await response.json()) as ApiResponse<HistoryItem[]>;
      setHistory(envelope.success && envelope.data ? envelope.data : []);
    } catch {
      setHistory([]);
    }
  };

  const loadApiKeys = async (): Promise<void> => {
    try {
      const response = await fetch("/api/auth/api-keys", { credentials: "include" });
      if (!response.ok) return;
      const envelope = (await response.json()) as ApiResponse<ApiKeysStatus>;
      if (envelope.success && envelope.data) setApiKeyStatus(envelope.data);
    } catch { /* silently ignore */ }
  };

  const loadAdminConfig = async (): Promise<void> => {
    try {
      const response = await fetch("/api/admin/config", { credentials: "include" });
      if (!response.ok) { setIsAdmin(false); return; }
      const envelope = (await response.json()) as ApiResponse<AdminConfig>;
      if (envelope.success && envelope.data) {
        setAdminConfig(envelope.data);
      } else {
        setIsAdmin(false);
      }
    } catch {
      setIsAdmin(false);
    }
  };

  const handleAuthSuccess = async (payload: AuthResponse): Promise<void> => {
    setUser(payload.username);
    setIsAdmin(payload.is_admin === true);
    if (payload.is_admin) {
      await loadAdminConfig();
    } else {
      await Promise.all([loadHistory(), loadApiKeys()]);
    }
  };

  const handleLogout = async (): Promise<void> => {
    await fetch("/api/auth/logout", { method: "POST", credentials: "include" });
    setUser(null);
    setIsAdmin(false);
    setAdminConfig(null);
    setHistory([]);
  };

  const handleAdminSave = async (event: FormEvent<HTMLFormElement>): Promise<void> => {
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
      const envelope = (await response.json()) as ApiResponse<AdminConfig>;
      if (!response.ok || !envelope.success) {
        const msg = envelope.errors?.length
          ? envelope.errors.join("; ")
          : envelope.message || `HTTP ${response.status}`;
        throw new Error(msg);
      }
      if (envelope.data) setAdminConfig(envelope.data);
      setAdminMessage("Configuration saved successfully.");
    } catch (err) {
      setAdminMessage(err instanceof Error ? err.message : "Save failed");
    }
  };

  useEffect(() => {
    const init = async () => {
      try {
        const response = await fetch("/api/auth/me", { credentials: "include" });
        if (!response.ok) return;
        const envelope = (await response.json()) as ApiResponse<AuthResponse>;
        if (!envelope.success || !envelope.data) return;
        const payload = envelope.data;
        setUser(payload.username);
        setIsAdmin(payload.is_admin === true);
        if (payload.is_admin) {
          await loadAdminConfig();
        } else {
          await Promise.all([loadHistory(), loadApiKeys()]);
        }
      } catch { /* not authenticated */ }
    };
    init();
  }, []);

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
          <AuthForm onSuccess={handleAuthSuccess} />
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
            {adminConfig && (
              <AdminPanel
                config={adminConfig}
                onChange={setAdminConfig}
                onSave={handleAdminSave}
                message={adminMessage}
              />
            )}
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
            <ApiKeysForm status={apiKeyStatus} onSaved={setApiKeyStatus} />
            <AnalysisForm onResult={loadHistory} />
          </>
        )}

        {user && <HistoryList items={history} />}
      </main>
    </div>
  );
}

export default App;
