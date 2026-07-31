import { FormEvent, useState } from "react";
import type { ApiKeysStatus } from "../types";

interface Props {
  status: ApiKeysStatus;
  onSaved: (status: ApiKeysStatus) => void;
}

export function ApiKeysForm({ status, onSaved }: Props) {
  const [urlscanKey, setUrlscanKey] = useState("");
  const [googleKey, setGoogleKey] = useState("");
  const [vtKey, setVtKey] = useState("");
  const [abuseipdbKey, setAbuseipdbKey] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setMessage(null);

    try {
      const response = await fetch("/api/auth/api-keys", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          urlscan: urlscanKey || undefined,
          google_safebrowsing: googleKey || undefined,
          virustotal: vtKey || undefined,
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

      const payload = (await response.json()) as ApiKeysStatus;
      setUrlscanKey("");
      setGoogleKey("");
      setVtKey("");
      setAbuseipdbKey("");
      setMessage("API keys updated successfully. Only you can use these keys.");
      onSaved(payload);
    } catch (err) {
      setMessage(err instanceof Error ? err.message : "Unable to update API keys.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="result-card">
      <h2>API Keys</h2>
      <p className="subtext">
        Store your provider API keys securely for your account. Only you can use these keys.
      </p>
      <form onSubmit={handleSubmit} className="search-form">
        <input
          type="password"
          value={urlscanKey}
          onChange={(e) => setUrlscanKey(e.target.value)}
          placeholder={status.has_urlscan ? "URLScan key stored — enter new to replace" : "URLScan API key"}
        />
        <input
          type="password"
          value={googleKey}
          onChange={(e) => setGoogleKey(e.target.value)}
          placeholder={
            status.has_google_safebrowsing
              ? "Google Safe Browsing key stored — enter new to replace"
              : "Google Safe Browsing API key"
          }
        />
        <input
          type="password"
          value={vtKey}
          onChange={(e) => setVtKey(e.target.value)}
          placeholder={status.has_virustotal ? "VirusTotal key stored — enter new to replace" : "VirusTotal API key"}
        />
        <input
          type="password"
          value={abuseipdbKey}
          onChange={(e) => setAbuseipdbKey(e.target.value)}
          placeholder={status.has_abuseipdb ? "AbuseIPDB key stored — enter new to replace" : "AbuseIPDB API key"}
        />
        <button type="submit" disabled={loading}>
          {loading ? "Saving..." : "Save API Keys"}
        </button>
      </form>
      {message && <div className="toast success">{message}</div>}
    </section>
  );
}
