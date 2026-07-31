import { FormEvent, useState } from "react";
import type { ApiKeysStatus, ApiResponse } from "../types";

interface Props {
  status: ApiKeysStatus;
  onSaved: (status: ApiKeysStatus) => void;
}

type ToastState = { message: string; kind: "success" | "error" } | null;

export function ApiKeysForm({ status, onSaved }: Props) {
  const [urlscanKey, setUrlscanKey] = useState("");
  const [googleKey, setGoogleKey] = useState("");
  const [vtKey, setVtKey] = useState("");
  const [abuseipdbKey, setAbuseipdbKey] = useState("");
  const [toast, setToast] = useState<ToastState>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setToast(null);

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

      const envelope = (await response.json()) as ApiResponse<ApiKeysStatus>;

      if (!response.ok || !envelope.success) {
        const msg = envelope.errors?.length
          ? envelope.errors.join("; ")
          : envelope.message || `HTTP ${response.status}`;
        throw new Error(msg);
      }

      setUrlscanKey("");
      setGoogleKey("");
      setVtKey("");
      setAbuseipdbKey("");
      setToast({ message: "API keys updated successfully. Only you can use these keys.", kind: "success" });
      onSaved(envelope.data!);
    } catch (err) {
      setToast({ message: err instanceof Error ? err.message : "Unable to update API keys.", kind: "error" });
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
      {toast && <div className={`toast ${toast.kind}`}>{toast.message}</div>}
    </section>
  );
}