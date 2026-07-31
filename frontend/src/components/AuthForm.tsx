import { FormEvent, useState } from "react";
import type { ApiResponse, AuthResponse } from "../types";

interface Props {
  onSuccess: (payload: AuthResponse) => void;
}

export function AuthForm({ onSuccess }: Props) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`/api/auth/${mode}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ username, password }),
      });

      const envelope = (await response.json()) as ApiResponse<AuthResponse>;

      if (!response.ok || !envelope.success) {
        const msg = envelope.errors?.length
          ? envelope.errors.join("; ")
          : envelope.message || `HTTP ${response.status}`;
        throw new Error(msg);
      }

      setUsername("");
      setPassword("");
      onSuccess(envelope.data!);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication error occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <section className="result-card">
      <h2>User Login</h2>
      <form onSubmit={handleSubmit} className="search-form">
        <input
          type="text"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          placeholder="Username"
          required
        />
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Password"
          required
        />
        <button type="submit" disabled={loading}>
          {loading ? "Working..." : mode === "login" ? "Login" : "Register"}
        </button>
      </form>
      <div className="provider-metrics">
        <button type="button" onClick={() => setMode(mode === "login" ? "register" : "login")}>
          {mode === "login" ? "Create account" : "Switch to login"}
        </button>
      </div>
      {error && <div className="toast error">{error}</div>}
    </section>
  );
}
