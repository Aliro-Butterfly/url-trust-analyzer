import { FormEvent } from "react";
import type { AdminConfig } from "../types";

interface Props {
  config: AdminConfig;
  onChange: (config: AdminConfig) => void;
  onSave: (event: FormEvent<HTMLFormElement>) => void;
  message: string | null;
}

export function AdminPanel({ config, onChange, onSave, message }: Props) {
  return (
    <section className="result-card">
      <h2>Scoring Configuration</h2>
      <form onSubmit={onSave}>
        <h3>Category Weights</h3>
        <p className="subtext">Weight of each category in the overall score (sum should be ~100).</p>
        <div className="breakdown-list">
          {Object.entries(config.dimension_weights).map(([key, val]) => (
            <div key={key} className="breakdown-item">
              <span>{key}</span>
              <input
                type="number"
                min="0"
                max="100"
                value={val}
                onChange={(e) =>
                  onChange({
                    ...config,
                    dimension_weights: { ...config.dimension_weights, [key]: Number(e.target.value) },
                  })
                }
                style={{ width: "70px" }}
              />
            </div>
          ))}
        </div>

        <h3>Providers</h3>
        <p className="subtext">Coefficient + coverage per dimension (0–100) for each provider.</p>
        <div className="provider-list" style={{ marginTop: "0.5rem" }}>
          {Object.entries(config.providers).map(([name, prov]) => (
            <article key={name} className="provider-card" style={{ padding: "0.75rem" }}>
              <div className="provider-card-header">
                <h2 style={{ fontSize: "1rem" }}>{name}</h2>
              </div>
              <div className="breakdown-item" style={{ marginBottom: "0.4rem" }}>
                <span style={{ fontWeight: 600 }}>Coefficient</span>
                <input
                  type="number"
                  step="0.1"
                  min="0"
                  max="10"
                  value={prov.coefficient}
                  onChange={(e) =>
                    onChange({
                      ...config,
                      providers: {
                        ...config.providers,
                        [name]: { ...prov, coefficient: Number(e.target.value) },
                      },
                    })
                  }
                  style={{ width: "70px" }}
                />
              </div>
              <div className="breakdown-list">
                {Object.entries(prov.dimensions).map(([dim, cov]) => (
                  <div key={dim} className="breakdown-item">
                    <span>{dim}</span>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.3rem" }}>
                      <span style={{ fontSize: "0.75rem", color: "#888" }}>cov</span>
                      <input
                        type="number"
                        min="0"
                        max="100"
                        value={cov}
                        onChange={(e) => {
                          const dims = { ...prov.dimensions, [dim]: Number(e.target.value) };
                          onChange({
                            ...config,
                            providers: { ...config.providers, [name]: { ...prov, dimensions: dims } },
                          });
                        }}
                        style={{ width: "55px" }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </article>
          ))}
        </div>

        <button type="submit" style={{ marginTop: "1rem" }}>
          Save Configuration
        </button>
      </form>
      {message && (
        <div className={`toast ${message.includes("successfully") ? "success" : "error"}`}>
          {message}
        </div>
      )}
    </section>
  );
}
