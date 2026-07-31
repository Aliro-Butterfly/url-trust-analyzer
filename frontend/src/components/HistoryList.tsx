import { useState } from "react";
import { AnalysisResults } from "./AnalysisResults";
import type { HistoryItem } from "../types";

interface Props {
  items: HistoryItem[];
}

export function HistoryList({ items }: Props) {
  const [selectedId, setSelectedId] = useState<number | null>(null);

  return (
    <section className="history-card">
      <h2>Analysis history</h2>
      {items.length === 0 ? (
        <p>No saved analysis yet.</p>
      ) : (
        <ul className="history-list">
          {items.map((item) => (
            <li key={item.id} className="history-item">
              <div>
                <strong>{item.url}</strong>
                <span>{new Date(item.created_at).toLocaleString()}</span>
              </div>
              <div>
                <span>Score: {item.overall_score}</span>
                <span>Confidence: {item.confidence}%</span>
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() => setSelectedId(selectedId === item.id ? null : item.id)}
                >
                  {selectedId === item.id ? "Hide details" : "View details"}
                </button>
              </div>
              {selectedId === item.id && item.report && (
                <div className="history-item-details">
                  <AnalysisResults analysis={item.report} />
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
