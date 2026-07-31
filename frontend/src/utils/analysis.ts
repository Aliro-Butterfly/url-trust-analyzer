import type { AnalysisResponse, ProviderResult } from "../types";

export function normalizeUrlInput(rawValue: string): string {
  const trimmed = rawValue.trim();
  if (!trimmed) return trimmed;
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

export function validateAnalysisUrl(rawValue: string): { ok: true; normalized: string } | { ok: false; message: string } {
  const normalized = normalizeUrlInput(rawValue);
  if (!normalized) {
    return { ok: false, message: "Veuillez saisir une URL." };
  }
  let parsed: URL;
  try {
    parsed = new URL(normalized);
  } catch {
    return { ok: false, message: "URL invalide. Exemple attendu : https://example.com" };
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    return { ok: false, message: "Seuls les protocoles HTTP et HTTPS sont autorisés." };
  }
  if (!parsed.hostname || parsed.hostname.length < 3 || !parsed.hostname.includes(".")) {
    return { ok: false, message: "Le domaine semble incomplet. Exemple : example.com" };
  }
  if (normalized.length > 2048) {
    return { ok: false, message: "URL trop longue (maximum 2048 caractères)." };
  }
  return { ok: true, normalized };
}

export function getRiskLabel(score: number): "Low risk" | "Medium risk" | "High risk" {
  if (score >= 70) return "Low risk";
  if (score >= 40) return "Medium risk";
  return "High risk";
}

export function getRiskExplanation(score: number): string {
  if (score >= 70) return "La majorité des signaux observés sont favorables.";
  if (score >= 40) return "Le résultat est mitigé : vérifiez les providers en désaccord.";
  return "Des signaux de risque importants ont été détectés.";
}

type SafetyBucket = "safe" | "risky" | "unknown";

function classifyProvider(result: ProviderResult): SafetyBucket {
  if (result.status !== "success") return "unknown";
  if (result.score >= 70) return "safe";
  if (result.score < 40) return "risky";
  return "unknown";
}

export function getConsensusSummary(analysis: AnalysisResponse): {
  safe: number;
  risky: number;
  unknown: number;
  hasDisagreement: boolean;
} {
  const summary = analysis.results.reduce(
    (acc, item) => {
      const bucket = classifyProvider(item);
      acc[bucket] += 1;
      return acc;
    },
    { safe: 0, risky: 0, unknown: 0 }
  );
  return {
    ...summary,
    hasDisagreement: summary.safe > 0 && summary.risky > 0,
  };
}

export function listContradictions(analysis: AnalysisResponse): Array<{ safe: ProviderResult; risky: ProviderResult }> {
  const safeProviders = analysis.results.filter((item) => item.status === "success" && item.score >= 70);
  const riskyProviders = analysis.results.filter((item) => item.status === "success" && item.score < 40);
  const pairs: Array<{ safe: ProviderResult; risky: ProviderResult }> = [];
  const maxPairs = Math.min(3, safeProviders.length, riskyProviders.length);
  for (let i = 0; i < maxPairs; i += 1) {
    pairs.push({ safe: safeProviders[i], risky: riskyProviders[i] });
  }
  return pairs;
}
