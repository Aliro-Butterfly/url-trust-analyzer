export interface ProviderResult {
  provider: string;
  status: string;
  score: number;
  confidence: number;
  summary: string;
  details: Record<string, unknown>;
}

export interface AnalysisResponse {
  url: string;
  overall_score: number;
  confidence: number;
  reasons: string[];
  score_breakdown: Record<string, number>;
  results: ProviderResult[];
}

export interface HistoryItem {
  id: number;
  url: string;
  overall_score: number;
  confidence: number;
  created_at: string;
  report: AnalysisResponse;
}

export interface AuthResponse {
  username: string;
  is_admin?: boolean;
}

export interface ApiKeysStatus {
  has_urlscan: boolean;
  has_google_safebrowsing: boolean;
  has_virustotal: boolean;
  has_abuseipdb: boolean;
}

export interface AdminConfig {
  dimension_weights: Record<string, number>;
  providers: Record<string, { coefficient: number; dimensions: Record<string, number> }>;
}
