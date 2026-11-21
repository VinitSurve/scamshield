import { ThreatCategory, ThreatSeverity } from './threat';

export interface ThreatPrefixMatch {
  full_hash: string;
  threat_type: ThreatCategory;
  severity: ThreatSeverity;
  impersonated_brand?: string;
  reported_count?: number;
  updated_at: string;
}

export interface PrefixLookupResponse {
  prefix: string;
  matches: ThreatPrefixMatch[];
}

export interface AnalyzeUrlRequest {
  url: string;
  caller: 'extension';
  timestamp: string;
}

export interface AnalyzeUrlResponse {
  url: string;
  domain: string;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNKNOWN';
  category: ThreatCategory;
  risk_score: number;
  evidence: string[];
  impersonated_brand?: string;
  community_report_count: number;
}

export interface CreateReportRequest {
  indicator_type: 'URL' | 'DOMAIN';
  indicator_value: string;
  threat_category: string;
  description: string;
  evidence_metadata?: Record<string, unknown>;
}

export interface CreateReportResponse {
  report_id: string;
  status: 'RECORDED' | 'QUEUED';
  current_community_score: number;
  message: string;
}
