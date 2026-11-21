export type ThreatSeverity = 'SAFE' | 'UNKNOWN' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';

export type ThreatCategory =
  | 'PHISHING'
  | 'MALWARE'
  | 'FAKE_KYC'
  | 'UPI_FRAUD'
  | 'DECEPTIVE_REDIRECT'
  | 'GOV_IMPERSONATION'
  | 'LOTTERY_SCAM'
  | 'SUSPICIOUS_LOGIN'
  | 'LEGITIMATE'
  | 'UNKNOWN';

export type ReputationSource =
  | 'LOCAL_CACHE'
  | 'TRANCO_ANCHOR'
  | 'REMOTE_API'
  | 'HEURISTIC'
  | 'OFFLINE_RULE'
  | 'AI_DIAGNOSTIC'
  | 'FALLBACK';

export interface ThreatEvidenceItem {
  id: string;
  description: string;
  severity: ThreatSeverity;
  timestamp: number;
}

export interface ReputationVerdict {
  domain: string;
  canonicalUrl: string;
  severity: ThreatSeverity;
  category: ThreatCategory;
  riskScore: number; // 0.00 to 1.00
  evidence: string[];
  impersonatedBrand?: string;
  communityReportCount?: number;
  source: ReputationSource;
  isBlocked: boolean;
  evaluatedAt: number;
}

export interface RedirectHop {
  hopNumber: number;
  url: string;
  domain: string;
  statusCode?: number;
  isSuspicious: boolean;
  reason?: string;
}

export interface RedirectChain {
  tabId: number;
  originalUrl: string;
  originalDomain: string;
  hops: RedirectHop[];
  finalUrl?: string;
  finalDomain?: string;
  isCrossDomain: boolean;
  hasSuspiciousHop: boolean;
  isBlocked: boolean;
  startedAt: number;
  lastUpdatedAt: number;
}

export interface DomHeuristicReport {
  domain: string;
  url: string;
  hasPasswordField: boolean;
  hasCreditCardField: boolean;
  hasOtpField: boolean;
  formCount: number;
  impersonationKeywordsFound: string[];
  externalFormAction?: string;
  hasPunycode: boolean;
}
