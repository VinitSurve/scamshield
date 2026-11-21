import { ReputationVerdict, ThreatCategory, ThreatSeverity } from '../types/threat';

export interface OCRTextBlock {
  text: string;
  confidence?: number;
  bbox?: { x0: number; y0: number; x1: number; y1: number };
}

export interface OCRResult {
  extractedText: string;
  language?: string;
  confidence?: number;
  processingTimeMs: number;
  blocks?: OCRTextBlock[];
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED';
  errors?: string[];
  sourceEngine: 'LOCAL_TESSERACT' | 'LOCAL_CANVAS' | 'AI_VISION';
}

export interface ExtractedUrlIndicator {
  original: string;
  normalized: string;
  isShortener: boolean;
  domain: string;
  reputationVerdict?: ReputationVerdict;
}

export interface ExtractedPhoneIndicator {
  original: string;
  normalized: string;
  isIndian: boolean;
  carrierRegion?: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  riskReason?: string;
}

export interface ExtractedUpiIndicator {
  original: string;
  normalized: string;
  handle: string;
  provider: string;
  isSuspiciousKeyword: boolean;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  riskReason?: string;
}

export interface ExtractedQrIndicator {
  rawData: string;
  type: 'URL' | 'UPI' | 'TEXT' | 'OTHER';
  decodedUrl?: string;
  decodedUpi?: ExtractedUpiIndicator;
  reputationVerdict?: ReputationVerdict;
}

export interface ExtractedEmailIndicator {
  original: string;
  domain: string;
  isFreeProvider: boolean;
  isBrandImpersonating: boolean;
  impersonatedBrand?: string;
}

export interface ExtractedIndicators {
  urls: ExtractedUrlIndicator[];
  phones: ExtractedPhoneIndicator[];
  upiIds: ExtractedUpiIndicator[];
  emails: ExtractedEmailIndicator[];
  qrCodes: ExtractedQrIndicator[];
  socialEngineeringTactics: string[];
}

export interface ImageScamAnalysisResult {
  scanId: string;
  timestamp: number;
  durationMs: number;
  imageMetadata: {
    name?: string;
    sizeBytes: number;
    width?: number;
    height?: number;
    mimeType: string;
  };
  ocrResult: OCRResult;
  indicators: ExtractedIndicators;
  scamClassification: {
    category: ThreatCategory;
    confidenceScore: number; // 0 to 1
    riskLevel: ThreatSeverity;
    urgencyLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH';
    primaryThreatSummary: string;
    socialEngineeringTactics: string[];
  };
  securityChecks: {
    urlChecks: { url: string; verdict: string; riskScore: number; isBlocked: boolean }[];
    phoneChecks: { phone: string; risk: string; reason?: string }[];
    upiChecks: { upiId: string; risk: string; reason?: string }[];
    qrChecks: { type: string; target: string; verdict?: string }[];
    brandImpersonation?: { detected: boolean; brand?: string; matchedKeyword?: string };
  };
  aiInsights?: {
    used: boolean;
    provider?: string;
    model?: string;
    explanation?: string;
  };
  verdict: ThreatSeverity;
  overallRiskScore: number; // 0 to 100
  recommendedActions: string[];
}
