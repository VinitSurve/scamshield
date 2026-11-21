/**
 * ScamShield AI Engine — Types and Schema Definitions
 */

export type AIProviderId = 'gemini' | 'groq';

export type KeyHealthStatus = 'healthy' | 'cooling_down' | 'invalid' | 'disabled';

export type AIErrorCategory =
  | 'RATE_LIMIT'
  | 'AUTH_ERROR'
  | 'PERMISSION'
  | 'BAD_REQUEST'
  | 'SERVER_ERROR'
  | 'TIMEOUT'
  | 'NETWORK_ERROR'
  | 'MALFORMED_RESPONSE'
  | 'NO_KEYS_AVAILABLE'
  | 'UNKNOWN';

export interface AIKeyConfig {
  id: string;
  provider: AIProviderId;
  key: string; // Stored securely in chrome.storage.local, masked on UI
  label?: string;
  enabled: boolean;
  status: KeyHealthStatus;
  usageCount: number;
  failureCount: number;
  rateLimitCount: number;
  lastUsedAt?: number;
  lastSuccessAt?: number;
  lastErrorAt?: number;
  lastErrorCategory?: AIErrorCategory;
  lastErrorMessage?: string;
  cooldownUntil?: number; // Timestamp (ms) until which key is in cooldown
}

export interface MaskedAIKey {
  id: string;
  provider: AIProviderId;
  maskedKey: string;
  label?: string;
  enabled: boolean;
  status: KeyHealthStatus;
  usageCount: number;
  failureCount: number;
  rateLimitCount: number;
  lastUsedAt?: number;
  lastSuccessAt?: number;
  lastErrorAt?: number;
  lastErrorCategory?: AIErrorCategory;
  lastErrorMessage?: string;
  cooldownRemainingSeconds?: number;
}

export interface ProviderHealthStats {
  providerId: AIProviderId;
  name: string;
  status: 'operational' | 'degraded' | 'exhausted' | 'unconfigured';
  totalKeys: number;
  healthyKeys: number;
  coolingDownKeys: number;
  invalidKeys: number;
  totalRequests: number;
  totalSuccesses: number;
  totalFailures: number;
  totalRateLimits: number;
  lastSuccessfulRequestAt?: number;
}

export interface AIProviderConfig {
  enabled: boolean;
  selectedModel: string;
  availableModels: string[];
}

export interface AISystemSettings {
  enabled: boolean;
  primaryProvider: AIProviderId;
  fallbackEnabled: boolean;
  keyRotationEnabled: boolean;
  requestTimeoutMs: number;
  maxRetriesPerKey: number;
  providers: Record<AIProviderId, AIProviderConfig>;
}

export const DEFAULT_AI_SETTINGS: AISystemSettings = {
  enabled: true,
  primaryProvider: 'gemini',
  fallbackEnabled: true,
  keyRotationEnabled: true,
  requestTimeoutMs: 15000,
  maxRetriesPerKey: 1,
  providers: {
    gemini: {
      enabled: true,
      selectedModel: 'gemini-1.5-flash',
      availableModels: ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.0-flash'],
    },
    groq: {
      enabled: true,
      selectedModel: 'llama-3.3-70b-versatile',
      availableModels: [
        'llama-3.3-70b-versatile',
        'qwen/qwen3.8-27b',
        'llama-3.1-8b-instant',
        'mixtral-8x7b-32768',
      ],
    },
  },
};

// ==========================================
// Structured Analysis Request & Response
// ==========================================

export type ScamClassification = 'SAFE' | 'SUSPICIOUS' | 'SCAM' | 'MALICIOUS' | 'UNKNOWN';
export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ScamIndicator {
  type: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH';
}

export interface ExtractedEntities {
  brandImpersonated?: string;
  suspiciousUrls?: string[];
  paymentRequests?: string[];
  requestedActions?: string[];
}

export interface StructuredScamAnalysis {
  success: boolean;
  classification: ScamClassification;
  riskLevel: RiskSeverity;
  confidenceScore: number; // 0.0 to 1.0
  scamCategory: string; // e.g., 'BANKING_KYC', 'UPI_FRAUD', 'LOTTERY_SCAM', 'JOB_OFFER'
  summary: string;
  socialEngineeringTactics: string[]; // e.g., ['Urgency', 'Authority', 'Fear of penalty']
  indicators: ScamIndicator[];
  extractedEntities: ExtractedEntities;
  recommendedActions: string[];
  explanation: string;
  providerUsed?: AIProviderId;
  modelUsed?: string;
  latencyMs?: number;
  fallbackOccurred?: boolean;
  error?: string;
}

export interface MessageAnalysisRequest {
  messageText: string;
  sourceType?: 'SMS' | 'WHATSAPP' | 'EMAIL' | 'SOCIAL_MEDIA' | 'SCREENSHOT_OCR' | 'OTHER';
  userLanguage?: 'en' | 'hi' | 'mr';
}

export interface UrlEvidenceExplanationRequest {
  url: string;
  domain: string;
  verdictSeverity: string;
  riskScore: number;
  evidence: string[];
  redirectHops?: number;
  domIndicators?: string[];
  userLanguage?: 'en' | 'hi' | 'mr';
}

export interface UrlEvidenceExplanation {
  success: boolean;
  summary: string;
  dangerLevel: RiskSeverity;
  tacticsDetected: string[];
  safetyGuidance: string[];
  providerUsed?: AIProviderId;
  latencyMs?: number;
}

export interface KeyValidationResult {
  valid: boolean;
  providerId: AIProviderId;
  statusCode?: number;
  errorCategory?: AIErrorCategory;
  sanitizedMessage: string;
  latencyMs: number;
}
