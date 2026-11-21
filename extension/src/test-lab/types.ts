import { ThreatCategory, ThreatSeverity, ReputationVerdict, RedirectChain } from '../types/threat';

export type TestCaseId =
  | 'LEGIT_GOOGLE'
  | 'LEGIT_GITHUB'
  | 'LEGIT_MICROSOFT'
  | 'LEGIT_AMAZON_IN'
  | 'LEGIT_LINKEDIN'
  | 'IMPERSONATION_SBI'
  | 'IMPERSONATION_HDFC'
  | 'IMPERSONATION_PHONEPE'
  | 'MALICIOUS_OFFLINE_KYC'
  | 'MALWARE_GOOGLE_TEST_URL'
  | 'CLEAN_DOMAIN_CLEAN_PATH'
  | 'SIMULATED_REDIRECT_CHAIN'
  | 'INVALID_URL_SAFETY'
  | 'IMAGE_KYC_PHISHING_SCAN'
  | 'IMAGE_UPI_FRAUD_SCAN'
  | 'WHATSAPP_BOT_DEMO_PIPELINE'
  | 'AI_KEY_ROTATION'
  | 'AI_RATE_LIMIT_COOLDOWN'
  | 'AI_PROVIDER_FALLBACK'
  | 'AI_SCAM_PARSING';

export type TestCaseCategory =
  | 'Legitimate Mainstream'
  | 'Brand Impersonation'
  | 'Known Threat Fixture'
  | 'Redirect Chain'
  | 'Input Resilience'
  | 'Image Scam Diagnostic'
  | 'WhatsApp Bot Diagnostic'
  | 'AI Engine Diagnostic';

export interface TestCase {
  id: TestCaseId;
  title: string;
  categoryLabel: TestCaseCategory;
  targetUrl: string;
  description: string;
  expectedSeverity: ThreatSeverity | ThreatSeverity[];
  expectedCategory: ThreatCategory | ThreatCategory[];
  expectedSource?: string | string[];
  isRedirectSimulation?: boolean;
  simulationHops?: string[];
  isAiDiagnostic?: boolean;
  aiTestType?: 'ROTATION' | 'RATE_LIMIT' | 'FALLBACK' | 'PARSER';
  isImageDiagnostic?: boolean;
  isWhatsAppDiagnostic?: boolean;
}

export type TestExecutionStatus = 'IDLE' | 'RUNNING' | 'PASS' | 'FAIL' | 'WARNING';

export interface TestResult {
  testCase: TestCase;
  status: TestExecutionStatus;
  actualVerdict?: ReputationVerdict;
  actualRedirectChain?: RedirectChain;
  durationMs: number;
  notes: string[];
  executedAt?: number;
}
