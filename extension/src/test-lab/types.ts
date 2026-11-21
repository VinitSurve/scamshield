import { ThreatCategory, ThreatSeverity, ReputationVerdict, RedirectChain } from '../types/threat';

export type TestCaseId =
  | 'LEGIT_GOOGLE'
  | 'LEGIT_GITHUB'
  | 'LEGIT_MICROSOFT'
  | 'LEGIT_AMAZON_IN'
  | 'IMPERSONATION_SBI'
  | 'IMPERSONATION_HDFC'
  | 'IMPERSONATION_PHONEPE'
  | 'MALICIOUS_OFFLINE_KYC'
  | 'SIMULATED_REDIRECT_CHAIN'
  | 'INVALID_URL_SAFETY';

export interface TestCase {
  id: TestCaseId;
  title: string;
  categoryLabel: 'Legitimate Mainstream' | 'Brand Impersonation' | 'Known Threat Fixture' | 'Redirect Chain' | 'Input Resilience';
  targetUrl: string;
  description: string;
  expectedSeverity: ThreatSeverity | ThreatSeverity[];
  expectedCategory: ThreatCategory | ThreatCategory[];
  expectedSource?: string;
  isRedirectSimulation?: boolean;
  simulationHops?: string[];
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
