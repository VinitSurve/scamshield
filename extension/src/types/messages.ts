import { ReputationVerdict, DomHeuristicReport, RedirectChain } from './threat';
import { AIProviderId } from '../ai/types';

export type ExtensionActionType =
  | 'GET_CURRENT_TAB_STATUS'
  | 'CHECK_URL_REPUTATION'
  | 'TRIGGER_MANUAL_SCAN'
  | 'REPORT_PAGE_HEURISTICS'
  | 'SUBMIT_COMMUNITY_REPORT'
  | 'GET_USER_SETTINGS'
  | 'UPDATE_USER_SETTINGS'
  | 'OVERRIDE_THREAT_BLOCK'
  | 'CLEAR_LOCAL_CACHE'
  // AI Engine Action Types
  | 'AI_ANALYZE_MESSAGE'
  | 'AI_EXPLAIN_URL_THREAT'
  | 'AI_GET_CONFIG'
  | 'AI_UPDATE_CONFIG'
  | 'AI_GET_KEYS'
  | 'AI_ADD_KEY'
  | 'AI_REMOVE_KEY'
  | 'AI_TOGGLE_KEY'
  | 'AI_RESET_KEY_STATUS'
  | 'AI_TEST_KEY'
  | 'AI_TEST_RAW_KEY'
  | 'AI_GET_HEALTH_STATS';

export interface BaseExtensionMessage<T = unknown> {
  type: ExtensionActionType;
  payload: T;
  timestamp: number;
}

export interface TabStatusPayload {
  tabId?: number;
  url?: string;
}

export interface TabStatusResponse {
  verdict: ReputationVerdict;
  redirectChain?: RedirectChain;
  protectionActive: boolean;
  isWhitelisted: boolean;
  heuristics?: DomHeuristicReport;
}

export interface CommunityReportPayload {
  url: string;
  domain: string;
  threatCategory: string;
  description: string;
  evidenceMetadata?: Record<string, unknown>;
}

export interface CommunityReportResponse {
  success: boolean;
  reportId?: string;
  message: string;
  isDemo?: boolean;
}

export interface ThreatBlockOverridePayload {
  domain: string;
  url: string;
  bypassDurationMinutes?: number;
}

// AI Message Payloads
export interface AIAddKeyPayload {
  provider: AIProviderId;
  key: string;
  label?: string;
}

export interface AITestKeyPayload {
  keyId: string;
}

export interface AITestRawKeyPayload {
  providerId: AIProviderId;
  rawKey: string;
  model?: string;
}

export interface AIToggleKeyPayload {
  keyId: string;
  enabled: boolean;
}

export interface AIResetKeyPayload {
  keyId: string;
}
