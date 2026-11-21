import { ReputationVerdict, DomHeuristicReport, RedirectChain } from './threat';

export type ExtensionActionType =
  | 'GET_CURRENT_TAB_STATUS'
  | 'CHECK_URL_REPUTATION'
  | 'TRIGGER_MANUAL_SCAN'
  | 'REPORT_PAGE_HEURISTICS'
  | 'SUBMIT_COMMUNITY_REPORT'
  | 'GET_USER_SETTINGS'
  | 'UPDATE_USER_SETTINGS'
  | 'OVERRIDE_THREAT_BLOCK'
  | 'CLEAR_LOCAL_CACHE';

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
