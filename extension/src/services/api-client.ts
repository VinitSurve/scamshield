import { PrefixLookupResponse, AnalyzeUrlResponse, CreateReportRequest, CreateReportResponse } from '../types/api';
import { logger } from '../utils/logger';

export interface ApiResponse<T> {
  success: boolean;
  data: T | null;
  status: number;
  error?: string;
  isTimeout?: boolean;
  isOffline?: boolean;
}

export class ApiClient {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(baseUrl = 'https://api.scamshield.org', timeoutMs = 4000) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
  }

  private async fetchWithDetails<T>(path: string, options: RequestInit = {}): Promise<ApiResponse<T>> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const url = `${this.baseUrl}${path.startsWith('/') ? path : `/${path}`}`;
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-Client-App': 'ScamShield-Chrome-Extension',
          'X-Client-Version': '1.0.0',
          ...(options.headers || {}),
        },
      });

      clearTimeout(timer);

      if (!response.ok) {
        logger.warn(`API request to ${path} failed with status: ${response.status}`);
        return {
          success: false,
          data: null,
          status: response.status,
          error: `API returned HTTP ${response.status}`,
        };
      }

      const data = (await response.json()) as T;
      return {
        success: true,
        data,
        status: response.status,
      };
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof Error && err.name === 'AbortError') {
        logger.warn(`API request to ${path} timed out after ${this.timeoutMs}ms`);
        return {
          success: false,
          data: null,
          status: 0,
          isTimeout: true,
          error: `Request timed out after ${this.timeoutMs}ms`,
        };
      } else {
        logger.debug(`API request to ${path} failed (offline/unreachable):`, err);
        return {
          success: false,
          data: null,
          status: 0,
          isOffline: true,
          error: err instanceof Error ? err.message : 'Network offline / connection refused',
        };
      }
    }
  }

  private async fetchWithTimeout<T>(path: string, options: RequestInit = {}): Promise<T | null> {
    const res = await this.fetchWithDetails<T>(path, options);
    return res.data;
  }

  /**
   * k-Anonymity 32-bit Prefix Lookup with detailed response structure
   */
  async getPrefixLookup(prefix: string): Promise<ApiResponse<PrefixLookupResponse>> {
    if (!prefix || prefix.length !== 8) {
      logger.error('Invalid prefix provided for k-anonymity lookup:', prefix);
      return {
        success: false,
        data: null,
        status: 400,
        error: 'Invalid prefix format: must be 8 hexadecimal characters',
      };
    }
    return this.fetchWithDetails<PrefixLookupResponse>(`/api/v1/reputation/prefix/${prefix}`);
  }

  /**
   * k-Anonymity 32-bit Prefix Lookup
   * Only transmits the 8-character hex prefix, never the full URL or domain.
   */
  async getPrefixMatches(prefix: string): Promise<PrefixLookupResponse | null> {
    const res = await this.getPrefixLookup(prefix);
    return res.data;
  }

  /**
   * Explicit URL Deep Analysis
   */
  async analyzeUrl(rawUrl: string): Promise<AnalyzeUrlResponse | null> {
    return this.fetchWithTimeout<AnalyzeUrlResponse>('/api/v1/analyze/url', {
      method: 'POST',
      body: JSON.stringify({
        url: rawUrl,
        caller: 'extension',
        timestamp: new Date().toISOString(),
      }),
    });
  }

  /**
   * Submit Community Threat Report
   */
  async submitReport(report: CreateReportRequest): Promise<CreateReportResponse | null> {
    return this.fetchWithTimeout<CreateReportResponse>('/api/v1/reports', {
      method: 'POST',
      body: JSON.stringify(report),
    });
  }
}
