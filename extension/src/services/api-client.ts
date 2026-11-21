import { PrefixLookupResponse, AnalyzeUrlResponse, CreateReportRequest, CreateReportResponse } from '../types/api';
import { logger } from '../utils/logger';

export class ApiClient {
  private baseUrl: string;
  private timeoutMs: number;

  constructor(baseUrl = 'https://api.scamshield.org', timeoutMs = 4000) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
    this.timeoutMs = timeoutMs;
  }

  private async fetchWithTimeout<T>(path: string, options: RequestInit = {}): Promise<T | null> {
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
        return null;
      }

      return (await response.json()) as T;
    } catch (err: unknown) {
      clearTimeout(timer);
      if (err instanceof Error && err.name === 'AbortError') {
        logger.warn(`API request to ${path} timed out after ${this.timeoutMs}ms`);
      } else {
        logger.debug(`API request to ${path} failed (offline/unreachable):`, err);
      }
      return null;
    }
  }

  /**
   * k-Anonymity 32-bit Prefix Lookup
   * Only transmits the 8-character hex prefix, never the full URL or domain.
   */
  async getPrefixMatches(prefix: string): Promise<PrefixLookupResponse | null> {
    if (!prefix || prefix.length !== 8) {
      logger.error('Invalid prefix provided for k-anonymity lookup:', prefix);
      return null;
    }
    return this.fetchWithTimeout<PrefixLookupResponse>(`/api/v1/reputation/prefix/${prefix}`);
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
