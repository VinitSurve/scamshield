import { CommunityReportPayload, CommunityReportResponse } from '../types/messages';
import { CreateReportRequest } from '../types/api';
import { ApiClient } from './api-client';
import { SettingsService } from '../storage/settings-service';
import { CacheService } from '../storage/cache-service';
import { generateRandomId } from '../utils/crypto';
import { logger } from '../utils/logger';

const PENDING_REPORTS_KEY = 'scamshield_pending_reports';

export class ReportService {
  static async submitReport(payload: CommunityReportPayload): Promise<CommunityReportResponse> {
    if (!payload.url || !payload.domain) {
      return {
        success: false,
        message: 'Invalid report: URL and Domain are required.',
      };
    }

    const settings = await SettingsService.getSettings();
    const client = new ApiClient(settings.apiBaseUrl);

    const reportReq: CreateReportRequest = {
      indicator_type: 'DOMAIN',
      indicator_value: payload.domain,
      threat_category: payload.threatCategory || 'PHISHING',
      description: payload.description || 'Reported via ScamShield Extension Popup',
      evidence_metadata: {
        raw_url: payload.url,
        reported_at: new Date().toISOString(),
        ...(payload.evidenceMetadata || {}),
      },
    };

    // If demo mode is active
    if (settings.demoMode) {
      const demoId = generateRandomId('demo_rep');
      await this.saveLocalReport(reportReq, demoId);
      await this.applyLocalReportSuspicion(payload.domain, payload.threatCategory);

      return {
        success: true,
        reportId: demoId,
        message: 'Report recorded in local demonstration queue.',
        isDemo: true,
      };
    }

    // Try submitting to ScamShield Backend API
    try {
      const response = await client.submitReport(reportReq);
      if (response && response.report_id) {
        // Immediate local reinforcement
        await this.applyLocalReportSuspicion(payload.domain, payload.threatCategory);

        return {
          success: true,
          reportId: response.report_id,
          message: 'Report successfully submitted to ScamShield Intelligence Network.',
          isDemo: false,
        };
      }
    } catch (err) {
      logger.warn('Failed to submit report directly to API, queueing locally:', err);
    }

    // Offline fallback: Queue report locally in Chrome Storage
    const localId = generateRandomId('local_rep');
    await this.saveLocalReport(reportReq, localId);
    await this.applyLocalReportSuspicion(payload.domain, payload.threatCategory);

    return {
      success: true,
      reportId: localId,
      message: 'Network offline. Report saved locally and queued for synchronization.',
      isDemo: false,
    };
  }

  private static async saveLocalReport(report: CreateReportRequest, reportId: string): Promise<void> {
    try {
      const data = await chrome.storage.local.get(PENDING_REPORTS_KEY);
      const list: Array<CreateReportRequest & { id: string; savedAt: number }> =
        data[PENDING_REPORTS_KEY] || [];
      list.push({ ...report, id: reportId, savedAt: Date.now() });
      await chrome.storage.local.set({ [PENDING_REPORTS_KEY]: list });
    } catch (err) {
      logger.error('Failed to save local pending report:', err);
    }
  }

  private static async applyLocalReportSuspicion(domain: string, category: string): Promise<void> {
    const existing = CacheService.checkLocalIntelligence(domain, `https://${domain}/`);
    if (!existing || existing.severity === 'SAFE' || existing.severity === 'UNKNOWN') {
      await CacheService.set(domain, {
        domain,
        canonicalUrl: `https://${domain}/`,
        severity: 'SUSPICIOUS',
        category: (category as any) || 'PHISHING',
        riskScore: 0.78,
        evidence: [
          'Locally submitted community threat report pending multi-signal consensus',
          `Category: ${category}`,
        ],
        source: 'LOCAL_CACHE',
        isBlocked: false,
        evaluatedAt: Date.now(),
      });
    }
  }
}
