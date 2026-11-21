import { OFFLINE_MALICIOUS_THREATS } from '../storage/cache-service';
import { logger } from '../utils/logger';

export class DnrManager {
  private static readonly RULE_ID_START = 1000;

  /**
   * Synchronize high-confidence malicious domains into Chrome DeclarativeNetRequest dynamic rules
   */
  static async syncRules(enabled = true): Promise<void> {
    if (!chrome.declarativeNetRequest) {
      logger.warn('DeclarativeNetRequest API not supported in this browser context');
      return;
    }

    try {
      // 1. Get existing dynamic rule IDs to remove them first
      const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
      const existingRuleIds = existingRules.map((r) => r.id);

      if (!enabled) {
        if (existingRuleIds.length > 0) {
          await chrome.declarativeNetRequest.updateDynamicRules({
            removeRuleIds: existingRuleIds,
          });
          logger.info('DNR blocking rules disabled and cleared');
        }
        return;
      }

      // 2. Build new rules from verified offline threat dataset
      const domains = Object.keys(OFFLINE_MALICIOUS_THREATS);
      const newRules: chrome.declarativeNetRequest.Rule[] = domains.map((domain, index) => {
        return {
          id: this.RULE_ID_START + index,
          priority: 1,
          action: {
            type: 'redirect' as chrome.declarativeNetRequest.RuleActionType,
            redirect: {
              extensionPath: `/interstitial.html?url=https://${encodeURIComponent(domain)}/&reason=OFFLINE_BLOCKLIST`,
            },
          },
          condition: {
            urlFilter: `||${domain}^`,
            resourceTypes: ['main_frame' as chrome.declarativeNetRequest.ResourceType],
          },
        };
      });

      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existingRuleIds,
        addRules: newRules,
      });

      logger.info(`Successfully synchronized ${newRules.length} declarativeNetRequest dynamic threat rules`);
    } catch (err) {
      logger.error('Failed to update declarativeNetRequest dynamic rules:', err);
    }
  }
}
