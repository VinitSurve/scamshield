import { SafeMessaging } from '../security/safe-messaging';
import { BaseExtensionMessage, TabStatusResponse } from '../types/messages';
import { ReputationService } from '../services/reputation-service';
import { ReportService } from '../services/report-service';
import { SettingsService } from '../storage/settings-service';
import { CacheService } from '../storage/cache-service';
import { NavigationMonitor } from './navigation-monitor';
import { RedirectTracker } from './redirect-tracker';
import { DnrManager } from './dnr-manager';
import { AIService } from '../ai/ai-service';
import { canonicalizeUrl } from '../security/url-validator';
import { logger } from '../utils/logger';

// 1. Initialize Navigation Interception Engine
NavigationMonitor.initialize();

// 2. Extension Installation & Startup Hooks
chrome.runtime.onInstalled.addListener(async (details) => {
  logger.info(`ScamShield Extension installed / updated: ${details.reason}`);
  const settings = await SettingsService.getSettings();
  await DnrManager.syncRules(settings.enableDnrBlocking && settings.protectionEnabled);

  // Initialize Right-Click Context Menus
  try {
    if (chrome.contextMenus) {
      chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({
          id: 'scamshield_scan_image',
          title: 'Scan image with ScamShield',
          contexts: ['image'],
        });
        chrome.contextMenus.create({
          id: 'scamshield_scan_link',
          title: 'Scan link with ScamShield',
          contexts: ['link'],
        });
        chrome.contextMenus.create({
          id: 'scamshield_scan_selection',
          title: 'Analyze suspicious text with ScamShield',
          contexts: ['selection'],
        });
      });
    }
  } catch (err) {
    logger.debug('Context menu registration skipped:', err);
  }
});

// Handle Context Menu Actions
if (chrome.contextMenus?.onClicked) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    try {
      if (info.menuItemId === 'scamshield_scan_link' && info.linkUrl) {
        const verdict = await ReputationService.evaluateUrl(info.linkUrl, true);
        if (verdict.isBlocked && tab?.id) {
          const warningUrl = chrome.runtime.getURL(`interstitial.html?blockedUrl=${encodeURIComponent(info.linkUrl)}&category=${encodeURIComponent(verdict.category)}&severity=${encodeURIComponent(verdict.severity)}`);
          chrome.tabs.update(tab.id, { url: warningUrl });
        }
      } else if (info.menuItemId === 'scamshield_scan_selection' && info.selectionText) {
        // Open options or message scan view
        chrome.runtime.openOptionsPage?.();
      } else if (info.menuItemId === 'scamshield_scan_image' && info.srcUrl) {
        chrome.runtime.openOptionsPage?.();
      }
    } catch (err) {
      logger.error('Error executing context menu action:', err);
    }
  });
}

chrome.runtime.onStartup.addListener(async () => {
  logger.info('ScamShield Background Service Worker started');
  const settings = await SettingsService.getSettings();
  await DnrManager.syncRules(settings.enableDnrBlocking && settings.protectionEnabled);
});

// 3. Centralized Typed Runtime Message Listener
chrome.runtime.onMessage.addListener((message: BaseExtensionMessage, sender, sendResponse) => {
  // Security Verification: Reject external, unauthorized senders
  if (!SafeMessaging.isTrustedSender(sender)) {
    logger.warn('Rejected untrusted message origin:', sender.id, sender.url);
    sendResponse({ error: 'Unauthorized message sender' });
    return false;
  }

  // Handle typed actions asynchronously
  handleExtensionMessage(message, sender)
    .then((result) => sendResponse(result))
    .catch((err) => {
      logger.error(`Error handling action ${message.type}:`, err);
      sendResponse({ error: err instanceof Error ? err.message : 'Internal error' });
    });

  // Return true to indicate asynchronous response
  return true;
});

async function handleExtensionMessage(
  message: BaseExtensionMessage,
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  switch (message.type) {
    case 'GET_CURRENT_TAB_STATUS': {
      // Find current active tab if not specified
      let tabId = (message.payload as any)?.tabId;
      let tabUrl = (message.payload as any)?.url;

      if (!tabId || !tabUrl) {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (activeTab) {
          tabId = activeTab.id;
          tabUrl = activeTab.url;
        }
      }

      if (!tabUrl) {
        return {
          verdict: {
            domain: '',
            canonicalUrl: '',
            severity: 'UNKNOWN',
            category: 'UNKNOWN',
            riskScore: 0,
            evidence: ['No active tab detected'],
            source: 'FALLBACK',
            isBlocked: false,
            evaluatedAt: Date.now(),
          },
          protectionActive: true,
          isWhitelisted: false,
        } as TabStatusResponse;
      }

      const canonical = canonicalizeUrl(tabUrl);
      const verdict = await ReputationService.evaluateUrl(tabUrl);
      const redirectChain = tabId ? RedirectTracker.getChain(tabId) : undefined;
      const settings = await SettingsService.getSettings();
      const isWhitelisted = canonical.domain
        ? await SettingsService.isDomainWhitelisted(canonical.domain)
        : false;

      return {
        verdict,
        redirectChain,
        protectionActive: settings.protectionEnabled,
        isWhitelisted,
      } as TabStatusResponse;
    }

    case 'CHECK_URL_REPUTATION': {
      const url = (message.payload as any)?.url;
      if (!url) throw new Error('Missing URL parameter');
      return ReputationService.evaluateUrl(url);
    }

    case 'TRIGGER_MANUAL_SCAN': {
      let url = (message.payload as any)?.url;
      const tabId = (message.payload as any)?.tabId;

      if (!url && tabId) {
        try {
          const tab = await chrome.tabs.get(tabId);
          url = tab?.url;
        } catch {
          // Fall through to active tab query
        }
      }

      if (!url) {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        url = activeTab?.url;
      }

      if (!url) throw new Error('No active website detected to scan');
      // Force fresh live evaluation by skipping cache
      return ReputationService.evaluateUrl(url, true);
    }

    case 'REPORT_PAGE_HEURISTICS': {
      const heuristics = message.payload as any;
      if (heuristics && heuristics.domain) {
        logger.debug('Received DOM heuristics from tab:', sender.tab?.id, heuristics);

        // If high-risk credential form found on unverified domain, elevate suspicion
        if (heuristics.hasPasswordField && heuristics.impersonationKeywordsFound?.length > 0) {
          const cached = CacheService.checkLocalIntelligence(heuristics.domain, heuristics.url);
          if (!cached || cached.severity === 'UNKNOWN' || cached.severity === 'SAFE') {
            await CacheService.set(heuristics.domain, {
              domain: heuristics.domain,
              canonicalUrl: heuristics.url,
              severity: 'HIGH',
              category: 'SUSPICIOUS_LOGIN',
              riskScore: 0.88,
              evidence: [
                'In-Browser Heuristic: Password field detected on unverified domain',
                `Contains brand impersonation keyword(s): ${heuristics.impersonationKeywordsFound.join(', ')}`,
              ],
              source: 'HEURISTIC',
              isBlocked: false,
              evaluatedAt: Date.now(),
            });
          }
        }
      }
      return { received: true };
    }

    case 'SUBMIT_COMMUNITY_REPORT': {
      return ReportService.submitReport(message.payload as any);
    }

    case 'GET_USER_SETTINGS': {
      return SettingsService.getSettings();
    }

    case 'UPDATE_USER_SETTINGS': {
      const updated = await SettingsService.saveSettings(message.payload as any);
      await DnrManager.syncRules(updated.enableDnrBlocking && updated.protectionEnabled);
      return updated;
    }

    case 'OVERRIDE_THREAT_BLOCK': {
      const { domain, durationMinutes } = message.payload as any;
      if (!domain) throw new Error('Missing domain parameter for block override');
      NavigationMonitor.grantBypass(domain, durationMinutes || 15);
      return { success: true, bypassedDomain: domain };
    }

    case 'CLEAR_LOCAL_CACHE': {
      await CacheService.clearAll();
      return { success: true };
    }

    // AI Engine Handlers
    case 'AI_ANALYZE_MESSAGE': {
      return AIService.analyzeMessage(message.payload as any);
    }

    case 'AI_EXPLAIN_URL_THREAT': {
      return AIService.explainUrlThreat(message.payload as any);
    }

    case 'AI_GET_CONFIG': {
      return AIService.getSettings();
    }

    case 'AI_UPDATE_CONFIG': {
      return AIService.updateSettings(message.payload as any);
    }

    case 'AI_GET_KEYS': {
      const provider = (message.payload as any)?.provider;
      return AIService.getMaskedKeys(provider);
    }

    case 'AI_ADD_KEY': {
      const { provider, key, label } = message.payload as any;
      if (!provider || !key) throw new Error('Missing provider or key parameter');
      return AIService.addKey(provider, key, label);
    }

    case 'AI_REMOVE_KEY': {
      const { keyId } = message.payload as any;
      if (!keyId) throw new Error('Missing keyId parameter');
      return AIService.removeKey(keyId);
    }

    case 'AI_TOGGLE_KEY': {
      const { keyId, enabled } = message.payload as any;
      if (!keyId) throw new Error('Missing keyId parameter');
      return AIService.toggleKey(keyId, enabled);
    }

    case 'AI_RESET_KEY_STATUS': {
      const { keyId } = message.payload as any;
      if (!keyId) throw new Error('Missing keyId parameter');
      return AIService.resetKeyStatus(keyId);
    }

    case 'AI_TEST_KEY': {
      const { keyId } = message.payload as any;
      if (!keyId) throw new Error('Missing keyId parameter');
      return AIService.testKeyById(keyId);
    }

    case 'AI_TEST_RAW_KEY': {
      const { providerId, rawKey, model } = message.payload as any;
      if (!providerId || !rawKey) throw new Error('Missing providerId or rawKey parameter');
      return AIService.testRawKey(providerId, rawKey, model);
    }

    case 'AI_GET_HEALTH_STATS': {
      return AIService.getHealthStats();
    }

    default:
      throw new Error(`Unhandled message type: ${message.type}`);
  }
}
