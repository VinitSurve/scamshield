import React, { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { StatusCard } from './components/StatusCard';
import { QuickActions } from './components/QuickActions';
import { ReportModal } from './components/ReportModal';
import { AIScamAnalyzerModal } from './components/AIScamAnalyzerModal';
import { AIExplanationModal } from './components/AIExplanationModal';
import { SafeMessaging } from '../security/safe-messaging';
import { TabStatusResponse } from '../types/messages';
import { ReputationVerdict } from '../types/threat';
import { UserSettings, DEFAULT_SETTINGS } from '../types/settings';
import { getTranslation } from '../i18n';

export const PopupApp: React.FC = () => {
  const [tabStatus, setTabStatus] = useState<TabStatusResponse | null>(null);
  const [settings, setSettings] = useState<UserSettings>(DEFAULT_SETTINGS);
  const [isLoading, setIsLoading] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [isReportOpen, setIsReportOpen] = useState(false);
  const [isAiAnalyzerOpen, setIsAiAnalyzerOpen] = useState(false);
  const [isAiExplanationOpen, setIsAiExplanationOpen] = useState(false);

  const t = getTranslation(settings.language);

  const fetchStatus = async () => {
    try {
      const [statusRes, settingsRes] = await Promise.all([
        SafeMessaging.sendToBackground<TabStatusResponse>('GET_CURRENT_TAB_STATUS'),
        SafeMessaging.sendToBackground<UserSettings>('GET_USER_SETTINGS'),
      ]);
      setTabStatus(statusRes);
      if (settingsRes) setSettings(settingsRes);
    } catch (err) {
      console.error('Failed to load popup tab status:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleManualScan = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanError(null);
    setScanMessage('Identifying active browser tab...');

    try {
      // 1. Detect active browser tab
      let activeUrl = tabStatus?.verdict.canonicalUrl;
      let activeTabId: number | undefined;

      try {
        const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (activeTab?.url) {
          activeUrl = activeTab.url;
          activeTabId = activeTab.id;
        }
      } catch {
        // Fall back to tabStatus url if tabs.query is unavailable
      }

      if (!activeUrl) {
        setScanError('Unable to identify active website URL.');
        setIsScanning(false);
        return;
      }

      // Check for internal schemes
      if (
        activeUrl.startsWith('chrome://') ||
        activeUrl.startsWith('chrome-extension://') ||
        activeUrl.startsWith('about:') ||
        activeUrl.startsWith('edge://')
      ) {
        setScanError('Internal browser pages cannot be scanned.');
        setIsScanning(false);
        return;
      }

      setScanMessage('Running multi-layer threat intelligence checks...');

      // 2. Trigger fresh live scan through background worker
      const freshVerdict = await SafeMessaging.sendToBackground<ReputationVerdict>(
        'TRIGGER_MANUAL_SCAN',
        { url: activeUrl, tabId: activeTabId },
        20000
      );

      setTabStatus((prev) => (prev ? { ...prev, verdict: freshVerdict } : null));
      setScanMessage(`Scan complete in ${freshVerdict.scanDurationMs || 0}ms`);
      setTimeout(() => setScanMessage(null), 3000);
    } catch (err: any) {
      console.error('Manual scan failed:', err);
      setScanError(err.message || 'Website scan failed. Check network connectivity.');
    } finally {
      setIsScanning(false);
    }
  };

  const handleToggleProtection = async () => {
    const updatedProtection = !settings.protectionEnabled;
    try {
      const updated = await SafeMessaging.sendToBackground<UserSettings>('UPDATE_USER_SETTINGS', {
        protectionEnabled: updatedProtection,
      });
      setSettings(updated);
      setTabStatus((prev) => (prev ? { ...prev, protectionActive: updatedProtection } : null));
    } catch (err) {
      console.error('Failed to toggle protection:', err);
    }
  };

  const handleOpenSettings = () => {
    if (chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    } else {
      window.open(chrome.runtime.getURL('options.html'));
    }
  };

  const handleOpenTestLab = () => {
    if (chrome.tabs && chrome.tabs.create) {
      chrome.tabs.create({ url: chrome.runtime.getURL('test-lab.html') });
    } else {
      window.open(chrome.runtime.getURL('test-lab.html'));
    }
  };

  if (isLoading) {
    return (
      <div className="w-[380px] h-[520px] flex items-center justify-center bg-shield-dark text-slate-400 text-xs font-mono">
        <div className="text-center space-y-2">
          <div className="w-6 h-6 border-2 border-shield-accent border-t-transparent rounded-full animate-spin mx-auto" />
          <p>Initializing ScamShield Shield...</p>
        </div>
      </div>
    );
  }

  const verdict: ReputationVerdict = tabStatus?.verdict || {
    domain: '',
    canonicalUrl: '',
    severity: 'UNKNOWN',
    category: 'UNKNOWN',
    riskScore: 0,
    evidence: ['Unable to inspect active tab'],
    source: 'FALLBACK',
    isBlocked: false,
    evaluatedAt: Date.now(),
  };

  const canExplainThreat = Boolean(
    verdict.domain &&
      (verdict.severity === 'CRITICAL' ||
        verdict.severity === 'HIGH' ||
        verdict.severity === 'SUSPICIOUS' ||
        verdict.riskScore > 0.3)
  );

  return (
    <div className="w-[380px] min-h-[520px] bg-shield-dark flex flex-col justify-between select-none">
      <div>
        <Header
          severity={verdict.severity}
          protectionActive={tabStatus?.protectionActive ?? true}
          onOpenSettings={handleOpenSettings}
          title={t.appTitle}
          tagline={t.tagline}
        />

        <StatusCard
          verdict={verdict}
          protectionActive={tabStatus?.protectionActive ?? true}
          isWhitelisted={tabStatus?.isWhitelisted ?? false}
          isScanning={isScanning}
          scanMessage={scanMessage}
          scanError={scanError}
          onScanAgain={handleManualScan}
          t={t as unknown as Record<string, string>}
        />
      </div>

      <QuickActions
        onScan={handleManualScan}
        onOpenReport={() => setIsReportOpen(true)}
        onToggleProtection={handleToggleProtection}
        onOpenTestLab={handleOpenTestLab}
        onOpenAiAnalyzer={() => setIsAiAnalyzerOpen(true)}
        onOpenAiExplanation={() => setIsAiExplanationOpen(true)}
        canExplainThreat={canExplainThreat}
        isScanning={isScanning}
        protectionActive={tabStatus?.protectionActive ?? true}
        t={t as unknown as Record<string, string>}
      />

      <ReportModal
        isOpen={isReportOpen}
        onClose={() => setIsReportOpen(false)}
        domain={verdict.domain}
        url={verdict.canonicalUrl}
        t={t as unknown as Record<string, string>}
      />

      <AIScamAnalyzerModal
        isOpen={isAiAnalyzerOpen}
        onClose={() => setIsAiAnalyzerOpen(false)}
        userLanguage={settings.language}
      />

      {canExplainThreat && (
        <AIExplanationModal
          isOpen={isAiExplanationOpen}
          onClose={() => setIsAiExplanationOpen(false)}
          url={verdict.canonicalUrl}
          domain={verdict.domain}
          severity={verdict.severity}
          riskScore={Math.round(verdict.riskScore * 100)}
          evidence={verdict.evidence}
          redirectHops={tabStatus?.redirectChain?.hops?.length}
          domIndicators={tabStatus?.heuristics?.impersonationKeywordsFound}
          userLanguage={settings.language}
        />
      )}
    </div>
  );
};
