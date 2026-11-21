import React, { useEffect, useState } from 'react';
import { Shield, Globe, Trash2, RotateCcw, Check, Plus } from 'lucide-react';
import { UserSettings, DEFAULT_SETTINGS, SupportedLanguage } from '../types/settings';
import { SafeMessaging } from '../security/safe-messaging';
import { getTranslation } from '../i18n';
import { AISettingsSection } from './components/AISettingsSection';

export const OptionsApp: React.FC = () => {
  const [settings, setSettings] = useState<UserSettings>(DEFAULT_SETTINGS);
  const [isLoading, setIsLoading] = useState(true);
  const [saveMessage, setSaveMessage] = useState<string | null>(null);
  const [newWhitelistDomain, setNewWhitelistDomain] = useState('');

  const t = getTranslation(settings.language);

  useEffect(() => {
    const loadSettings = async () => {
      try {
        const loaded = await SafeMessaging.sendToBackground<UserSettings>('GET_USER_SETTINGS');
        if (loaded) setSettings(loaded);
      } catch (err) {
        console.error('Failed to load settings:', err);
      } finally {
        setIsLoading(false);
      }
    };
    loadSettings();
  }, []);

  const handleUpdate = async (updates: Partial<UserSettings>) => {
    try {
      const updated = await SafeMessaging.sendToBackground<UserSettings>(
        'UPDATE_USER_SETTINGS',
        updates
      );
      setSettings(updated);
      setSaveMessage('Settings updated successfully');
      setTimeout(() => setSaveMessage(null), 2500);
    } catch (err) {
      console.error('Failed to update settings:', err);
    }
  };

  const handleClearCache = async () => {
    try {
      await SafeMessaging.sendToBackground('CLEAR_LOCAL_CACHE');
      setSaveMessage(t.cacheCleared);
      setTimeout(() => setSaveMessage(null), 2500);
    } catch (err) {
      console.error('Failed to clear cache:', err);
    }
  };

  const handleResetDefaults = async () => {
    if (window.confirm('Reset all ScamShield settings and whitelists to factory defaults?')) {
      await handleUpdate(DEFAULT_SETTINGS);
    }
  };

  const handleAddWhitelist = async (e: React.FormEvent) => {
    e.preventDefault();
    const domain = newWhitelistDomain.trim().toLowerCase();
    if (!domain) return;
    if (settings.whitelistedDomains.includes(domain)) return;

    const updated = [...settings.whitelistedDomains, domain];
    await handleUpdate({ whitelistedDomains: updated });
    setNewWhitelistDomain('');
  };

  const handleRemoveWhitelist = async (domain: string) => {
    const updated = settings.whitelistedDomains.filter((d) => d !== domain);
    await handleUpdate({ whitelistedDomains: updated });
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-shield-dark flex items-center justify-center text-slate-400 font-mono text-sm">
        Loading ScamShield Settings...
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto py-10 px-6 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-shield-border pb-5">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 bg-shield-accent/20 rounded-xl border border-shield-accent/30">
            <Shield className="w-6 h-6 text-shield-accent" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight">{t.settingsHeading}</h1>
            <p className="text-xs text-slate-400">{t.settingsDesc}</p>
          </div>
        </div>

        {saveMessage && (
          <div className="flex items-center space-x-1.5 px-3 py-1.5 bg-emerald-950/40 border border-emerald-800 text-emerald-300 rounded-lg text-xs font-medium animate-fade-in">
            <Check className="w-3.5 h-3.5" />
            <span>{saveMessage}</span>
          </div>
        )}
      </div>

      {/* Section 1: Core Protection Toggles */}
      <div className="bg-shield-card border border-shield-border rounded-2xl p-6 space-y-4 shadow-sm">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider">
          Proactive Threat Detection
        </h2>

        <div className="space-y-3.5 divide-y divide-shield-border/50 text-xs">
          <label className="flex items-center justify-between pt-1 cursor-pointer">
            <div>
              <span className="font-semibold text-white block">Master Protection Switch</span>
              <span className="text-slate-400">Globally enable or pause all real-time shield monitoring</span>
            </div>
            <input
              type="checkbox"
              checked={settings.protectionEnabled}
              onChange={(e) => handleUpdate({ protectionEnabled: e.target.checked })}
              className="w-4 h-4 rounded text-shield-accent bg-shield-dark border-shield-border focus:ring-0"
            />
          </label>

          <label className="flex items-center justify-between pt-3.5 cursor-pointer">
            <div>
              <span className="font-semibold text-white block">Kernel-Level Blocking (DNR)</span>
              <span className="text-slate-400">Instantly halt known malicious domains using DeclarativeNetRequest</span>
            </div>
            <input
              type="checkbox"
              checked={settings.enableDnrBlocking}
              onChange={(e) => handleUpdate({ enableDnrBlocking: e.target.checked })}
              className="w-4 h-4 rounded text-shield-accent bg-shield-dark border-shield-border focus:ring-0"
            />
          </label>

          <label className="flex items-center justify-between pt-3.5 cursor-pointer">
            <div>
              <span className="font-semibold text-white block">Redirect Protection</span>
              <span className="text-slate-400">Trace multi-hop short links and cross-origin tracking jumps</span>
            </div>
            <input
              type="checkbox"
              checked={settings.enableRedirectProtection}
              onChange={(e) => handleUpdate({ enableRedirectProtection: e.target.checked })}
              className="w-4 h-4 rounded text-shield-accent bg-shield-dark border-shield-border focus:ring-0"
            />
          </label>

          <label className="flex items-center justify-between pt-3.5 cursor-pointer">
            <div>
              <span className="font-semibold text-white block">Gmail Web Security Pill</span>
              <span className="text-slate-400">Alert on sender display name vs SMTP envelope mismatches in webmail</span>
            </div>
            <input
              type="checkbox"
              checked={settings.enableGmailProtection}
              onChange={(e) => handleUpdate({ enableGmailProtection: e.target.checked })}
              className="w-4 h-4 rounded text-shield-accent bg-shield-dark border-shield-border focus:ring-0"
            />
          </label>
        </div>
      </div>

      {/* Section 2: AI-Powered Multi-Provider Engine & Key Pool */}
      <AISettingsSection />

      {/* Section 2: Language & Localization */}
      <div className="bg-shield-card border border-shield-border rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
          <Globe className="w-4 h-4 text-shield-accent" />
          <span>Regional Language / भाषा</span>
        </h2>

        <div>
          <label className="block text-xs text-slate-300 font-medium mb-1.5">
            {t.languageLabel}
          </label>
          <div className="grid grid-cols-3 gap-3">
            {[
              { code: 'en', label: 'English' },
              { code: 'hi', label: 'हिन्दी (Hindi)' },
              { code: 'mr', label: 'मराठी (Marathi)' },
            ].map((lang) => (
              <button
                key={lang.code}
                onClick={() => handleUpdate({ language: lang.code as SupportedLanguage })}
                className={`py-2 px-3 rounded-xl border text-xs font-semibold transition-all ${
                  settings.language === lang.code
                    ? 'bg-shield-accent/20 border-shield-accent text-white shadow-sm'
                    : 'bg-shield-dark border-shield-border text-slate-400 hover:text-white'
                }`}
              >
                {lang.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Section 3: Whitelist Management */}
      <div className="bg-shield-card border border-shield-border rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider">
          Trusted Domain Whitelist
        </h2>
        <p className="text-xs text-slate-400">
          Domains added here bypass automated blocking and warning interstitials.
        </p>

        <form onSubmit={handleAddWhitelist} className="flex space-x-2">
          <input
            type="text"
            placeholder="e.g. internal-portal.corp"
            value={newWhitelistDomain}
            onChange={(e) => setNewWhitelistDomain(e.target.value)}
            className="flex-1 bg-shield-dark border border-shield-border rounded-xl px-3 py-2 text-xs text-white placeholder:text-slate-500 focus:outline-none focus:border-shield-accent"
          />
          <button
            type="submit"
            className="px-4 py-2 bg-shield-accent hover:bg-shield-accentHover text-slate-950 font-bold rounded-xl text-xs flex items-center space-x-1"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add</span>
          </button>
        </form>

        <div className="space-y-1.5 pt-1">
          {settings.whitelistedDomains.length === 0 ? (
            <p className="text-xs text-slate-500 italic">No custom whitelisted domains.</p>
          ) : (
            <div className="flex flex-wrap gap-2">
              {settings.whitelistedDomains.map((domain) => (
                <span
                  key={domain}
                  className="flex items-center space-x-1.5 px-2.5 py-1 bg-shield-dark border border-shield-border rounded-lg text-xs font-mono text-slate-300"
                >
                  <span>{domain}</span>
                  <button
                    onClick={() => handleRemoveWhitelist(domain)}
                    className="text-slate-500 hover:text-red-400 ml-1"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Section 4: Intelligence & Developer Controls */}
      <div className="bg-shield-card border border-shield-border rounded-2xl p-6 space-y-4">
        <h2 className="text-sm font-bold text-white uppercase tracking-wider">
          Intelligence Gateway & Cache
        </h2>

        <div className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-300 font-medium mb-1">
              {t.apiBaseUrlLabel}
            </label>
            <input
              type="text"
              value={settings.apiBaseUrl}
              onChange={(e) => handleUpdate({ apiBaseUrl: e.target.value })}
              className="w-full bg-shield-dark border border-shield-border rounded-xl px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-shield-accent"
            />
          </div>

          <label className="flex items-center justify-between pt-2 cursor-pointer">
            <div>
              <span className="font-semibold text-white block">{t.demoModeLabel}</span>
              <span className="text-slate-400">
                Exercise synthetic threat intelligence when ScamShield API is offline
              </span>
            </div>
            <input
              type="checkbox"
              checked={settings.demoMode}
              onChange={(e) => handleUpdate({ demoMode: e.target.checked })}
              className="w-4 h-4 rounded text-shield-accent bg-shield-dark border-shield-border focus:ring-0"
            />
          </label>

          <div className="pt-2 flex items-center justify-between border-t border-shield-border">
            <button
              onClick={handleClearCache}
              className="flex items-center space-x-1.5 py-2 px-3 bg-shield-dark hover:bg-shield-cardHover text-slate-300 border border-shield-border rounded-xl text-xs transition-colors"
            >
              <Trash2 className="w-3.5 h-3.5 text-amber-400" />
              <span>{t.clearCache}</span>
            </button>

            <button
              onClick={handleResetDefaults}
              className="flex items-center space-x-1.5 py-2 px-3 bg-red-950/30 hover:bg-red-900/40 text-red-300 border border-red-800/50 rounded-xl text-xs transition-colors"
            >
              <RotateCcw className="w-3.5 h-3.5" />
              <span>{t.resetDefaults}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
