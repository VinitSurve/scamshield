import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  Key,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  RotateCcw,
  Zap,
} from 'lucide-react';
import {
  AIProviderId,
  AISystemSettings,
  DEFAULT_AI_SETTINGS,
  MaskedAIKey,
  ProviderHealthStats,
  KeyValidationResult,
} from '../../ai/types';
import { SafeMessaging } from '../../security/safe-messaging';

export const AISettingsSection: React.FC = () => {
  const [aiSettings, setAiSettings] = useState<AISystemSettings>(DEFAULT_AI_SETTINGS);
  const [keys, setKeys] = useState<MaskedAIKey[]>([]);
  const [healthStats, setHealthStats] = useState<Record<AIProviderId, ProviderHealthStats> | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Add Key Form state
  const [selectedProviderToAdd, setSelectedProviderToAdd] = useState<AIProviderId>('gemini');
  const [newKeyString, setNewKeyString] = useState('');
  const [newKeyLabel, setNewKeyLabel] = useState('');
  const [showKeySecret, setShowKeySecret] = useState(false);
  const [isAddingKey, setIsAddingKey] = useState(false);
  const [addKeyError, setAddKeyError] = useState<string | null>(null);

  // Testing Key State
  const [testingKeyId, setTestingKeyId] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ keyId: string; result: KeyValidationResult } | null>(null);

  const loadData = async () => {
    try {
      const [settingsRes, keysRes, statsRes] = await Promise.all([
        SafeMessaging.sendToBackground<AISystemSettings>('AI_GET_CONFIG'),
        SafeMessaging.sendToBackground<MaskedAIKey[]>('AI_GET_KEYS'),
        SafeMessaging.sendToBackground<Record<AIProviderId, ProviderHealthStats>>('AI_GET_HEALTH_STATS'),
      ]);

      if (settingsRes) setAiSettings(settingsRes);
      if (keysRes) setKeys(keysRes);
      if (statsRes) setHealthStats(statsRes);
    } catch (err) {
      console.error('Failed to load AI settings & keys:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000); // Poll for cooldown updates
    return () => clearInterval(interval);
  }, []);

  const handleUpdateSettings = async (updates: Partial<AISystemSettings>) => {
    try {
      const updated = await SafeMessaging.sendToBackground<AISystemSettings>('AI_UPDATE_CONFIG', updates);
      setAiSettings(updated);
    } catch (err) {
      console.error('Failed to update AI settings:', err);
    }
  };

  const handleUpdateModel = async (provider: AIProviderId, selectedModel: string) => {
    const updatedProviders = {
      ...aiSettings.providers,
      [provider]: {
        ...aiSettings.providers[provider],
        selectedModel,
      },
    };
    await handleUpdateSettings({ providers: updatedProviders });
  };

  const handleAddKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyString.trim()) {
      setAddKeyError('API Key cannot be empty');
      return;
    }
    setAddKeyError(null);
    setIsAddingKey(true);

    try {
      await SafeMessaging.sendToBackground('AI_ADD_KEY', {
        provider: selectedProviderToAdd,
        key: newKeyString.trim(),
        label: newKeyLabel.trim() || undefined,
      });

      setNewKeyString('');
      setNewKeyLabel('');
      await loadData();
    } catch (err: any) {
      setAddKeyError(err.message || 'Failed to add API key');
    } finally {
      setIsAddingKey(false);
    }
  };

  const handleRemoveKey = async (keyId: string) => {
    if (!window.confirm('Are you sure you want to remove this API key from ScamShield?')) return;
    try {
      await SafeMessaging.sendToBackground('AI_REMOVE_KEY', { keyId });
      await loadData();
    } catch (err) {
      console.error('Failed to remove key:', err);
    }
  };

  const handleToggleKey = async (keyId: string, enabled: boolean) => {
    try {
      await SafeMessaging.sendToBackground('AI_TOGGLE_KEY', { keyId, enabled });
      await loadData();
    } catch (err) {
      console.error('Failed to toggle key:', err);
    }
  };

  const handleResetKey = async (keyId: string) => {
    try {
      await SafeMessaging.sendToBackground('AI_RESET_KEY_STATUS', { keyId });
      await loadData();
    } catch (err) {
      console.error('Failed to reset key status:', err);
    }
  };

  const handleTestKey = async (keyId: string) => {
    setTestingKeyId(keyId);
    setTestResult(null);
    try {
      const res = await SafeMessaging.sendToBackground<KeyValidationResult>('AI_TEST_KEY', { keyId }, 12000);
      setTestResult({ keyId, result: res });
      await loadData();
    } catch (err: any) {
      setTestResult({
        keyId,
        result: {
          valid: false,
          providerId: 'gemini',
          sanitizedMessage: err.message || 'Validation request failed',
          latencyMs: 0,
        },
      });
    } finally {
      setTestingKeyId(null);
    }
  };

  if (isLoading) {
    return (
      <div className="bg-shield-card border border-shield-border rounded-2xl p-6 text-center text-xs text-slate-400">
        Loading AI Engine Configuration...
      </div>
    );
  }

  const geminiKeys = keys.filter((k) => k.provider === 'gemini');
  const groqKeys = keys.filter((k) => k.provider === 'groq');

  return (
    <div className="bg-shield-card border border-shield-border rounded-2xl p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-shield-border/60 pb-4">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 border border-indigo-500/30 rounded-xl text-indigo-400">
            <Sparkles className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <span>Multi-Provider AI Engine</span>
              <span className="px-2 py-0.5 text-[10px] font-mono bg-indigo-950/80 border border-indigo-500/40 text-indigo-300 rounded-full">
                Gemini + Groq
              </span>
            </h2>
            <p className="text-xs text-slate-400">
              Multi-key pool with automated key rotation, rate-limit cooldown recovery, and seamless provider fallback.
            </p>
          </div>
        </div>

        <label className="flex items-center space-x-2 cursor-pointer">
          <span className="text-xs font-semibold text-slate-300">AI Engine</span>
          <input
            type="checkbox"
            checked={aiSettings.enabled}
            onChange={(e) => handleUpdateSettings({ enabled: e.target.checked })}
            className="w-4 h-4 rounded text-indigo-500 bg-shield-dark border-shield-border focus:ring-0"
          />
        </label>
      </div>

      {/* Global AI Routing Controls */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
        <div className="p-3 bg-shield-dark border border-shield-border rounded-xl space-y-1.5">
          <span className="text-slate-400 font-medium block">Primary Provider</span>
          <select
            value={aiSettings.primaryProvider}
            onChange={(e) => handleUpdateSettings({ primaryProvider: e.target.value as AIProviderId })}
            className="w-full bg-slate-900 border border-shield-border text-white rounded-lg px-2.5 py-1.5 font-semibold focus:outline-none focus:border-indigo-500"
          >
            <option value="gemini">Google Gemini (Primary)</option>
            <option value="groq">Groq Fast Inference (Primary)</option>
          </select>
        </div>

        <div className="p-3 bg-shield-dark border border-shield-border rounded-xl space-y-1.5">
          <span className="text-slate-400 font-medium block">Automatic Fallback</span>
          <label className="flex items-center justify-between pt-1 cursor-pointer">
            <span className="text-slate-300 font-semibold">Enable Provider Fallback</span>
            <input
              type="checkbox"
              checked={aiSettings.fallbackEnabled}
              onChange={(e) => handleUpdateSettings({ fallbackEnabled: e.target.checked })}
              className="w-4 h-4 rounded text-indigo-500 bg-slate-900 border-shield-border focus:ring-0"
            />
          </label>
        </div>

        <div className="p-3 bg-shield-dark border border-shield-border rounded-xl space-y-1.5">
          <span className="text-slate-400 font-medium block">Key Rotation Policy</span>
          <label className="flex items-center justify-between pt-1 cursor-pointer">
            <span className="text-slate-300 font-semibold">Health-Aware Round Robin</span>
            <input
              type="checkbox"
              checked={aiSettings.keyRotationEnabled}
              onChange={(e) => handleUpdateSettings({ keyRotationEnabled: e.target.checked })}
              className="w-4 h-4 rounded text-indigo-500 bg-slate-900 border-shield-border focus:ring-0"
            />
          </label>
        </div>
      </div>

      {/* Provider Health Dashboard */}
      {healthStats && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
          {/* Gemini Card */}
          <div className="p-4 bg-shield-dark/90 border border-shield-border rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="font-bold text-white text-sm">Google Gemini Pool</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                    healthStats.gemini.status === 'operational'
                      ? 'bg-emerald-950/80 border border-emerald-700 text-emerald-300'
                      : healthStats.gemini.status === 'degraded'
                      ? 'bg-amber-950/80 border border-amber-700 text-amber-300'
                      : healthStats.gemini.status === 'exhausted'
                      ? 'bg-red-950/80 border border-red-700 text-red-300'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {healthStats.gemini.status}
                </span>
              </div>
              <select
                value={aiSettings.providers.gemini.selectedModel}
                onChange={(e) => handleUpdateModel('gemini', e.target.value)}
                className="bg-slate-900 border border-shield-border text-[11px] text-slate-200 rounded px-2 py-1 font-mono focus:outline-none focus:border-indigo-500"
              >
                {aiSettings.providers.gemini.availableModels.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-4 gap-2 text-center">
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Healthy Keys</span>
                <span className="text-emerald-400 font-bold font-mono text-sm">
                  {healthStats.gemini.healthyKeys}/{healthStats.gemini.totalKeys}
                </span>
              </div>
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Cooling Down</span>
                <span className="text-amber-400 font-bold font-mono text-sm">
                  {healthStats.gemini.coolingDownKeys}
                </span>
              </div>
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Total Requests</span>
                <span className="text-white font-bold font-mono text-sm">
                  {healthStats.gemini.totalRequests}
                </span>
              </div>
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Rate Limits</span>
                <span className="text-red-400 font-bold font-mono text-sm">
                  {healthStats.gemini.totalRateLimits}
                </span>
              </div>
            </div>
          </div>

          {/* Groq Card */}
          <div className="p-4 bg-shield-dark/90 border border-shield-border rounded-xl space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <span className="font-bold text-white text-sm">Groq Fast Inference</span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                    healthStats.groq.status === 'operational'
                      ? 'bg-emerald-950/80 border border-emerald-700 text-emerald-300'
                      : healthStats.groq.status === 'degraded'
                      ? 'bg-amber-950/80 border border-amber-700 text-amber-300'
                      : healthStats.groq.status === 'exhausted'
                      ? 'bg-red-950/80 border border-red-700 text-red-300'
                      : 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {healthStats.groq.status}
                </span>
              </div>
              <select
                value={aiSettings.providers.groq.selectedModel}
                onChange={(e) => handleUpdateModel('groq', e.target.value)}
                className="bg-slate-900 border border-shield-border text-[11px] text-slate-200 rounded px-2 py-1 font-mono focus:outline-none focus:border-indigo-500"
              >
                {aiSettings.providers.groq.availableModels.map((m) => (
                  <option key={m} value={m}>
                    {m}
                  </option>
                ))}
              </select>
            </div>

            <div className="grid grid-cols-4 gap-2 text-center">
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Healthy Keys</span>
                <span className="text-emerald-400 font-bold font-mono text-sm">
                  {healthStats.groq.healthyKeys}/{healthStats.groq.totalKeys}
                </span>
              </div>
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Cooling Down</span>
                <span className="text-amber-400 font-bold font-mono text-sm">
                  {healthStats.groq.coolingDownKeys}
                </span>
              </div>
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Total Requests</span>
                <span className="text-white font-bold font-mono text-sm">
                  {healthStats.groq.totalRequests}
                </span>
              </div>
              <div className="p-2 bg-slate-900/80 rounded-lg border border-shield-border/40">
                <span className="text-[10px] text-slate-400 block">Rate Limits</span>
                <span className="text-red-400 font-bold font-mono text-sm">
                  {healthStats.groq.totalRateLimits}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Add New Key Form */}
      <div className="p-4 bg-shield-dark border border-shield-border rounded-xl space-y-3">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
          <Key className="w-3.5 h-3.5 text-indigo-400" />
          <span>Add API Key to Pool</span>
        </h3>

        <form onSubmit={handleAddKey} className="space-y-3 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Target Provider</label>
              <select
                value={selectedProviderToAdd}
                onChange={(e) => setSelectedProviderToAdd(e.target.value as AIProviderId)}
                className="w-full bg-slate-900 border border-shield-border rounded-lg px-2.5 py-2 text-white font-semibold focus:outline-none focus:border-indigo-500"
              >
                <option value="gemini">Google Gemini (AI Studio)</option>
                <option value="groq">Groq (console.groq.com)</option>
              </select>
            </div>

            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Key Label (Optional)</label>
              <input
                type="text"
                placeholder="e.g. Primary Free Tier, Hackathon Key 2"
                value={newKeyLabel}
                onChange={(e) => setNewKeyLabel(e.target.value)}
                className="w-full bg-slate-900 border border-shield-border rounded-lg px-2.5 py-2 text-white placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
              />
            </div>

            <div>
              <label className="text-[11px] text-slate-400 block mb-1">Secret Key String</label>
              <div className="relative">
                <input
                  type={showKeySecret ? 'text' : 'password'}
                  placeholder={
                    selectedProviderToAdd === 'gemini'
                      ? 'AIzaSy...'
                      : 'gsk_...'
                  }
                  value={newKeyString}
                  onChange={(e) => setNewKeyString(e.target.value)}
                  className="w-full bg-slate-900 border border-shield-border rounded-lg pl-2.5 pr-8 py-2 text-white font-mono placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
                />
                <button
                  type="button"
                  onClick={() => setShowKeySecret(!showKeySecret)}
                  className="absolute right-2 top-2 text-slate-400 hover:text-white"
                >
                  {showKeySecret ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          </div>

          {addKeyError && (
            <p className="text-red-400 text-xs flex items-center space-x-1">
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>{addKeyError}</span>
            </p>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={isAddingKey || !newKeyString.trim()}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-bold rounded-lg text-xs flex items-center space-x-1.5 transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>{isAddingKey ? 'Adding...' : 'Add API Key to Pool'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Configured Keys Pool Display */}
      <div className="space-y-4">
        {/* Gemini Keys */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
              <span>Google Gemini Keys ({geminiKeys.length})</span>
            </span>
          </div>

          {geminiKeys.length === 0 ? (
            <div className="p-3 bg-shield-dark/50 border border-dashed border-shield-border/60 rounded-xl text-center text-xs text-slate-500">
              No Gemini keys configured. Add one or more Gemini API keys above.
            </div>
          ) : (
            <div className="space-y-2">
              {geminiKeys.map((key) => renderKeyCard(key))}
            </div>
          )}
        </div>

        {/* Groq Keys */}
        <div className="space-y-2 pt-2">
          <div className="flex items-center justify-between text-xs">
            <span className="font-bold text-white uppercase tracking-wider flex items-center space-x-1.5">
              <span>Groq Keys ({groqKeys.length})</span>
            </span>
          </div>

          {groqKeys.length === 0 ? (
            <div className="p-3 bg-shield-dark/50 border border-dashed border-shield-border/60 rounded-xl text-center text-xs text-slate-500">
              No Groq keys configured. Add one or more Groq API keys above.
            </div>
          ) : (
            <div className="space-y-2">
              {groqKeys.map((key) => renderKeyCard(key))}
            </div>
          )}
        </div>
      </div>

      {/* Security & Privacy Notice */}
      <div className="p-3.5 bg-indigo-950/30 border border-indigo-900/40 rounded-xl text-xs space-y-1 text-slate-400">
        <div className="flex items-center space-x-1.5 text-indigo-300 font-semibold">
          <ShieldAlert className="w-3.5 h-3.5 text-indigo-400" />
          <span>Security & Privacy Boundary</span>
        </div>
        <p className="text-[11px] leading-relaxed">
          API keys are encrypted in your local browser profile (`chrome.storage.local`) and are strictly restricted
          to the background service worker. Keys are never transmitted to ScamShield servers, never logged, and
          never exposed to website page contexts. All text is automatically scrubbed of personal phone numbers,
          emails, and account identifiers before calling AI provider endpoints.
        </p>
      </div>
    </div>
  );

  function renderKeyCard(key: MaskedAIKey) {
    const isTestingThis = testingKeyId === key.id;
    const testResultForThis = testResult?.keyId === key.id ? testResult.result : null;

    return (
      <div
        key={key.id}
        className="p-3 bg-shield-dark border border-shield-border rounded-xl space-y-2 text-xs"
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                key.status === 'healthy'
                  ? 'bg-emerald-400 shadow-sm shadow-emerald-400/50'
                  : key.status === 'cooling_down'
                  ? 'bg-amber-400 animate-pulse'
                  : key.status === 'invalid'
                  ? 'bg-red-400'
                  : 'bg-slate-600'
              }`}
            />
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold text-white">{key.label || 'API Key'}</span>
                <span className="font-mono text-slate-300 bg-slate-900 px-2 py-0.5 rounded text-[11px] border border-shield-border/40">
                  {key.maskedKey}
                </span>
              </div>
              <div className="flex items-center space-x-2 text-[10px] text-slate-400 mt-0.5">
                <span>Used: {key.usageCount}</span>
                <span>•</span>
                <span>Fails: {key.failureCount}</span>
                <span>•</span>
                <span>Rate Limits: {key.rateLimitCount}</span>
                {key.cooldownRemainingSeconds ? (
                  <>
                    <span>•</span>
                    <span className="text-amber-400 font-semibold font-mono">
                      Cooldown: {key.cooldownRemainingSeconds}s remaining
                    </span>
                  </>
                ) : null}
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2">
            {key.status === 'cooling_down' || key.status === 'invalid' ? (
              <button
                type="button"
                onClick={() => handleResetKey(key.id)}
                title="Reset key health status to operational"
                className="px-2 py-1 bg-amber-950/60 hover:bg-amber-900 border border-amber-700/60 text-amber-300 rounded text-[11px] flex items-center space-x-1"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset Status</span>
              </button>
            ) : null}

            <button
              type="button"
              disabled={isTestingThis}
              onClick={() => handleTestKey(key.id)}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-shield-border rounded text-[11px] flex items-center space-x-1 transition-colors"
            >
              <Zap className={`w-3 h-3 ${isTestingThis ? 'animate-spin text-amber-400' : 'text-indigo-400'}`} />
              <span>{isTestingThis ? 'Testing...' : 'Test Key'}</span>
            </button>

            <button
              type="button"
              onClick={() => handleToggleKey(key.id, !key.enabled)}
              className={`px-2 py-1 rounded text-[11px] font-semibold border ${
                key.enabled
                  ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                  : 'bg-slate-800 border-shield-border text-slate-400'
              }`}
            >
              {key.enabled ? 'Enabled' : 'Disabled'}
            </button>

            <button
              type="button"
              onClick={() => handleRemoveKey(key.id)}
              className="p-1 text-slate-500 hover:text-red-400 rounded transition-colors"
              title="Delete key from pool"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Inline Test Result Toast */}
        {testResultForThis && (
          <div
            className={`p-2 rounded-lg border text-[11px] flex items-center justify-between ${
              testResultForThis.valid
                ? 'bg-emerald-950/40 border-emerald-800 text-emerald-300'
                : 'bg-red-950/40 border-red-800 text-red-300'
            }`}
          >
            <div className="flex items-center space-x-1.5">
              {testResultForThis.valid ? (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              ) : (
                <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
              )}
              <span>{testResultForThis.sanitizedMessage}</span>
            </div>
            <span className="font-mono text-[10px] text-slate-400">
              {testResultForThis.latencyMs}ms
            </span>
          </div>
        )}
      </div>
    );
  }
};
