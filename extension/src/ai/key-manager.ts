/**
 * ScamShield AI Engine — Key Manager & Health Pool
 *
 * Manages multi-key pools per AI provider (Gemini, Groq) with:
 * - Round-robin health-aware key selection
 * - Automatic rate-limit cooldown recovery
 * - Persistent storage in chrome.storage.local
 * - Key masking for UI safety (never exposes raw keys to UI or content scripts)
 */

import {
  AIKeyConfig,
  AIProviderId,
  MaskedAIKey,
  ProviderHealthStats,
  AIErrorCategory,
} from './types';
import { logger } from '../utils/logger';

const AI_KEYS_STORAGE_KEY = 'scamshield_ai_keys_v1';

export class KeyManager {
  private static keys: AIKeyConfig[] = [];
  private static roundRobinIndices: Record<AIProviderId, number> = {
    gemini: 0,
    groq: 0,
  };
  private static isInitialized = false;

  /**
   * Initializes and loads keys from chrome.storage.local
   */
  static async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      const data = await chrome.storage.local.get(AI_KEYS_STORAGE_KEY);
      if (data && Array.isArray(data[AI_KEYS_STORAGE_KEY])) {
        this.keys = data[AI_KEYS_STORAGE_KEY];
      } else {
        this.keys = [];
      }
      this.isInitialized = true;
      this.refreshCooldowns();
    } catch (err) {
      logger.warn('Failed to load AI keys from storage:', err);
      this.keys = [];
      this.isInitialized = true;
    }
  }

  /**
   * Masks secret key strings (e.g. 'AIzaSy...1234' -> 'AIza••••••••1234')
   */
  static maskKey(rawKey: string): string {
    if (!rawKey || typeof rawKey !== 'string') return '';
    const clean = rawKey.trim();
    if (clean.length <= 8) {
      return '••••••••';
    }
    const prefix = clean.slice(0, 4);
    const suffix = clean.slice(-4);
    return `${prefix}••••••••${suffix}`;
  }

  /**
   * Retrieves next available healthy key for a provider using round-robin
   */
  static async getNextAvailableKey(provider: AIProviderId): Promise<AIKeyConfig | null> {
    await this.initialize();
    this.refreshCooldowns();

    const providerKeys = this.keys.filter(
      (k) => k.provider === provider && k.enabled && k.status !== 'invalid' && k.status !== 'disabled'
    );

    if (providerKeys.length === 0) {
      return null;
    }

    // Filter to keys that are not cooling down
    const availableKeys = providerKeys.filter((k) => {
      if (k.status === 'cooling_down') {
        return k.cooldownUntil && Date.now() >= k.cooldownUntil;
      }
      return k.status === 'healthy';
    });

    if (availableKeys.length === 0) {
      return null;
    }

    // Round-robin selection
    const currentIndex = this.roundRobinIndices[provider] || 0;
    const selected = availableKeys[currentIndex % availableKeys.length];
    this.roundRobinIndices[provider] = (currentIndex + 1) % availableKeys.length;

    return selected;
  }

  /**
   * Records a rate-limit event on a key (HTTP 429) and initiates cooldown
   */
  static async recordRateLimit(
    keyId: string,
    retryAfterSeconds?: number
  ): Promise<void> {
    const key = this.keys.find((k) => k.id === keyId);
    if (!key) return;

    // Determine cooldown: Retry-After or exponential backoff (30s base * (1 + count), max 300s)
    const baseCooldownSec = retryAfterSeconds && retryAfterSeconds > 0
      ? retryAfterSeconds
      : Math.min(30 * (1 + key.rateLimitCount), 300);

    const cooldownUntil = Date.now() + baseCooldownSec * 1000;

    key.status = 'cooling_down';
    key.rateLimitCount += 1;
    key.lastErrorAt = Date.now();
    key.lastErrorCategory = 'RATE_LIMIT';
    key.lastErrorMessage = `Rate limit exceeded. Cooling down for ${baseCooldownSec}s`;
    key.cooldownUntil = cooldownUntil;

    logger.warn(`AI Key ${keyId} entered cooldown for ${baseCooldownSec}s (rate limit # ${key.rateLimitCount})`);
    await this.persist();
  }

  /**
   * Records authentication failure (HTTP 401 / Invalid Key)
   */
  static async recordAuthFailure(keyId: string, message?: string): Promise<void> {
    const key = this.keys.find((k) => k.id === keyId);
    if (!key) return;

    key.status = 'invalid';
    key.failureCount += 1;
    key.lastErrorAt = Date.now();
    key.lastErrorCategory = 'AUTH_ERROR';
    key.lastErrorMessage = message || 'Authentication failed: Invalid API key';

    logger.error(`AI Key ${keyId} marked as INVALID due to authentication failure`);
    await this.persist();
  }

  /**
   * Records general failure on key
   */
  static async recordFailure(
    keyId: string,
    category: AIErrorCategory,
    message: string
  ): Promise<void> {
    const key = this.keys.find((k) => k.id === keyId);
    if (!key) return;

    key.failureCount += 1;
    key.lastErrorAt = Date.now();
    key.lastErrorCategory = category;
    key.lastErrorMessage = message;

    await this.persist();
  }

  /**
   * Records successful execution using this key
   */
  static async recordSuccess(keyId: string): Promise<void> {
    const key = this.keys.find((k) => k.id === keyId);
    if (!key) return;

    key.status = 'healthy';
    key.usageCount += 1;
    key.lastUsedAt = Date.now();
    key.lastSuccessAt = Date.now();
    key.cooldownUntil = undefined;
    key.lastErrorMessage = undefined;

    await this.persist();
  }

  /**
   * Adds a new API key to the pool
   */
  static async addKey(
    provider: AIProviderId,
    rawKey: string,
    label?: string
  ): Promise<MaskedAIKey> {
    await this.initialize();
    const cleanKey = rawKey.trim();
    if (!cleanKey) {
      throw new Error('API Key cannot be empty');
    }

    // Check for duplicate key in the same provider
    const existing = this.keys.find(
      (k) => k.provider === provider && k.key === cleanKey
    );
    if (existing) {
      throw new Error('This API key is already configured for this provider');
    }

    const newKey: AIKeyConfig = {
      id: `${provider}_key_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
      provider,
      key: cleanKey,
      label: label?.trim() || `Key ${this.keys.filter((k) => k.provider === provider).length + 1}`,
      enabled: true,
      status: 'healthy',
      usageCount: 0,
      failureCount: 0,
      rateLimitCount: 0,
    };

    this.keys.push(newKey);
    await this.persist();

    return this.toMasked(newKey);
  }

  /**
   * Removes an API key by ID
   */
  static async removeKey(keyId: string): Promise<boolean> {
    await this.initialize();
    const initialLen = this.keys.length;
    this.keys = this.keys.filter((k) => k.id !== keyId);
    if (this.keys.length !== initialLen) {
      await this.persist();
      return true;
    }
    return false;
  }

  /**
   * Enables or disables a key
   */
  static async toggleKey(keyId: string, enabled: boolean): Promise<MaskedAIKey | null> {
    await this.initialize();
    const key = this.keys.find((k) => k.id === keyId);
    if (!key) return null;

    key.enabled = enabled;
    if (!enabled) {
      key.status = 'disabled';
    } else if (key.status === 'disabled') {
      key.status = 'healthy';
    }

    await this.persist();
    return this.toMasked(key);
  }

  /**
   * Resets health status of a key (e.g. from cooling_down or invalid back to healthy)
   */
  static async resetKeyStatus(keyId: string): Promise<MaskedAIKey | null> {
    await this.initialize();
    const key = this.keys.find((k) => k.id === keyId);
    if (!key) return null;

    key.status = 'healthy';
    key.cooldownUntil = undefined;
    key.lastErrorMessage = undefined;
    key.failureCount = 0;
    key.rateLimitCount = 0;

    await this.persist();
    return this.toMasked(key);
  }

  /**
   * Returns list of all keys in masked form (safe for UI display)
   */
  static async getMaskedKeys(provider?: AIProviderId): Promise<MaskedAIKey[]> {
    await this.initialize();
    this.refreshCooldowns();

    const targetKeys = provider ? this.keys.filter((k) => k.provider === provider) : this.keys;
    return targetKeys.map((k) => this.toMasked(k));
  }

  /**
   * Returns raw key by ID (INTERNAL Background Worker Only — Never send to UI)
   */
  static async getRawKeyById(keyId: string): Promise<AIKeyConfig | null> {
    await this.initialize();
    return this.keys.find((k) => k.id === keyId) || null;
  }

  /**
   * Generates health statistics for all providers
   */
  static async getHealthStats(): Promise<Record<AIProviderId, ProviderHealthStats>> {
    await this.initialize();
    this.refreshCooldowns();

    const providers: AIProviderId[] = ['gemini', 'groq'];
    const result: Partial<Record<AIProviderId, ProviderHealthStats>> = {};

    for (const p of providers) {
      const pKeys = this.keys.filter((k) => k.provider === p);
      const healthyKeys = pKeys.filter((k) => k.enabled && k.status === 'healthy').length;
      const coolingDownKeys = pKeys.filter((k) => k.enabled && k.status === 'cooling_down').length;
      const invalidKeys = pKeys.filter((k) => k.status === 'invalid').length;

      let status: 'operational' | 'degraded' | 'exhausted' | 'unconfigured' = 'unconfigured';
      if (pKeys.length === 0) {
        status = 'unconfigured';
      } else if (healthyKeys > 0) {
        status = coolingDownKeys > 0 ? 'degraded' : 'operational';
      } else if (coolingDownKeys > 0) {
        status = 'degraded';
      } else {
        status = 'exhausted';
      }

      const totalRequests = pKeys.reduce((acc, k) => acc + k.usageCount + k.failureCount, 0);
      const totalSuccesses = pKeys.reduce((acc, k) => acc + k.usageCount, 0);
      const totalFailures = pKeys.reduce((acc, k) => acc + k.failureCount, 0);
      const totalRateLimits = pKeys.reduce((acc, k) => acc + k.rateLimitCount, 0);

      const lastSuccessTimes = pKeys
        .map((k) => k.lastSuccessAt || 0)
        .filter((t) => t > 0);
      const lastSuccessfulRequestAt =
        lastSuccessTimes.length > 0 ? Math.max(...lastSuccessTimes) : undefined;

      result[p] = {
        providerId: p,
        name: p === 'gemini' ? 'Google Gemini' : 'Groq Fast Inference',
        status,
        totalKeys: pKeys.length,
        healthyKeys,
        coolingDownKeys,
        invalidKeys,
        totalRequests,
        totalSuccesses,
        totalFailures,
        totalRateLimits,
        lastSuccessfulRequestAt,
      };
    }

    return result as Record<AIProviderId, ProviderHealthStats>;
  }

  /**
   * Automatically clears expired cooldowns
   */
  private static refreshCooldowns(): void {
    const now = Date.now();
    let hasChanges = false;

    for (const key of this.keys) {
      if (key.status === 'cooling_down' && key.cooldownUntil && now >= key.cooldownUntil) {
        key.status = 'healthy';
        key.cooldownUntil = undefined;
        key.lastErrorMessage = undefined;
        hasChanges = true;
      }
    }

    if (hasChanges) {
      this.persist().catch((err) => logger.warn('Failed to persist cooldown updates:', err));
    }
  }

  /**
   * Persists key array to chrome.storage.local
   */
  private static async persist(): Promise<void> {
    try {
      await chrome.storage.local.set({ [AI_KEYS_STORAGE_KEY]: this.keys });
    } catch (err) {
      logger.error('Failed to persist AI keys to storage:', err);
    }
  }

  /**
   * Converts raw key config to safe masked representation
   */
  private static toMasked(key: AIKeyConfig): MaskedAIKey {
    const now = Date.now();
    const cooldownRemainingSeconds =
      key.status === 'cooling_down' && key.cooldownUntil && key.cooldownUntil > now
        ? Math.ceil((key.cooldownUntil - now) / 1000)
        : undefined;

    return {
      id: key.id,
      provider: key.provider,
      maskedKey: this.maskKey(key.key),
      label: key.label,
      enabled: key.enabled,
      status: key.status,
      usageCount: key.usageCount,
      failureCount: key.failureCount,
      rateLimitCount: key.rateLimitCount,
      lastUsedAt: key.lastUsedAt,
      lastSuccessAt: key.lastSuccessAt,
      lastErrorAt: key.lastErrorAt,
      lastErrorCategory: key.lastErrorCategory,
      lastErrorMessage: key.lastErrorMessage,
      cooldownRemainingSeconds,
    };
  }

  /**
   * Test utility: clear all keys (used in automated test cleanups)
   */
  static async clearAllKeys(): Promise<void> {
    this.keys = [];
    this.roundRobinIndices = { gemini: 0, groq: 0 };
    await this.persist();
  }
}
