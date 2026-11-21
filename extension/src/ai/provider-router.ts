/**
 * ScamShield AI Engine — Provider Router & Fallback Coordinator
 *
 * Implements:
 * - Priority-based routing between Gemini and Groq
 * - Automatic key rotation on rate limits and auth errors
 * - Seamless provider fallback when a provider is exhausted
 * - Persistent AI system configuration in chrome.storage.local
 */

import {
  AIProviderId,
  AISystemSettings,
  DEFAULT_AI_SETTINGS,
  KeyValidationResult,
} from './types';
import { KeyManager } from './key-manager';
import { BaseAIProvider } from './providers/base-provider';
import { GeminiProvider } from './providers/gemini-provider';
import { GroqProvider } from './providers/groq-provider';
import { logger } from '../utils/logger';

const AI_SETTINGS_STORAGE_KEY = 'scamshield_ai_settings_v1';

export class ProviderRouter {
  private static settings: AISystemSettings = { ...DEFAULT_AI_SETTINGS };
  private static isInitialized = false;

  private static providers: Record<AIProviderId, BaseAIProvider> = {
    gemini: new GeminiProvider(),
    groq: new GroqProvider(),
  };

  /**
   * Initializes settings from storage
   */
  static async initialize(): Promise<void> {
    if (this.isInitialized) return;

    try {
      const data = await chrome.storage.local.get(AI_SETTINGS_STORAGE_KEY);
      if (data && data[AI_SETTINGS_STORAGE_KEY]) {
        this.settings = {
          ...DEFAULT_AI_SETTINGS,
          ...data[AI_SETTINGS_STORAGE_KEY],
          providers: {
            gemini: {
              ...DEFAULT_AI_SETTINGS.providers.gemini,
              ...data[AI_SETTINGS_STORAGE_KEY]?.providers?.gemini,
            },
            groq: {
              ...DEFAULT_AI_SETTINGS.providers.groq,
              ...data[AI_SETTINGS_STORAGE_KEY]?.providers?.groq,
            },
          },
        };
      } else {
        this.settings = { ...DEFAULT_AI_SETTINGS };
        await chrome.storage.local.set({ [AI_SETTINGS_STORAGE_KEY]: this.settings });
      }
      this.isInitialized = true;
    } catch (err) {
      logger.warn('Failed to load AI settings from storage, using defaults:', err);
      this.settings = { ...DEFAULT_AI_SETTINGS };
      this.isInitialized = true;
    }
  }

  /**
   * Returns current AI settings
   */
  static async getSettings(): Promise<AISystemSettings> {
    await this.initialize();
    return this.settings;
  }

  /**
   * Updates AI settings and persists to storage
   */
  static async updateSettings(updates: Partial<AISystemSettings>): Promise<AISystemSettings> {
    await this.initialize();
    this.settings = {
      ...this.settings,
      ...updates,
      providers: {
        ...this.settings.providers,
        ...(updates.providers || {}),
      },
    };

    try {
      await chrome.storage.local.set({ [AI_SETTINGS_STORAGE_KEY]: this.settings });
    } catch (err) {
      logger.error('Failed to save AI settings:', err);
      throw err;
    }

    return this.settings;
  }

  /**
   * Returns ordered list of providers to attempt based on user priority and fallback configuration
   */
  static async getProviderExecutionOrder(): Promise<AIProviderId[]> {
    const settings = await this.getSettings();
    if (!settings.enabled) return [];

    const primary = settings.primaryProvider;
    const secondary: AIProviderId = primary === 'gemini' ? 'groq' : 'gemini';

    const order: AIProviderId[] = [];

    if (settings.providers[primary]?.enabled) {
      order.push(primary);
    }

    if (settings.fallbackEnabled && settings.providers[secondary]?.enabled) {
      order.push(secondary);
    }

    return order;
  }

  /**
   * Executes prompt across provider priority with multi-key rotation and automatic fallback
   */
  static async executeWithFallback(prompt: string): Promise<{
    rawOutput: string;
    providerUsed: AIProviderId;
    modelUsed: string;
    latencyMs: number;
    fallbackOccurred: boolean;
  }> {
    await this.initialize();
    const settings = await this.getSettings();

    if (!settings.enabled) {
      throw new Error('AI analysis is currently disabled in ScamShield settings');
    }

    const providerOrder = await this.getProviderExecutionOrder();
    if (providerOrder.length === 0) {
      throw new Error('No AI providers are enabled in ScamShield settings');
    }

    const overallStart = Date.now();
    const attemptedKeys = new Set<string>();
    const providerErrors: Array<{ provider: AIProviderId; error: string }> = [];

    const primaryProvider = providerOrder[0];

    for (const providerId of providerOrder) {
      const provider = this.providers[providerId];
      const model = settings.providers[providerId]?.selectedModel;
      const timeoutMs = settings.requestTimeoutMs || 15000;

      let keyAttemptForProvider = 0;
      const maxKeyAttempts = 5; // Cap key rotations per provider to avoid unbounded loops

      while (keyAttemptForProvider < maxKeyAttempts) {
        keyAttemptForProvider++;

        const keyConfig = await KeyManager.getNextAvailableKey(providerId);

        // If no healthy/available keys for this provider, fall back to next provider
        if (!keyConfig) {
          logger.info(`No available keys for provider ${providerId}. Falling back.`);
          providerErrors.push({
            provider: providerId,
            error: 'No active or healthy API keys available (all cooling down, invalid, or unconfigured)',
          });
          break; // Break inner loop to try next provider
        }

        // Avoid infinite loop on the exact same key in a single request
        if (attemptedKeys.has(keyConfig.id)) {
          logger.info(`All available keys for ${providerId} have been attempted in this request.`);
          break;
        }
        attemptedKeys.add(keyConfig.id);

        const callStart = Date.now();
        try {
          logger.info(`Executing AI request on ${providerId} (${model}) using key ${KeyManager.maskKey(keyConfig.key)}`);
          const rawOutput = await provider.executeRaw(prompt, model, keyConfig.key, timeoutMs);
          const latencyMs = Date.now() - callStart;

          // Record success on key
          await KeyManager.recordSuccess(keyConfig.id);

          const fallbackOccurred = providerId !== primaryProvider;
          return {
            rawOutput,
            providerUsed: providerId,
            modelUsed: model,
            latencyMs,
            fallbackOccurred,
          };
        } catch (err: any) {
          const category = err.category || 'UNKNOWN';
          const msg = err.message || 'Request failed';

          logger.warn(`AI request failed on ${providerId} with key ${KeyManager.maskKey(keyConfig.key)}: [${category}] ${msg}`);

          if (category === 'RATE_LIMIT') {
            await KeyManager.recordRateLimit(keyConfig.id, err.retryAfterSeconds);
            // Immediately rotate to next key in same provider
            continue;
          }

          if (category === 'AUTH_ERROR') {
            await KeyManager.recordAuthFailure(keyConfig.id, msg);
            // Immediately rotate to next key in same provider
            continue;
          }

          if (category === 'BAD_REQUEST') {
            await KeyManager.recordFailure(keyConfig.id, 'BAD_REQUEST', msg);
            // Malformed prompt/schema: fail immediately without retrying all keys
            throw err;
          }

          // Server error / network error / timeout
          await KeyManager.recordFailure(keyConfig.id, category, msg);

          // If retry count permits, attempt next key; else fall back to next provider
          if (keyAttemptForProvider >= settings.maxRetriesPerKey) {
            providerErrors.push({ provider: providerId, error: msg });
            break;
          }
        }
      }
    }

    const totalDuration = Date.now() - overallStart;
    const summaryErr = providerErrors.map((e) => `${e.provider}: ${e.error}`).join('; ');
    throw new Error(
      `All AI providers and keys exhausted after ${totalDuration}ms. (${summaryErr || 'No operational keys configured'})`
    );
  }

  /**
   * Executes Vision request with automatic key rotation and multi-provider fallback
   */
  static async executeVisionWithFallback(
    prompt: string,
    imageDataUrl: string
  ): Promise<{
    rawText: string;
    providerUsed: AIProviderId;
    modelUsed: string;
    latencyMs: number;
    fallbackOccurred: boolean;
  }> {
    await this.initialize();
    const settings = await this.getSettings();

    if (!settings.enabled) {
      throw new Error('AI analysis is disabled in ScamShield settings');
    }

    const providerOrder = await this.getProviderExecutionOrder();
    const overallStart = Date.now();
    const providerErrors: { provider: AIProviderId; error: string }[] = [];
    let initialProviderTried = false;
    let fallbackOccurred = false;

    for (const providerId of providerOrder) {
      const providerConfig = settings.providers[providerId];
      if (!providerConfig?.enabled) continue;

      const provider = this.providers[providerId];
      if (!provider.executeVision) continue;

      const model =
        providerConfig.selectedModel ||
        (providerId === 'groq' ? 'qwen/qwen3.8-27b' : 'gemini-1.5-flash');
      const maxRetries = settings.maxRetriesPerKey || 1;

      for (let attempt = 0; attempt <= maxRetries; attempt++) {
        const keyConfig = await KeyManager.getNextAvailableKey(providerId);

        if (!keyConfig) {
          providerErrors.push({
            provider: providerId,
            error: 'No active or healthy API keys available',
          });
          break;
        }

        if (initialProviderTried) {
          fallbackOccurred = true;
        }
        initialProviderTried = true;

        const reqStart = Date.now();
        try {
          const rawText = await provider.executeVision(
            prompt,
            imageDataUrl,
            model,
            keyConfig.key,
            settings.requestTimeoutMs || 15000
          );

          const latencyMs = Date.now() - reqStart;
          await KeyManager.recordSuccess(keyConfig.id);

          return {
            rawText,
            providerUsed: providerId,
            modelUsed: model,
            latencyMs,
            fallbackOccurred,
          };
        } catch (err: any) {
          const category = err.category || 'UNKNOWN';

          if (category === 'RATE_LIMIT') {
            await KeyManager.recordRateLimit(keyConfig.id, err.retryAfterSeconds);
          } else if (category === 'AUTHENTICATION') {
            await KeyManager.recordAuthFailure(keyConfig.id);
          } else {
            await KeyManager.recordFailure(keyConfig.id, category, err.message || 'Vision request failed');
          }

          providerErrors.push({
            provider: providerId,
            error: err.message || 'Vision request failed',
          });
        }
      }

      if (!settings.fallbackEnabled) break;
    }

    const totalDuration = Date.now() - overallStart;
    const summaryErr = providerErrors.map((e) => `${e.provider}: ${e.error}`).join('; ');
    throw new Error(
      `All AI vision providers exhausted after ${totalDuration}ms. (${summaryErr || 'No operational vision keys configured'})`
    );
  }

  /**
   * Tests a specific configured key by ID
   */
  static async testKeyById(keyId: string): Promise<KeyValidationResult> {
    await this.initialize();
    const key = await KeyManager.getRawKeyById(keyId);
    if (!key) {
      return {
        valid: false,
        providerId: 'gemini',
        sanitizedMessage: 'Key not found in storage',
        latencyMs: 0,
      };
    }

    const provider = this.providers[key.provider];
    const settings = await this.getSettings();
    const model = settings.providers[key.provider]?.selectedModel;

    const result = await provider.validateKey(key.key, model, 8000);

    if (result.valid) {
      await KeyManager.recordSuccess(keyId);
    } else if (result.errorCategory === 'RATE_LIMIT') {
      await KeyManager.recordRateLimit(keyId);
    } else if (result.errorCategory === 'AUTH_ERROR') {
      await KeyManager.recordAuthFailure(keyId, result.sanitizedMessage);
    } else {
      await KeyManager.recordFailure(keyId, result.errorCategory || 'UNKNOWN', result.sanitizedMessage);
    }

    return result;
  }

  /**
   * Tests a raw key before saving
   */
  static async testRawKey(
    providerId: AIProviderId,
    rawKey: string,
    model?: string
  ): Promise<KeyValidationResult> {
    await this.initialize();
    const provider = this.providers[providerId];
    const settings = await this.getSettings();
    const targetModel = model || settings.providers[providerId]?.selectedModel;

    return provider.validateKey(rawKey.trim(), targetModel, 8000);
  }

  /**
   * Returns provider instance
   */
  static getProvider(providerId: AIProviderId): BaseAIProvider {
    return this.providers[providerId];
  }
}
