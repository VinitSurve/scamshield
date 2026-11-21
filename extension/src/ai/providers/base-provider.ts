/**
 * ScamShield AI Engine — Base Provider Abstraction
 *
 * Provides core network execution, bounded timeouts, error classification,
 * secret-safe error sanitization, and JSON response extraction.
 */

import {
  AIProviderId,
  AIErrorCategory,
  KeyValidationResult,
  StructuredScamAnalysis,
  UrlEvidenceExplanation,
} from '../types';
import { logger } from '../../utils/logger';

export abstract class BaseAIProvider {
  abstract readonly id: AIProviderId;
  abstract readonly name: string;

  /**
   * Executes prompt on provider with bounded timeout and returns raw text response
   */
  abstract executeRaw(
    prompt: string,
    model: string,
    apiKey: string,
    timeoutMs: number
  ): Promise<string>;

  /**
   * Validates API key health using a minimal token test
   */
  abstract validateKey(
    apiKey: string,
    model: string,
    timeoutMs: number
  ): Promise<KeyValidationResult>;

  /**
   * Classifies HTTP status and error payload into standardized AIErrorCategory
   */
  classifyError(
    statusCode: number,
    errorBody?: any,
    rawError?: Error
  ): { category: AIErrorCategory; retryAfterSeconds?: number; sanitizedMessage: string } {
    let category: AIErrorCategory = 'UNKNOWN';
    let retryAfterSeconds: number | undefined;
    let sanitizedMessage = 'AI provider request failed';

    const errMsg = errorBody?.error?.message || errorBody?.message || rawError?.message || '';

    if (rawError?.name === 'AbortError' || errMsg.toLowerCase().includes('timeout')) {
      category = 'TIMEOUT';
      sanitizedMessage = 'Request timed out after maximum allowed latency';
      return { category, sanitizedMessage };
    }

    if (errMsg.toLowerCase().includes('network') || errMsg.toLowerCase().includes('failed to fetch')) {
      category = 'NETWORK_ERROR';
      sanitizedMessage = 'Network connection failed or connection refused';
      return { category, sanitizedMessage };
    }

    if (statusCode === 429 || errMsg.toLowerCase().includes('rate limit') || errMsg.toLowerCase().includes('quota') || errMsg.toLowerCase().includes('resource_exhausted')) {
      category = 'RATE_LIMIT';
      sanitizedMessage = 'API rate limit or quota exceeded';

      // Check for retry delay indicators
      if (typeof errorBody?.error?.details === 'object') {
        const retryInfo = Array.isArray(errorBody.error.details)
          ? errorBody.error.details.find((d: any) => d['@type']?.includes('RetryInfo'))
          : null;
        if (retryInfo?.retryDelay) {
          const seconds = parseInt(retryInfo.retryDelay, 10);
          if (!isNaN(seconds) && seconds > 0) {
            retryAfterSeconds = seconds;
          }
        }
      }
      return { category, retryAfterSeconds, sanitizedMessage };
    }

    if (statusCode === 401 || errMsg.toLowerCase().includes('api key') || errMsg.toLowerCase().includes('unauthenticated') || errMsg.toLowerCase().includes('invalid_api_key')) {
      category = 'AUTH_ERROR';
      sanitizedMessage = 'Authentication failed: Invalid or expired API key';
      return { category, sanitizedMessage };
    }

    if (statusCode === 403 || errMsg.toLowerCase().includes('permission_denied')) {
      category = 'PERMISSION';
      sanitizedMessage = 'Permission denied: Key lacks required model permissions or billing';
      return { category, sanitizedMessage };
    }

    if (statusCode === 400 || errMsg.toLowerCase().includes('invalid_argument')) {
      category = 'BAD_REQUEST';
      sanitizedMessage = `Malformed request structure: ${this.sanitizeMessage(errMsg)}`;
      return { category, sanitizedMessage };
    }

    if (statusCode >= 500) {
      category = 'SERVER_ERROR';
      sanitizedMessage = `Provider service error (HTTP ${statusCode})`;
      return { category, sanitizedMessage };
    }

    return { category, sanitizedMessage: this.sanitizeMessage(errMsg) || 'Unknown error occurred' };
  }

  /**
   * Strips any raw API keys or secret tokens from error strings
   */
  protected sanitizeMessage(msg: string): string {
    if (!msg) return '';
    return msg
      .replace(/AIza[0-9A-Za-z-_]{35}/g, '[REDACTED_GEMINI_KEY]')
      .replace(/gsk_[0-9A-Za-z]{40,}/g, '[REDACTED_GROQ_KEY]')
      .replace(/Bearer\s+[A-Za-z0-9_\-.]+/gi, 'Bearer [REDACTED]');
  }

  /**
   * Safely parses JSON from LLM response (handling markdown fences and trailing text)
   */
  parseStructuredJson<T>(rawText: string, fallbackDefault: T): T {
    if (!rawText || typeof rawText !== 'string') {
      return fallbackDefault;
    }

    let clean = rawText.trim();

    // Strip markdown code fences if present
    if (clean.startsWith('```')) {
      clean = clean.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/, '').trim();
    }

    // Find the outer JSON object { ... }
    const firstBrace = clean.indexOf('{');
    const lastBrace = clean.lastIndexOf('}');
    if (firstBrace !== -1 && lastBrace !== -1 && lastBrace > firstBrace) {
      clean = clean.substring(firstBrace, lastBrace + 1);
    }

    try {
      return JSON.parse(clean) as T;
    } catch (err) {
      logger.warn('Failed to parse structured JSON from AI output:', err, 'Raw text:', rawText.substring(0, 100));
      return fallbackDefault;
    }
  }

  /**
   * Validates and normalizes structured scam analysis object
   */
  normalizeAnalysisResponse(
    parsed: any,
    provider: AIProviderId,
    model: string,
    latencyMs: number,
    fallbackOccurred = false
  ): StructuredScamAnalysis {
    const validClassifications = ['SAFE', 'SUSPICIOUS', 'SCAM', 'MALICIOUS', 'UNKNOWN'];
    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

    const classification = validClassifications.includes(parsed?.classification?.toUpperCase())
      ? parsed.classification.toUpperCase()
      : 'UNKNOWN';

    const riskLevel = validSeverities.includes(parsed?.riskLevel?.toUpperCase())
      ? parsed.riskLevel.toUpperCase()
      : 'MEDIUM';

    const confidenceScore = typeof parsed?.confidenceScore === 'number'
      ? Math.max(0, Math.min(1, parsed.confidenceScore))
      : 0.5;

    return {
      success: true,
      classification,
      riskLevel,
      confidenceScore,
      scamCategory: parsed?.scamCategory || 'UNCLASSIFIED',
      summary: parsed?.summary || 'Analysis completed.',
      socialEngineeringTactics: Array.isArray(parsed?.socialEngineeringTactics)
        ? parsed.socialEngineeringTactics
        : [],
      indicators: Array.isArray(parsed?.indicators)
        ? parsed.indicators.map((ind: any) => ({
            type: ind?.type || 'INDICATOR',
            description: ind?.description || '',
            severity: ['LOW', 'MEDIUM', 'HIGH'].includes(ind?.severity?.toUpperCase())
              ? ind.severity.toUpperCase()
              : 'MEDIUM',
          }))
        : [],
      extractedEntities: {
        brandImpersonated: parsed?.extractedEntities?.brandImpersonated,
        suspiciousUrls: Array.isArray(parsed?.extractedEntities?.suspiciousUrls)
          ? parsed.extractedEntities.suspiciousUrls
          : [],
        paymentRequests: Array.isArray(parsed?.extractedEntities?.paymentRequests)
          ? parsed.extractedEntities.paymentRequests
          : [],
        requestedActions: Array.isArray(parsed?.extractedEntities?.requestedActions)
          ? parsed.extractedEntities.requestedActions
          : [],
      },
      recommendedActions: Array.isArray(parsed?.recommendedActions) && parsed.recommendedActions.length > 0
        ? parsed.recommendedActions
        : ['Do not click suspicious links.', 'Do not share OTPs or passwords.'],
      explanation: parsed?.explanation || parsed?.summary || '',
      providerUsed: provider,
      modelUsed: model,
      latencyMs,
      fallbackOccurred,
    };
  }

  /**
   * Normalizes URL evidence explanation response
   */
  normalizeUrlExplanation(
    parsed: any,
    provider: AIProviderId,
    latencyMs: number
  ): UrlEvidenceExplanation {
    const validSeverities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const dangerLevel = validSeverities.includes(parsed?.dangerLevel?.toUpperCase())
      ? parsed.dangerLevel.toUpperCase()
      : 'MEDIUM';

    return {
      success: true,
      summary: parsed?.summary || 'Evidence review completed.',
      dangerLevel,
      tacticsDetected: Array.isArray(parsed?.tacticsDetected) ? parsed.tacticsDetected : [],
      safetyGuidance: Array.isArray(parsed?.safetyGuidance) && parsed.safetyGuidance.length > 0
        ? parsed.safetyGuidance
        : ['Exercise caution before entering credentials.', 'Verify the domain name carefully.'],
      providerUsed: provider,
      latencyMs,
    };
  }
}
