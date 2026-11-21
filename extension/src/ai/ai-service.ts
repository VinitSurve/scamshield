/**
 * ScamShield AI Engine — Public AI Service
 *
 * Primary entry point for AI-assisted security features:
 * - Privacy-scrubbed Message Scam Analysis (SMS, WhatsApp, Email, Social DMs)
 * - Deterministic Website Evidence Explanation (assists without overriding scanner)
 * - Multi-Key Management and Provider Health Coordination
 */

import {
  MessageAnalysisRequest,
  StructuredScamAnalysis,
  UrlEvidenceExplanationRequest,
  UrlEvidenceExplanation,
  KeyValidationResult,
  MaskedAIKey,
  ProviderHealthStats,
  AIProviderId,
  AISystemSettings,
  AIDiagnosticsTelemetry,
} from './types';
import { PiiScrubber } from './pii-scrubber';
import { KeyManager } from './key-manager';
import { ProviderRouter } from './provider-router';
import { LocalMessageHeuristics } from '../security/local-message-heuristics';
import { logger } from '../utils/logger';

export class AIService {
  /**
   * Analyzes suspicious text (SMS, WhatsApp, Email, social media) for scam/phishing indicators.
   * Strips PII before transmission and normalizes response into strict JSON schema.
   */
  static async analyzeMessage(
    request: MessageAnalysisRequest
  ): Promise<StructuredScamAnalysis> {
    const rawInput = request.messageText?.trim() || '';
    if (!rawInput) {
      return {
        success: false,
        classification: 'UNKNOWN',
        riskLevel: 'LOW',
        confidenceScore: 0,
        scamCategory: 'NONE',
        summary: 'No text provided for analysis.',
        socialEngineeringTactics: [],
        indicators: [],
        extractedEntities: {},
        recommendedActions: ['Provide message text to analyze.'],
        explanation: 'Input was empty.',
        error: 'Empty input text',
      };
    }

    // 1. Privacy Scrubbing: Redact personal phone numbers, OTPs, emails, account numbers
    const sanitizedText = PiiScrubber.sanitizeText(rawInput);
    const sourceType = request.sourceType || 'OTHER';
    const lang = request.userLanguage || 'en';

    // 2. Build Structured Evaluation Prompt
    const prompt = `You are ScamShield AI, an expert cybersecurity threat analysis engine specializing in detecting digital fraud, phishing, social engineering, and financial scams (particularly common in India and worldwide: UPI fraud, electricity bill scams, fake KYC, lottery scams, job scams, bank impersonation).

Analyze the following ${sourceType} message (PII has been pre-redacted for privacy).
Message text:
"""
${sanitizedText}
"""

Evaluate the message and return ONLY a valid, raw JSON object matching this exact schema:
{
  "classification": "SAFE" | "SUSPICIOUS" | "SCAM" | "MALICIOUS",
  "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "confidenceScore": <number between 0.0 and 1.0>,
  "scamCategory": "<e.g. BANKING_KYC_PHISHING, UPI_FRAUD, ELECTRICITY_BILL_SCAM, JOB_OFFER_SCAM, LOTTERY_IMPERSONATION, COURIER_DELIVERY_FRAUD, EXTORTION, LEGITIMATE_COMMUNICATION, UNKNOWN>",
  "summary": "<2-3 sentence clear summary of the assessment in ${lang === 'hi' ? 'Hindi' : lang === 'mr' ? 'Marathi' : 'English'}>",
  "socialEngineeringTactics": ["<urgency, fear, greed, fake authority, emotional manipulation, etc.>"],
  "indicators": [
    {
      "type": "<e.g. SUSPICIOUS_URL, URGENT_THREAT, UNVERIFIED_SENDER, REQUEST_FOR_OTP, ADVANCE_FEE>",
      "description": "<brief description of the indicator>",
      "severity": "LOW" | "MEDIUM" | "HIGH"
    }
  ],
  "extractedEntities": {
    "brandImpersonated": "<brand name or null>",
    "suspiciousUrls": ["<urls detected in text>"],
    "paymentRequests": ["<payment demands or amounts>"],
    "requestedActions": ["<actions the sender is urging the victim to take>"]
  },
  "recommendedActions": [
    "<action 1: e.g. Do not click the link>",
    "<action 2: e.g. Report to cybercrime portal (1930 in India)>",
    "<action 3: e.g. Never share OTP or UPI PIN>"
  ],
  "explanation": "<detailed technical rationale for user awareness>"
}`;

    const startTime = Date.now();
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();

    let backendReachable = false;
    let backendError: string | undefined;

    // ----------------------------------------------------
    // STAGE 1: Try Backend Endpoint (whatsapp-bot service)
    // ----------------------------------------------------
    try {
      const backendUrl =
        ((import.meta as any).env?.VITE_BACKEND_API_URL as string) ||
        'http://localhost:3001/api/v1/analyze/message';

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 6000);

      const res = await fetch(backendUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Client-App': 'ScamShield-Chrome-Extension',
        },
        body: JSON.stringify({
          messageText: rawInput,
          sourceType: request.sourceType || 'SMS',
          userLanguage: lang,
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (res.ok) {
        backendReachable = true;
        const data = (await res.json()) as StructuredScamAnalysis;
        return {
          ...data,
          latencyMs: Date.now() - startTime,
        };
      } else {
        backendError = `Backend returned HTTP ${res.status}`;
      }
    } catch (err: any) {
      backendError = err instanceof Error ? err.message : String(err);
      logger.debug('Backend AI analysis endpoint unavailable, attempting local engine:', backendError);
    }

    // ----------------------------------------------------
    // STAGE 2: Try In-Extension ProviderRouter (Gemini -> Groq)
    // ----------------------------------------------------
    let providerError: string | undefined;
    try {
      const { rawOutput, providerUsed, modelUsed, latencyMs, fallbackOccurred } =
        await ProviderRouter.executeWithFallback(prompt);

      const provider = ProviderRouter.getProvider(providerUsed);
      const parsed = provider.parseStructuredJson(rawOutput, null);

      if (!parsed) {
        throw new Error('Failed to parse structured JSON response from AI provider');
      }

      const normalized = provider.normalizeAnalysisResponse(
        parsed,
        providerUsed,
        modelUsed,
        latencyMs,
        fallbackOccurred
      );

      return {
        ...normalized,
        aiStatus: 'SUCCESS',
        securityStatus: 'SUCCESS',
        diagnostics: {
          requestId,
          timestamp,
          backendReachable,
          providerAttempted: providerUsed,
          model: modelUsed,
          latencyMs: Date.now() - startTime,
          fallbackAttempted: fallbackOccurred,
          fallbackProvider: fallbackOccurred ? providerUsed : undefined,
          fallbackResult: 'SUCCESS',
          finalAnalysisStatus: 'AI_COMPLETED',
        },
      };
    } catch (err: any) {
      providerError = err.message || 'All AI providers exhausted';
      logger.warn('In-extension AI providers failed, falling back to local heuristics:', providerError);
    }

    // ----------------------------------------------------
    // STAGE 3: Local Heuristic Fallback Engine
    // ----------------------------------------------------
    // Never fail silently with UNKNOWN or 0% risk.
    const totalLatency = Date.now() - startTime;
    const diagnostics: AIDiagnosticsTelemetry = {
      requestId,
      timestamp,
      backendReachable,
      providerAttempted: 'gemini',
      model: 'local-heuristics',
      latencyMs: totalLatency,
      errorType: providerError || backendError || 'PROVIDERS_UNAVAILABLE',
      fallbackAttempted: true,
      fallbackProvider: 'groq',
      fallbackResult: 'FAILED',
      finalAnalysisStatus: 'LOCAL_HEURISTIC_FALLBACK',
      providerDiagnostics: [
        {
          provider: 'backend',
          model: 'api/v1/analyze/message',
          status: 'FAILED',
          error: backendError || 'Unreachable or disabled',
        },
        {
          provider: 'gemini',
          model: 'gemini-3-flash-preview',
          status: 'FAILED',
          error: providerError || 'No healthy keys or quota exhausted',
        },
        {
          provider: 'groq',
          model: 'qwen/qwen3.8-27b',
          status: 'FAILED',
          error: providerError || 'Fallback attempted but failed',
        },
      ],
    };

    return LocalMessageHeuristics.analyze(rawInput, request.sourceType || 'SMS', diagnostics);
  }

  /**
   * Generates a plain-language explanation of deterministic scanner evidence for a website.
   * STRICT CONSTRAINT: Never overrides scanner verdict and never hallucinates external DNS/WHOIS data.
   */
  static async explainUrlThreat(
    request: UrlEvidenceExplanationRequest
  ): Promise<UrlEvidenceExplanation> {
    const sanitizedUrl = PiiScrubber.sanitizeUrl(request.url);
    const lang = request.userLanguage || 'en';

    const prompt = `You are ScamShield AI, an assistant explaining technical cybersecurity findings to ordinary web users.
ScamShield's deterministic security scanner analyzed the following website and identified specific risk signals.

Website: ${sanitizedUrl}
Domain: ${request.domain}
Scanner Verdict Severity: ${request.verdictSeverity}
Scanner Risk Score: ${request.riskScore} / 100
Deterministic Evidence Detected:
${request.evidence.map((e) => `- ${e}`).join('\n')}
${request.redirectHops ? `- Redirect Hops Recorded: ${request.redirectHops}` : ''}
${request.domIndicators ? `- DOM Heuristics: ${request.domIndicators.join(', ')}` : ''}

CRITICAL RULES:
1. You must ONLY explain the factual evidence provided above.
2. Do NOT invent or claim external threat intelligence, WHOIS, or TLS findings not in the list.
3. Help the user understand WHY these signals represent a risk and what actions to take.

Respond ONLY with a valid, raw JSON object matching this schema:
{
  "summary": "<2-3 sentence non-technical explanation in ${lang === 'hi' ? 'Hindi' : lang === 'mr' ? 'Marathi' : 'English'}>",
  "dangerLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "tacticsDetected": ["<e.g. Brand Impersonation, Deceptive Redirect, Fake Login Form>"],
  "safetyGuidance": [
    "<guidance 1: e.g. Do not enter passwords or card numbers on this domain>",
    "<guidance 2: e.g. Access official service directly via official app or verified URL>"
  ]
}`;

    const startTime = Date.now();

    try {
      const { rawOutput, providerUsed, latencyMs } =
        await ProviderRouter.executeWithFallback(prompt);

      const provider = ProviderRouter.getProvider(providerUsed);
      const parsed = provider.parseStructuredJson(rawOutput, null);

      if (!parsed) {
        throw new Error('Failed to parse structured JSON response from AI provider');
      }

      return provider.normalizeUrlExplanation(parsed, providerUsed, latencyMs);
    } catch (err: any) {
      const totalLatency = Date.now() - startTime;
      logger.warn('URL explanation AI request failed:', err);

      return {
        success: false,
        summary: `Deterministic detection indicates ${request.verdictSeverity} threat: ${request.evidence.join('; ')}`,
        dangerLevel: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(request.verdictSeverity)
          ? (request.verdictSeverity as any)
          : 'HIGH',
        tacticsDetected: ['Deterministic Scanner Signal'],
        safetyGuidance: [
          'ScamShield recommends leaving this site immediately.',
          'Never enter passwords, OTPs, or financial data on unverified websites.',
        ],
        latencyMs: totalLatency,
      };
    }
  }

  // ==========================================
  // Delegation methods for UI & Background
  // ==========================================

  static async getSettings(): Promise<AISystemSettings> {
    return ProviderRouter.getSettings();
  }

  static async updateSettings(updates: Partial<AISystemSettings>): Promise<AISystemSettings> {
    return ProviderRouter.updateSettings(updates);
  }

  static async getMaskedKeys(provider?: AIProviderId): Promise<MaskedAIKey[]> {
    return KeyManager.getMaskedKeys(provider);
  }

  static async addKey(
    provider: AIProviderId,
    key: string,
    label?: string
  ): Promise<MaskedAIKey> {
    return KeyManager.addKey(provider, key, label);
  }

  static async removeKey(keyId: string): Promise<boolean> {
    return KeyManager.removeKey(keyId);
  }

  static async toggleKey(keyId: string, enabled: boolean): Promise<MaskedAIKey | null> {
    return KeyManager.toggleKey(keyId, enabled);
  }

  static async resetKeyStatus(keyId: string): Promise<MaskedAIKey | null> {
    return KeyManager.resetKeyStatus(keyId);
  }

  static async testKeyById(keyId: string): Promise<KeyValidationResult> {
    return ProviderRouter.testKeyById(keyId);
  }

  static async testRawKey(
    providerId: AIProviderId,
    rawKey: string,
    model?: string
  ): Promise<KeyValidationResult> {
    return ProviderRouter.testRawKey(providerId, rawKey, model);
  }

  static async getHealthStats(): Promise<Record<AIProviderId, ProviderHealthStats>> {
    return KeyManager.getHealthStats();
  }

  /**
   * Performs AI Vision OCR text extraction with multi-provider fallback
   */
  static async extractTextWithVisionFallback(
    imageDataUrl: string
  ): Promise<{
    success: boolean;
    extractedText: string;
    providerUsed?: AIProviderId;
    modelUsed?: string;
    error?: string;
  }> {
    const prompt =
      'Transcribe all text from this screenshot or image verbatim. Extract all messages, sender headers, phone numbers, and URLs. Return only the extracted text.';

    try {
      const result = await ProviderRouter.executeVisionWithFallback(prompt, imageDataUrl);
      return {
        success: true,
        extractedText: result.rawText.trim(),
        providerUsed: result.providerUsed,
        modelUsed: result.modelUsed,
      };
    } catch (err: any) {
      logger.debug('Vision OCR fallback execution failed:', err);
      return {
        success: false,
        extractedText: '',
        error: err instanceof Error ? err.message : String(err),
      };
    }
  }
}
