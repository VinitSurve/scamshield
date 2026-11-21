/**
 * ScamShield WhatsApp Bot & Backend AI Threat Analysis Engine
 *
 * Implements multi-provider AI pipeline (Gemini + Groq) with:
 * - Multi-key pool rotation
 * - Rate-limit (429) & quota-exhaustion handling
 * - Automatic provider fallback (Gemini -> Groq)
 * - Model auto-recovery on 404 (using verified active models)
 * - Complete developer diagnostics telemetry (never exposing secrets)
 * - Transparent offline local heuristic analysis fallback
 */

import { config } from './config.js';

export interface BackendAnalysisResult {
  success: boolean;
  classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM' | 'MALICIOUS' | 'UNKNOWN';
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidenceScore: number;
  scamCategory: string;
  summary: string;
  socialEngineeringTactics: string[];
  indicators: Array<{
    type: string;
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
  }>;
  extractedEntities: {
    brandImpersonated?: string;
    suspiciousUrls?: string[];
    paymentRequests?: string[];
    requestedActions?: string[];
  };
  recommendedActions: string[];
  explanation: string;
  providerUsed?: 'gemini' | 'groq';
  modelUsed?: string;
  latencyMs: number;
  fallbackOccurred: boolean;
  aiStatus: 'SUCCESS' | 'FAILED' | 'UNAVAILABLE';
  securityStatus: 'SUCCESS' | 'FAILED';
  isLocalHeuristicFallback?: boolean;
  diagnostics: {
    requestId: string;
    timestamp: string;
    backendReachable: boolean;
    providerAttempted?: string;
    model?: string;
    providerAttemptNumber?: number;
    httpStatus?: number;
    latencyMs: number;
    errorType?: string;
    fallbackAttempted: boolean;
    fallbackProvider?: string;
    fallbackResult?: string;
    finalAnalysisStatus: 'AI_COMPLETED' | 'LOCAL_HEURISTIC_FALLBACK' | 'ANALYSIS_UNAVAILABLE';
    providerDiagnostics: Array<{
      provider: string;
      model: string;
      status: 'SUCCESS' | 'FAILED';
      error?: string;
      httpStatus?: number;
      latencyMs?: number;
    }>;
  };
}

export class BackendAIEngine {
  // Key indices for round-robin rotation
  private static geminiKeyIndex = 0;
  private static groqKeyIndex = 0;

  // Key cooldown tracking: keyId -> cooldownUntil timestamp
  private static keyCooldowns = new Map<string, number>();

  /**
   * Builds strict JSON prompt for message scam analysis
   */
  private static buildPrompt(messageText: string, sourceType = 'SMS', lang = 'en'): string {
    return `Analyze the following ${sourceType} message for scam and fraud indicators.
Message text:
"""
${messageText}
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
  }

  /**
   * Analyzes message using multi-provider AI pipeline with key rotation and local heuristic fallback
   */
  static async analyzeMessage(
    messageText: string,
    sourceType = 'SMS',
    userLanguage = 'en'
  ): Promise<BackendAnalysisResult> {
    const overallStart = Date.now();
    const requestId = `req_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = new Date().toISOString();

    const providerDiagnostics: Array<{
      provider: string;
      model: string;
      status: 'SUCCESS' | 'FAILED';
      error?: string;
      httpStatus?: number;
      latencyMs?: number;
    }> = [];

    let fallbackAttempted = false;
    let fallbackProvider: string | undefined;
    let fallbackResult: string | undefined;

    const prompt = this.buildPrompt(messageText, sourceType, userLanguage);

    // ----------------------------------------------------
    // STAGE 1: Attempt Gemini Provider (Multi-Key Rotation)
    // ----------------------------------------------------
    const geminiKeys = config.geminiApiKeys.filter((k) => !this.isCoolingDown(`gemini_${k}`));
    if (geminiKeys.length > 0) {
      for (let attempt = 0; attempt < Math.min(geminiKeys.length, 3); attempt++) {
        const keyIdx = (this.geminiKeyIndex + attempt) % geminiKeys.length;
        const key = geminiKeys[keyIdx];
        const keyId = `gemini_${key}`;
        const model = 'gemini-3-flash-preview';

        const callStart = Date.now();
        try {
          const res = await this.callGemini(prompt, model, key);
          const latencyMs = Date.now() - callStart;

          this.geminiKeyIndex = (keyIdx + 1) % geminiKeys.length;

          providerDiagnostics.push({
            provider: 'gemini',
            model,
            status: 'SUCCESS',
            httpStatus: 200,
            latencyMs,
          });

          return {
            ...res,
            providerUsed: 'gemini',
            modelUsed: model,
            latencyMs: Date.now() - overallStart,
            fallbackOccurred: false,
            aiStatus: 'SUCCESS',
            securityStatus: 'SUCCESS',
            diagnostics: {
              requestId,
              timestamp,
              backendReachable: true,
              providerAttempted: 'gemini',
              model,
              providerAttemptNumber: attempt + 1,
              httpStatus: 200,
              latencyMs,
              fallbackAttempted: false,
              finalAnalysisStatus: 'AI_COMPLETED',
              providerDiagnostics,
            },
          };
        } catch (err: any) {
          const latencyMs = Date.now() - callStart;
          const status = err.status || 500;
          const errorMsg = err.message || 'Gemini request failed';

          providerDiagnostics.push({
            provider: 'gemini',
            model,
            status: 'FAILED',
            error: errorMsg,
            httpStatus: status,
            latencyMs,
          });

          if (status === 429) {
            this.setCooldown(keyId, 60); // 60s cooldown for rate limit
          } else if (status === 401 || status === 403) {
            this.setCooldown(keyId, 3600); // 1 hour cooldown for auth errors
          }
        }
      }
    } else {
      providerDiagnostics.push({
        provider: 'gemini',
        model: 'gemini-3-flash-preview',
        status: 'FAILED',
        error: 'No active Gemini API keys available',
      });
    }

    // ----------------------------------------------------
    // STAGE 2: Fallback to Groq Provider (Multi-Key Rotation)
    // ----------------------------------------------------
    fallbackAttempted = true;
    fallbackProvider = 'groq';

    const groqKeys = config.groqApiKeys.filter((k) => !this.isCoolingDown(`groq_${k}`));
    if (groqKeys.length > 0) {
      // Use verified active Groq models in order of capability
      const groqModels = ['qwen/qwen3.8-27b', 'openai/gpt-oss-120b', 'openai/gpt-oss-20b'];

      for (let attempt = 0; attempt < Math.min(groqKeys.length, 3); attempt++) {
        const keyIdx = (this.groqKeyIndex + attempt) % groqKeys.length;
        const key = groqKeys[keyIdx];
        const keyId = `groq_${key}`;

        for (const model of groqModels) {
          const callStart = Date.now();
          try {
            const res = await this.callGroq(prompt, model, key);
            const latencyMs = Date.now() - callStart;

            this.groqKeyIndex = (keyIdx + 1) % groqKeys.length;
            fallbackResult = 'SUCCESS';

            providerDiagnostics.push({
              provider: 'groq',
              model,
              status: 'SUCCESS',
              httpStatus: 200,
              latencyMs,
            });

            return {
              ...res,
              providerUsed: 'groq',
              modelUsed: model,
              latencyMs: Date.now() - overallStart,
              fallbackOccurred: true,
              aiStatus: 'SUCCESS',
              securityStatus: 'SUCCESS',
              diagnostics: {
                requestId,
                timestamp,
                backendReachable: true,
                providerAttempted: 'gemini',
                model,
                providerAttemptNumber: attempt + 1,
                httpStatus: 200,
                latencyMs,
                fallbackAttempted: true,
                fallbackProvider: 'groq',
                fallbackResult: 'SUCCESS',
                finalAnalysisStatus: 'AI_COMPLETED',
                providerDiagnostics,
              },
            };
          } catch (err: any) {
            const latencyMs = Date.now() - callStart;
            const status = err.status || 500;
            const errorMsg = err.message || 'Groq request failed';

            providerDiagnostics.push({
              provider: 'groq',
              model,
              status: 'FAILED',
              error: errorMsg,
              httpStatus: status,
              latencyMs,
            });

            if (status === 404) {
              // Model not found on this account tier: try next candidate model immediately
              continue;
            }

            if (status === 429) {
              this.setCooldown(keyId, 60);
              break; // Try next key
            } else if (status === 401 || status === 403) {
              this.setCooldown(keyId, 3600);
              break; // Try next key
            }
          }
        }
      }
    } else {
      providerDiagnostics.push({
        provider: 'groq',
        model: 'qwen/qwen3.8-27b',
        status: 'FAILED',
        error: 'No active Groq API keys available',
      });
    }

    fallbackResult = 'FAILED';

    // ----------------------------------------------------
    // STAGE 3: Local Heuristic Fallback Engine
    // ----------------------------------------------------
    // When all AI providers are exhausted, offline, or unavailable,
    // evaluate the message deterministically using local heuristics.
    const localResult = this.evaluateLocalHeuristics(messageText, sourceType);
    const totalLatency = Date.now() - overallStart;

    return {
      ...localResult,
      latencyMs: totalLatency,
      fallbackOccurred: true,
      aiStatus: 'FAILED',
      securityStatus: 'SUCCESS',
      isLocalHeuristicFallback: true,
      diagnostics: {
        requestId,
        timestamp,
        backendReachable: true,
        providerAttempted: 'gemini',
        model: 'groq:fallback_failed',
        latencyMs: totalLatency,
        errorType: 'ALL_PROVIDERS_EXHAUSTED',
        fallbackAttempted: true,
        fallbackProvider: 'groq',
        fallbackResult: 'FAILED',
        finalAnalysisStatus: 'LOCAL_HEURISTIC_FALLBACK',
        providerDiagnostics,
      },
    };
  }

  /**
   * Calls Google Gemini API
   */
  private static async callGemini(prompt: string, model: string, apiKey: string): Promise<any> {
    const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: prompt }] }],
          generationConfig: {
            temperature: 0.1,
            maxOutputTokens: 1024,
            responseMimeType: 'application/json',
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errText = await response.text();
        const err = new Error(`Gemini API HTTP ${response.status}: ${errText.substring(0, 150)}`);
        (err as any).status = response.status;
        throw err;
      }

      const data = await response.json();
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!rawText) throw new Error('Empty response from Gemini');

      return JSON.parse(rawText);
    } catch (err: any) {
      clearTimeout(timer);
      throw err;
    }
  }

  /**
   * Calls Groq Fast Inference API
   */
  private static async callGroq(prompt: string, model: string, apiKey: string): Promise<any> {
    const endpoint = 'https://api.groq.com/openai/v1/chat/completions';
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
          'User-Agent': 'ScamShield-Backend/1.0',
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content:
                'You are ScamShield AI cybersecurity analyzer. Always respond with strict, valid JSON matching the exact schema requested by the user.',
            },
            { role: 'user', content: prompt },
          ],
          temperature: 0.1,
          max_tokens: 1024,
          response_format: { type: 'json_object' },
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);

      if (!response.ok) {
        const errText = await response.text();
        const err = new Error(`Groq API HTTP ${response.status}: ${errText.substring(0, 150)}`);
        (err as any).status = response.status;
        throw err;
      }

      const data = await response.json();
      const rawText = data?.choices?.[0]?.message?.content;
      if (!rawText) throw new Error('Empty response from Groq');

      return JSON.parse(rawText);
    } catch (err: any) {
      clearTimeout(timer);
      throw err;
    }
  }

  /**
   * Deterministic local heuristic analysis fallback
   */
  static evaluateLocalHeuristics(messageText: string, sourceType: string): any {
    const text = messageText.trim();
    const lower = text.toLowerCase();

    // Impersonation detection
    let brand: string | null = null;
    if (/\b(sbi|state\s*bank|yono)\b/i.test(text)) brand = 'SBI';
    else if (/\b(hdfc)\b/i.test(text)) brand = 'HDFC';
    else if (/\b(icici)\b/i.test(text)) brand = 'ICICI';
    else if (/\b(phone\s*pe)\b/i.test(text)) brand = 'PhonePe';
    else if (/\b(paytm)\b/i.test(text)) brand = 'Paytm';
    else if (/\b(electricity|bijli)\b/i.test(text)) brand = 'Electricity Office';

    const kyc = /\b(kyc|pan(\s*card)?|aadhaar|re-?kyc)\b/i.test(text);
    const urgency = /\b(urgent|immediately|blocked(\s*today)?|block|suspend(ed)?|disconnect(ed)?|within\s*24\s*hours?)\b/i.test(text);
    const otp = /\b(otp|one\s*time\s*password|upi\s*pin|cvv|password)\b/i.test(text);
    const urls = text.match(/(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi) || [];
    const phones = text.match(/(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g) || [];

    const indicators: any[] = [];
    if (brand) {
      indicators.push({
        type: 'BRAND_IMPERSONATION',
        description: `Message impersonates official entity: ${brand}`,
        severity: 'HIGH',
      });
    }
    if (kyc) {
      indicators.push({
        type: 'KYC_FRAUD_LURE',
        description: 'Demands urgent KYC verification or documentation update',
        severity: 'HIGH',
      });
    }
    if (urgency) {
      indicators.push({
        type: 'COERCIVE_THREAT',
        description: 'Pressures recipient with immediate account blockage, disconnection, or suspension',
        severity: 'HIGH',
      });
    }
    for (const u of urls) {
      indicators.push({
        type: 'SUSPICIOUS_URL',
        description: `Contains external unverified link: ${u}`,
        severity: 'HIGH',
      });
    }
    for (const p of phones) {
      indicators.push({
        type: 'UNOFFICIAL_CONTACT',
        description: `Directs contact to non-bank mobile number: ${p}`,
        severity: 'MEDIUM',
      });
    }

    let classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM' = 'SAFE';
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let confidenceScore = 0.05;
    let scamCategory = 'LEGITIMATE_COMMUNICATION';

    if (brand === 'Electricity Office' || /\b(electricity|bijli)\b/i.test(text)) {
      classification = 'SCAM';
      riskLevel = 'HIGH';
      confidenceScore = 0.90;
      scamCategory = 'ELECTRICITY_BILL_SCAM';
    } else if (brand && (kyc || urgency)) {
      classification = 'SCAM';
      riskLevel = 'HIGH';
      confidenceScore = 0.92;
      scamCategory = 'BANKING_KYC_PHISHING';
    } else if (otp) {
      classification = 'SCAM';
      riskLevel = 'CRITICAL';
      confidenceScore = 0.95;
      scamCategory = 'OTP_CREDENTIAL_THEFT';
    } else if (urgency && (urls.length > 0 || phones.length > 0)) {
      classification = 'SUSPICIOUS';
      riskLevel = 'HIGH';
      confidenceScore = 0.80;
      scamCategory = 'URGENT_COERCION_PHISHING';
    } else if (urls.length > 0) {
      classification = 'SUSPICIOUS';
      riskLevel = 'MEDIUM';
      confidenceScore = 0.50;
      scamCategory = 'UNVERIFIED_LINK_COMMUNICATION';
    }

    const detectedPoints: string[] = [];
    if (brand) detectedPoints.push(`${brand} brand impersonation`);
    if (kyc) detectedPoints.push('KYC-related request');
    if (urgency) detectedPoints.push('Account suspension threat');
    if (urls.length > 0) detectedPoints.push('Suspicious URL');
    if (phones.length > 0) detectedPoints.push('Unverified mobile contact');

    const summary =
      classification === 'SAFE'
        ? 'Local security analysis detected no obvious phishing indicators, brand impersonation lures, or coercive suspension threats.'
        : `AI ANALYSIS UNAVAILABLE. Provider requests failed or were offline. However, local security checks detected:\n• ${detectedPoints.join('\n• ')}\n\nLocal assessment: ${riskLevel === 'CRITICAL' ? 'CRITICAL RISK' : 'HIGH RISK'}.\n(This result is based on local heuristic analysis, not AI inference.)`;

    const actions =
      classification === 'SAFE'
        ? ['Message appears normal. Exercise standard vigilance with unexpected links.']
        : [
            ...(urls.length > 0 ? [`Do NOT click on ${urls[0]}`] : []),
            ...(phones.length > 0 ? [`Do NOT call the mobile number ${phones[0]}`] : []),
            'Never share OTP, PIN, or confidential bank details.',
            'Report fraudulent messages to 1930 or cybercrime.gov.in',
          ];

    return {
      success: true,
      classification,
      riskLevel,
      confidenceScore,
      scamCategory,
      summary,
      socialEngineeringTactics: [
        ...(urgency ? ['Urgency / Deadline pressure'] : []),
        ...(brand === 'Electricity Office' || /\b(electricity|bijli)\b/i.test(text) ? ['Fear / Disconnection penalty'] : []),
        ...(kyc ? ['Account blockage fear'] : []),
        ...(otp ? ['Credential theft'] : []),
      ],
      indicators,
      extractedEntities: {
        brandImpersonated: brand || undefined,
        suspiciousUrls: urls.length > 0 ? urls : undefined,
        paymentRequests: undefined,
        requestedActions: kyc ? ['Update KYC immediately'] : undefined,
      },
      recommendedActions: actions,
      explanation:
        classification === 'SAFE'
          ? 'Message exhibits standard communication patterns without suspicious coercion or malicious links.'
          : 'ScamShield local heuristics identified severe red flags common in digital financial fraud.',
    };
  }

  private static isCoolingDown(keyId: string): boolean {
    const cd = this.keyCooldowns.get(keyId);
    if (!cd) return false;
    if (Date.now() > cd) {
      this.keyCooldowns.delete(keyId);
      return false;
    }
    return true;
  }

  private static setCooldown(keyId: string, seconds: number): void {
    this.keyCooldowns.set(keyId, Date.now() + seconds * 1000);
  }
}
