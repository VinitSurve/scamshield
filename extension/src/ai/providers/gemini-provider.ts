/**
 * ScamShield AI Engine — Google Gemini Provider
 *
 * Implements Google Gemini REST API v1beta via generateContent.
 * Supports structured JSON responses and key validation testing.
 */

import { BaseAIProvider } from './base-provider';
import { AIProviderId, KeyValidationResult } from '../types';

export class GeminiProvider extends BaseAIProvider {
  readonly id: AIProviderId = 'gemini';
  readonly name = 'Google Gemini';

  private readonly baseUrl = 'https://generativelanguage.googleapis.com/v1beta/models';

  /**
   * Executes prompt on Gemini API with bounded timeout
   */
  async executeRaw(
    prompt: string,
    model: string,
    apiKey: string,
    timeoutMs: number
  ): Promise<string> {
    const endpoint = `${this.baseUrl}/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [
            {
              role: 'user',
              parts: [{ text: prompt }],
            },
          ],
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
        let errJson: any;
        try {
          errJson = await response.json();
        } catch {
          errJson = null;
        }

        const classified = this.classifyError(response.status, errJson);
        const err = new Error(classified.sanitizedMessage);
        (err as any).category = classified.category;
        (err as any).statusCode = response.status;
        (err as any).retryAfterSeconds = classified.retryAfterSeconds;
        throw err;
      }

      const data = await response.json();
      const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;

      if (!rawText) {
        const err = new Error('Empty or blocked response from Gemini API');
        (err as any).category = 'MALFORMED_RESPONSE';
        throw err;
      }

      return rawText;
    } catch (err: any) {
      clearTimeout(timer);
      if (err.category) throw err;

      const classified = this.classifyError(0, null, err);
      const wrapped = new Error(classified.sanitizedMessage);
      (wrapped as any).category = classified.category;
      throw wrapped;
    }
  }

  /**
   * Tests API key validity with a minimal 5-token ping
   */
  async validateKey(
    apiKey: string,
    model: string,
    timeoutMs: number
  ): Promise<KeyValidationResult> {
    const startTime = Date.now();
    const endpoint = `${this.baseUrl}/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          contents: [
            {
              role: 'user',
              parts: [{ text: 'ping' }],
            },
          ],
          generationConfig: {
            maxOutputTokens: 5,
          },
        }),
        signal: controller.signal,
      });

      clearTimeout(timer);
      const latencyMs = Date.now() - startTime;

      if (!response.ok) {
        let errJson: any;
        try {
          errJson = await response.json();
        } catch {
          errJson = null;
        }

        const classified = this.classifyError(response.status, errJson);
        return {
          valid: false,
          providerId: this.id,
          statusCode: response.status,
          errorCategory: classified.category,
          sanitizedMessage: classified.sanitizedMessage,
          latencyMs,
        };
      }

      return {
        valid: true,
        providerId: this.id,
        statusCode: 200,
        sanitizedMessage: 'Gemini API key is operational and verified',
        latencyMs,
      };
    } catch (err: any) {
      clearTimeout(timer);
      const latencyMs = Date.now() - startTime;
      const classified = this.classifyError(0, null, err);

      return {
        valid: false,
        providerId: this.id,
        errorCategory: classified.category,
        sanitizedMessage: classified.sanitizedMessage,
        latencyMs,
      };
    }
  }
}
