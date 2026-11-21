/**
 * ScamShield AI Engine — Groq Provider
 *
 * Implements Groq fast-inference REST API (OpenAI-compatible /chat/completions).
 * Supports JSON mode and key validation testing.
 */

import { BaseAIProvider } from './base-provider';
import { AIProviderId, KeyValidationResult } from '../types';

export class GroqProvider extends BaseAIProvider {
  readonly id: AIProviderId = 'groq';
  readonly name = 'Groq Fast Inference';

  private readonly endpoint = 'https://api.groq.com/openai/v1/chat/completions';

  /**
   * Executes prompt on Groq API with bounded timeout
   */
  async executeRaw(
    prompt: string,
    model: string,
    apiKey: string,
    timeoutMs: number
  ): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'system',
              content:
                'You are ScamShield AI, a premier cybersecurity scam detection engine. Always respond with strict, valid JSON matching the exact schema requested by the user.',
            },
            {
              role: 'user',
              content: prompt,
            },
          ],
          temperature: 0.1,
          max_tokens: 1024,
          response_format: { type: 'json_object' },
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
      const rawText = data?.choices?.[0]?.message?.content;

      if (!rawText) {
        const err = new Error('Empty response received from Groq API');
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
   * Executes multimodal Vision OCR prompt on Groq API
   */
  async executeVision(
    prompt: string,
    imageDataUrl: string,
    model: string,
    apiKey: string,
    timeoutMs: number
  ): Promise<string> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    // Default to vision-capable model if selected model is text-only
    const visionModel = model.includes('qwen') || model.includes('vision')
      ? model
      : 'qwen/qwen3.8-27b';

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: visionModel,
          messages: [
            {
              role: 'system',
              content:
                'You are ScamShield AI Vision OCR engine. Transcribe all text, messages, URLs, links, and phone numbers from the provided image accurately. Return the extracted text faithfully without omission.',
            },
            {
              role: 'user',
              content: [
                {
                  type: 'text',
                  text: prompt,
                },
                {
                  type: 'image_url',
                  image_url: {
                    url: imageDataUrl,
                  },
                },
              ],
            },
          ],
          temperature: 0.1,
          max_tokens: 1024,
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
      const rawText = data?.choices?.[0]?.message?.content;

      if (!rawText) {
        const err = new Error('Empty response received from Groq Vision API');
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
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [{ role: 'user', content: 'ping' }],
          max_tokens: 5,
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
        sanitizedMessage: 'Groq API key is operational and verified',
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
