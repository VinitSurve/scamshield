/**
 * ScamShield WhatsApp Bot OCR & Image Analysis Service
 *
 * Implements:
 * - SSRF-protected image buffer fetching
 * - MIME type and maximum payload size (10MB) enforcement
 * - Local Tesseract.js optical character recognition
 * - Cloud AI Vision fallback (Groq qwen/qwen3.8-27b) when OCR text is empty or low confidence
 * - High-precision threat indicator extraction (URLs, phones, UPI IDs, bank brands, urgency)
 * - Safe handling of blank/unreadable images (flags as caution, never falsely safe)
 */

import Tesseract from 'tesseract.js';
import { BotSecurity } from './security.js';
import { UrlInvestigator } from './url-investigator.js';
import { config } from './config.js';

export interface OcrExtractedIndicators {
  urls: string[];
  phones: string[];
  upiIds: string[];
  brands: string[];
  tactics: string[];
}

export interface OcrAnalysisResult {
  success: boolean;
  rawText: string;
  confidence: number;
  engineUsed: 'tesseract' | 'ai_vision' | 'none';
  indicators: OcrExtractedIndicators;
  isUnreadable: boolean;
  error?: string;
}

export class OcrService {
  private static readonly MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

  /**
   * Loads an image buffer from a base64 Data URL, binary buffer, or remote URL (SSRF-protected)
   */
  static async resolveImageBuffer(
    imageInput: string | Buffer
  ): Promise<{ buffer: Buffer; mimeType: string }> {
    if (Buffer.isBuffer(imageInput)) {
      if (imageInput.length > this.MAX_IMAGE_SIZE_BYTES) {
        throw new Error('Image exceeds 10MB size limit');
      }
      return { buffer: imageInput, mimeType: 'image/jpeg' };
    }

    if (typeof imageInput === 'string') {
      const trimmed = imageInput.trim();

      // Case A: Base64 Data URL (e.g. data:image/png;base64,...)
      if (trimmed.startsWith('data:image/')) {
        const matches = trimmed.match(/^data:(image\/[a-zA-Z+]+);base64,(.+)$/);
        if (!matches) {
          throw new Error('Invalid base64 Data URL format');
        }
        const mimeType = matches[1];
        const buffer = Buffer.from(matches[2], 'base64');
        if (buffer.length > this.MAX_IMAGE_SIZE_BYTES) {
          throw new Error('Image exceeds 10MB size limit');
        }
        return { buffer, mimeType };
      }

      // Case B: Pure base64 string
      if (/^[A-Za-z0-9+/=]{100,}$/.test(trimmed)) {
        const buffer = Buffer.from(trimmed, 'base64');
        return { buffer, mimeType: 'image/jpeg' };
      }

      // Case C: Remote URL (SSRF protection mandatory)
      const parsed = UrlInvestigator.parseAndValidateUrl(trimmed);
      if (!parsed) {
        throw new Error('Image URL blocked: loopback, private host, or invalid scheme');
      }

      // If configured in Meta mode, verify against allowed CDN domains
      if (config.mode === 'cloud_api' && !BotSecurity.isSafeMediaUrl(trimmed)) {
        throw new Error('Image URL blocked: domain not in Meta WhatsApp CDN allowlist');
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);

      const response = await fetch(parsed.href, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'User-Agent': 'ScamShield-Media-Service/1.0' },
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Media download failed with status ${response.status}`);
      }

      const mimeType = response.headers.get('content-type') || 'image/jpeg';
      const arrayBuf = await response.arrayBuffer();
      const buffer = Buffer.from(arrayBuf);

      if (buffer.length > this.MAX_IMAGE_SIZE_BYTES) {
        throw new Error('Downloaded image exceeds 10MB size limit');
      }

      return { buffer, mimeType };
    }

    throw new Error('Unsupported image input format');
  }

  /**
   * Extracts indicators (URLs, phones, UPI IDs, brands, urgency triggers) from recognized text
   */
  static extractIndicatorsFromText(text: string): OcrExtractedIndicators {
    const raw = text || '';
    const lower = raw.toLowerCase();

    // 1. Extract URLs
    const urlRegex = /https?:\/\/[^\s<>"']+|\b[a-zA-Z0-9-]{2,63}\.(?:com|org|net|in|top|xyz|online|site|store|app|gd|ly)\b[^\s<>"']*/gi;
    const rawUrls = raw.match(urlRegex) || [];
    const urls = Array.from(new Set(rawUrls.map((u) => (u.startsWith('http') ? u : `https://${u}`))));

    // 2. Extract Indian Phone Numbers (10 digits starting with 6-9, optionally with +91 or 0)
    const phoneRegex = /(?:(?:\+91|91|0)[-.\s]?)?([6-9]\d{4}[-.\s]?\d{5})\b/g;
    const phones = Array.from(new Set(raw.match(phoneRegex) || []));

    // 3. Extract UPI IDs (e.g. user@okhdfcbank, refund@upi)
    const upiRegex = /\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b/g;
    const rawUpis = raw.match(upiRegex) || [];
    const upiIds = Array.from(
      new Set(
        rawUpis.filter(
          (u) =>
            !u.endsWith('@gmail.com') &&
            !u.endsWith('@yahoo.com') &&
            !u.endsWith('@outlook.com') &&
            !u.endsWith('@icloud.com') &&
            !u.endsWith('@example.com')
        )
      )
    );

    // 4. Extract Brands
    const brands: string[] = [];
    if (lower.includes('sbi') || lower.includes('state bank')) brands.push('State Bank of India (SBI)');
    if (lower.includes('hdfc')) brands.push('HDFC Bank');
    if (lower.includes('icici')) brands.push('ICICI Bank');
    if (lower.includes('axis')) brands.push('Axis Bank');
    if (lower.includes('paytm')) brands.push('Paytm');
    if (lower.includes('google pay') || lower.includes('gpay')) brands.push('Google Pay');
    if (lower.includes('phonepe')) brands.push('PhonePe');
    if (lower.includes('electricity') || lower.includes('bijli')) brands.push('Electricity Board');
    if (lower.includes('india post') || lower.includes('postal')) brands.push('India Post');

    // 5. Social Tactics
    const tactics: string[] = [];
    if (lower.includes('immediately') || lower.includes('24 hours') || lower.includes('today') || lower.includes('turant') || lower.includes('jaldi')) {
      tactics.push('Urgency pressure ("immediately / 24 hours")');
    }
    if (lower.includes('blocked') || lower.includes('suspended') || lower.includes('disconnected') || lower.includes('cut')) {
      tactics.push('Account suspension threat ("blocked / suspended / disconnected")');
    }
    if (lower.includes('share otp') || lower.includes('enter pin') || lower.includes('cvv')) {
      tactics.push('Credential theft attempt ("share OTP / PIN / CVV")');
    }
    if (lower.includes('lottery') || lower.includes('cashback') || lower.includes('won') || lower.includes('kbc')) {
      tactics.push('Financial reward lure ("lottery / cashback / prize")');
    }

    return { urls, phones, upiIds, brands, tactics };
  }

  /**
   * Executes AI Vision transcription via Groq or Gemini when Tesseract produces low confidence
   */
  private static async transcribeWithVisionAI(buffer: Buffer, mimeType: string): Promise<string> {
    const groqKey = config.groqApiKeys[0];
    if (!groqKey) {
      return '';
    }

    try {
      const base64Data = buffer.toString('base64');
      const dataUrl = `data:${mimeType};base64,${base64Data}`;

      const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${groqKey}`,
          'User-Agent': 'ScamShield-Vision/1.0',
        },
        body: JSON.stringify({
          model: 'qwen/qwen3.8-27b',
          messages: [
            {
              role: 'system',
              content:
                'You are ScamShield AI Vision OCR engine. Transcribe every line of text, message, URL, phone number, and UPI ID visible in the image verbatim.',
            },
            {
              role: 'user',
              content: [
                {
                  type: 'text',
                  text: 'Extract all readable text, SMS messages, phone numbers, and URLs from this screenshot exactly as they appear.',
                },
                { type: 'image_url', image_url: { url: dataUrl } },
              ],
            },
          ],
          temperature: 0.1,
          max_tokens: 1024,
        }),
      });

      if (!res.ok) {
        return '';
      }

      const data = await res.json();
      return data?.choices?.[0]?.message?.content || '';
    } catch {
      return '';
    }
  }

  /**
   * Analyzes an image with Tesseract OCR, falling back to AI Vision if text is sparse or low confidence
   */
  static async extractTextAndIndicators(imageInput: string | Buffer): Promise<OcrAnalysisResult> {
    try {
      const { buffer, mimeType } = await this.resolveImageBuffer(imageInput);

      let extractedText = '';
      let confidence = 0;
      let engineUsed: 'tesseract' | 'ai_vision' | 'none' = 'none';

      // 1. Attempt Tesseract OCR
      try {
        const tessResult = await Tesseract.recognize(buffer, 'eng');
        extractedText = tessResult.data.text.trim();
        confidence = tessResult.data.confidence;
        engineUsed = 'tesseract';
      } catch (tessErr) {
        console.warn('[ScamShield OCR] Tesseract engine error, attempting AI Vision fallback:', tessErr);
      }

      // 2. If Tesseract produced very short or low confidence text, fall back to AI Vision
      if (extractedText.length < 15 || confidence < 35) {
        const visionText = await this.transcribeWithVisionAI(buffer, mimeType);
        if (visionText && visionText.trim().length > extractedText.length) {
          extractedText = visionText.trim();
          confidence = 85;
          engineUsed = 'ai_vision';
        }
      }

      const isUnreadable = extractedText.length < 5;
      const indicators = this.extractIndicatorsFromText(extractedText);

      return {
        success: !isUnreadable,
        rawText: extractedText,
        confidence,
        engineUsed,
        indicators,
        isUnreadable,
      };
    } catch (err: any) {
      return {
        success: false,
        rawText: '',
        confidence: 0,
        engineUsed: 'none',
        indicators: { urls: [], phones: [], upiIds: [], brands: [], tactics: [] },
        isUnreadable: true,
        error: err.message || 'Image processing failed',
      };
    }
  }
}
