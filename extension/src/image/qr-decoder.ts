import jsQR from 'jsqr';
import { ExtractedQrIndicator } from './types';
import { logger } from '../utils/logger';

export class QrDecoder {
  /**
   * Decodes QR code from an image data URL or image buffer
   */
  static async decodeFromDataUrl(dataUrl: string): Promise<ExtractedQrIndicator | null> {
    try {
      // In browser / DOM environments
      if (typeof window !== 'undefined' && typeof document !== 'undefined') {
        return new Promise((resolve) => {
          const img = new Image();
          img.crossOrigin = 'anonymous';

          img.onload = () => {
            try {
              const canvas = document.createElement('canvas');
              const ctx = canvas.getContext('2d', { willReadFrequently: true });
              if (!ctx) {
                resolve(null);
                return;
              }

              canvas.width = img.naturalWidth || img.width;
              canvas.height = img.naturalHeight || img.height;
              ctx.drawImage(img, 0, 0);

              const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
              const code = jsQR(imageData.data, imageData.width, imageData.height);

              if (code && code.data) {
                resolve(this.parseQrPayload(code.data));
              } else {
                resolve(null);
              }
            } catch (err) {
              logger.debug('Canvas QR extraction error:', err);
              resolve(null);
            }
          };

          img.onerror = () => resolve(null);
          img.src = dataUrl;
        });
      }

      return null;
    } catch (err) {
      logger.debug('QR decoding failed:', err);
      return null;
    }
  }

  /**
   * Directly decodes raw ImageData pixel buffer
   */
  static decodeFromImageData(data: Uint8ClampedArray, width: number, height: number): ExtractedQrIndicator | null {
    try {
      const code = jsQR(data, width, height);
      if (code && code.data) {
        return this.parseQrPayload(code.data);
      }
    } catch (err) {
      logger.debug('Raw pixel QR decode failed:', err);
    }
    return null;
  }

  /**
   * Parses decoded QR string into structured indicators (UPI, URL, Text)
   */
  static parseQrPayload(raw: string): ExtractedQrIndicator {
    const trimmed = raw.trim();

    // Check for UPI Payment URI (e.g. upi://pay?pa=name@upi&pn=Name&am=100)
    if (trimmed.toLowerCase().startsWith('upi://pay')) {
      const parsedUpi = this.parseUpiUri(trimmed);
      return {
        rawData: trimmed,
        type: 'UPI',
        decodedUpi: parsedUpi,
      };
    }

    // Check for Web URL
    if (/^https?:\/\//i.test(trimmed) || /^(www\.)?[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/i.test(trimmed)) {
      const normalizedUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      return {
        rawData: trimmed,
        type: 'URL',
        decodedUrl: normalizedUrl,
      };
    }

    return {
      rawData: trimmed,
      type: 'TEXT',
    };
  }

  /**
   * Parses a upi://pay URI into structured UPI details
   */
  private static parseUpiUri(uri: string) {
    try {
      const url = new URL(uri.replace(/^upi:\/\/pay\?/i, 'https://dummy.upi/?'));
      const pa = url.searchParams.get('pa') || '';
      const pn = url.searchParams.get('pn') || '';

      const [handle, provider] = pa.split('@');
      const lowerPa = pa.toLowerCase();
      const isSuspicious =
        lowerPa.includes('refund') ||
        lowerPa.includes('support') ||
        lowerPa.includes('kyc') ||
        lowerPa.includes('cashback') ||
        lowerPa.includes('helpdesk') ||
        lowerPa.includes('reward');

      return {
        original: pa,
        normalized: lowerPa,
        handle: handle || pa,
        provider: provider || 'unknown',
        payeeName: pn,
        isSuspiciousKeyword: isSuspicious,
        riskLevel: isSuspicious ? ('HIGH' as const) : ('LOW' as const),
        riskReason: isSuspicious
          ? `QR encodes UPI ID with high-risk financial fraud lure keywords (${pa})`
          : undefined,
      };
    } catch {
      return {
        original: uri,
        normalized: uri.toLowerCase(),
        handle: uri,
        provider: 'unknown',
        isSuspiciousKeyword: false,
        riskLevel: 'LOW' as const,
      };
    }
  }
}
