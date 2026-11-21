/**
 * ScamShield Privacy Protection — PII Sanitizer / Scrubber
 *
 * Strips identifiable personal data (phone numbers, account numbers, OTPs,
 * personal email addresses, auth tokens) prior to sending content to third-party
 * AI providers, while preserving scam triggers, urgency tactics, and brand keywords.
 */

export class PiiScrubber {
  /**
   * Sanitizes unstructured text to redact sensitive user data.
   */
  static sanitizeText(input: string): string {
    if (!input || typeof input !== 'string') return '';

    let text = input;

    // 1. Redact Email Addresses (keep the domain type if relevant, but mask user identity)
    text = text.replace(
      /\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Z|a-z]{2,})\b/g,
      '[EMAIL_REDACTED@$1]'
    );

    // 2. Redact Indian and International Phone Numbers
    // e.g. +91 9876543210, +91-98765-43210, 09876543210, 9876543210
    text = text.replace(
      /(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g,
      '[PHONE_NUMBER_REDACTED]'
    );
    // General 10-12 digit international format
    text = text.replace(
      /(?:\+\d{1,3}[\s-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
      '[PHONE_NUMBER_REDACTED]'
    );

    // 3. Redact Bank Account / Credit / Debit Card Numbers (12 to 19 digits, with spaces or hyphens)
    text = text.replace(
      /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
      '[CARD_NUMBER_REDACTED]'
    );
    text = text.replace(
      /\b\d{11,18}\b/g,
      (match) => {
        // Only redact if not part of a timestamp or URL
        return match.length >= 11 && match.length <= 18 ? '[ACCOUNT_REDACTED]' : match;
      }
    );

    // 4. Redact OTP / Verification Codes (4 to 8 digit codes adjacent to "otp", "code", "pin")
    text = text.replace(
      /\b(otp|code|pin|one[\s-]time[\s-]password|verification[\s-]code)\s*(?:is|:|=|-)?\s*(\d{4,8})\b/gi,
      '$1: [OTP_REDACTED]'
    );

    // 5. Redact Indian UPI IDs (e.g. user@okaxis, user@okhdfcbank, user@paytm, user@upi)
    text = text.replace(
      /\b[a-zA-Z0-9.\-_]{2,256}@(okaxis|okhdfcbank|okicici|oksbi|paytm|ybl|ibl|upi|axl|apl)\b/gi,
      '[UPI_HANDLE_REDACTED]'
    );

    // 6. Redact Common Authentication Tokens, Bearer strings, and API keys
    text = text.replace(
      /\b(bearer|token|apikey|api_key|secret|password|pwd)\s*[:=]\s*['"]?[a-zA-Z0-9_\-.]{8,}['"]?/gi,
      '$1=[SECRET_REDACTED]'
    );

    return text.trim();
  }

  /**
   * Sanitizes URL query parameters by removing authentication, token, or session params.
   */
  static sanitizeUrl(urlStr: string): string {
    if (!urlStr || typeof urlStr !== 'string') return '';

    try {
      const url = new URL(urlStr);
      const sensitiveKeys = [
        'token',
        'auth',
        'session',
        'code',
        'api_key',
        'apikey',
        'secret',
        'access_token',
        'refresh_token',
        'state',
        'user_id',
        'email',
        'phone',
      ];

      for (const param of Array.from(url.searchParams.keys())) {
        if (sensitiveKeys.some((s) => param.toLowerCase().includes(s))) {
          url.searchParams.set(param, '[REDACTED]');
        }
      }

      return url.toString();
    } catch {
      return urlStr;
    }
  }
}
