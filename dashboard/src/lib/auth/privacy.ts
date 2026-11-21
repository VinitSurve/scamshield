/**
 * ScamShield Privacy & PII Redaction Engine
 *
 * Automatically redacts sensitive personal data (cards, account numbers, personal phone numbers, OTPs)
 * before storing or rendering public community posts to prevent doxxing and protect citizen privacy.
 */

export function redactSensitivePii(text: string): string {
  if (!text) return '';
  let s = text;

  // 1. Credit / Debit Card Numbers (13-19 digits, with or without spaces/dashes)
  s = s.replace(/\b(?:\d{4}[-\s]?){3}\d{4}\b/g, (match) => {
    const digits = match.replace(/\D/g, '');
    return `${digits.slice(0, 4)} **** **** ${digits.slice(-4)}`;
  });

  // 2. Bank Account Numbers (9 to 18 digits preceded by a/c, acct, account)
  s = s.replace(/\b(a\/?c|acct|account(?:\s+no)?)\s*[:#-]?\s*(\d{4,18})\b/gi, (_match, prefix, num) => {
    return `${prefix} ****${num.slice(-4)}`;
  });

  // 3. Indian Phone Numbers (keep first 2 and last 2 digits, mask middle 6)
  s = s.replace(/(?:\+91|0)?[-\s]?([6-9]\d{2})[-\s]?(\d{3})[-\s]?(\d{4})/g, (_match, p1, _p2, p3) => {
    return `+91 ${p1.slice(0, 2)}****${p3.slice(-2)}`;
  });

  // 4. One-Time Passwords (OTPs)
  s = s.replace(/\b(otp|one[-\s]?time[-\s]?password|pin|code)\s*[:#-]?\s*(\d{4,8})\b/gi, (_match, prefix, _code) => {
    return `${prefix} ******`;
  });

  return s;
}

/**
 * Sanitizes input text against XSS and formula injection
 */
export function sanitizeInput(input: string): string {
  if (!input) return '';
  let cleaned = input.trim();

  // Strip formula execution characters if text starts with CSV formulas
  if (/^[=+\-@]/.test(cleaned)) {
    cleaned = `'${cleaned}`;
  }

  // Basic HTML entity encoding for safety
  return cleaned
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

export const RedactionService = {
  redactPII: redactSensitivePii,
  sanitize: sanitizeInput,
};
