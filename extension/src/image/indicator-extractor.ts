import {
  ExtractedIndicators,
  ExtractedUrlIndicator,
  ExtractedPhoneIndicator,
  ExtractedUpiIndicator,
  ExtractedEmailIndicator,
} from './types';
import { canonicalizeUrl } from '../security/url-validator';

const URL_SHORTENERS = new Set([
  'bit.ly',
  'tinyurl.com',
  't.co',
  'cutt.ly',
  'is.gd',
  'rb.gy',
  'shorturl.at',
  'ow.ly',
  'rebrand.ly',
]);

const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com',
  'yahoo.com',
  'yahoo.co.in',
  'outlook.com',
  'hotmail.com',
  'rediffmail.com',
  'proton.me',
  'protonmail.com',
  'icloud.com',
]);

const KNOWN_UPI_VPA_PROVIDERS = new Set([
  'okhdfcbank',
  'okicici',
  'oksbi',
  'okaxis',
  'paytm',
  'ybl',
  'upi',
  'ibl',
  'axl',
  'barodampay',
  'idfcbank',
  'kotak',
  'postbank',
  'federal',
  'jupiteraxis',
  'fbl',
  'indus',
  'yesbank',
  'aubank',
  'freecharge',
]);

const SUSPICIOUS_UPI_KEYWORDS = [
  'refund',
  'support',
  'cashback',
  'kyc',
  'helpdesk',
  'reward',
  'gift',
  'bonus',
  'update',
  'verify',
  'service',
  'care',
  'tollfree',
];

const SOCIAL_ENGINEERING_PATTERNS = [
  { keyword: 'immediately', category: 'Urgency Pressure' },
  { keyword: 'within 24 hours', category: 'Urgency Pressure' },
  { keyword: 'within 12 hours', category: 'Urgency Pressure' },
  { keyword: 'today itself', category: 'Urgency Pressure' },
  { keyword: 'expiring today', category: 'Urgency Pressure' },
  { keyword: 'urgent notice', category: 'Urgency Pressure' },
  { keyword: 'turant', category: 'Urgency Pressure (Hindi)' },
  { keyword: 'jaldi', category: 'Urgency Pressure (Hindi)' },
  { keyword: 'tatkal', category: 'Urgency Pressure (Hindi)' },
  { keyword: 'account suspended', category: 'Threat / Account Block' },
  { keyword: 'account blocked', category: 'Threat / Account Block' },
  { keyword: 'account will be blocked', category: 'Threat / Account Block' },
  { keyword: 'block ho jayega', category: 'Threat / Account Block (Hindi)' },
  { keyword: 'sim deactivated', category: 'Threat / Service Cutoff' },
  { keyword: 'electricity disconnected', category: 'Threat / Utility Fraud' },
  { keyword: 'power will be disconnected', category: 'Threat / Utility Fraud' },
  { keyword: 'bijli cut', category: 'Threat / Utility Fraud' },
  { keyword: 'digital arrest', category: 'Law Enforcement Extortion' },
  { keyword: 'police action', category: 'Law Enforcement Extortion' },
  { keyword: 'cbi inquiry', category: 'Law Enforcement Extortion' },
  { keyword: 'fir registered', category: 'Law Enforcement Extortion' },
  { keyword: 'share otp', category: 'Credential Theft' },
  { keyword: 'enter pin', category: 'Credential Theft' },
  { keyword: 'download anydesk', category: 'Remote Access RAT' },
  { keyword: 'download rustdesk', category: 'Remote Access RAT' },
  { keyword: 'download quicksupport', category: 'Remote Access RAT' },
  { keyword: 'install apk', category: 'Malicious App Distribution' },
  { keyword: 'lottery won', category: 'Lottery / Prize Scam' },
  { keyword: 'you have won', category: 'Lottery / Prize Scam' },
  { keyword: 'congratulations', category: 'Lottery / Prize Scam' },
  { keyword: 'cashback credited', category: 'Payment Fraud' },
  { keyword: 'part-time job', category: 'Employment Scam' },
  { keyword: 'earn daily', category: 'Investment Fraud' },
  { keyword: 'guaranteed returns', category: 'Investment Fraud' },
];

export class IndicatorExtractor {
  /**
   * Main extractor running all specialized entity parsers across text
   */
  static extractAll(rawText: string): ExtractedIndicators {
    const text = rawText || '';

    const urls = this.extractUrls(text);
    const phones = this.extractPhoneNumbers(text);
    const upiIds = this.extractUpiIds(text);
    const emails = this.extractEmails(text);
    const socialEngineeringTactics = this.extractSocialEngineeringSignals(text);

    return {
      urls,
      phones,
      upiIds,
      emails,
      qrCodes: [], // Populated by QR decoder
      socialEngineeringTactics,
    };
  }

  /**
   * Discovers URLs, shortened links, and protocol-relative web destinations
   */
  static extractUrls(text: string): ExtractedUrlIndicator[] {
    const results: ExtractedUrlIndicator[] = [];
    const seen = new Set<string>();

    // Heal line-wrapped URLs common in mobile SMS / chat screenshots (e.g. "https://is.gd/\nJ9gaHq.iciciBank.KYC")
    const healedText = text
      .replace(/(https?:\/\/[^\s<>"'{}|\\^`\[\]]+\/)\s*\n\s*([a-zA-Z0-9_.-]+)/gi, '$1$2')
      .replace(/\b([a-zA-Z0-9-]+\.(?:gd|ly|com|top|xyz|in|org|net)\/)\s*\n\s*([a-zA-Z0-9_.-]+)/gi, '$1$2');

    // 1. Explicit http/https URLs
    const explicitUrlRegex = /https?:\/\/[^\s<>"'{}|\\^`\[\]]+/gi;
    let match: RegExpExecArray | null;

    while ((match = explicitUrlRegex.exec(healedText)) !== null) {
      const urlStr = match[0].replace(/[.,;:!?)\]]+$/, ''); // Strip trailing punctuation
      const canonical = canonicalizeUrl(urlStr);

      if (canonical.isValid && !seen.has(canonical.canonicalUrl)) {
        seen.add(canonical.canonicalUrl);
        const host = canonical.domain.toLowerCase();
        results.push({
          original: urlStr,
          normalized: canonical.canonicalUrl,
          isShortener: URL_SHORTENERS.has(host),
          domain: host,
        });
      }
    }

    // 2. Protocol-less domains with common TLDs (e.g. sbi-kyc.top/update, bit.ly/3xyz, update.ly/verify)
    const domainRegex = /\b([a-zA-Z0-9-]{2,63}\.(?:com|org|net|in|co\.in|top|xyz|online|site|store|app|biz|info|live|club|vip|link|cc|icu|tech|ly|io|me|to|ai|co|is|gd))(?:\/[^\s<>"'{}|\\^`\[\]]*)?/gi;

    while ((match = domainRegex.exec(healedText)) !== null) {
      const candidate = match[0].replace(/[.,;:!?)\]]+$/, '');
      const withProto = `https://${candidate}`;
      const canonical = canonicalizeUrl(withProto);

      if (canonical.isValid && !seen.has(canonical.canonicalUrl)) {
        seen.add(canonical.canonicalUrl);
        const host = canonical.domain.toLowerCase();
        results.push({
          original: candidate,
          normalized: canonical.canonicalUrl,
          isShortener: URL_SHORTENERS.has(host),
          domain: host,
        });
      }
    }

    return results;
  }

  /**
   * Discovers Indian and international phone numbers
   */
  static extractPhoneNumbers(text: string): ExtractedPhoneIndicator[] {
    const results: ExtractedPhoneIndicator[] = [];
    const seen = new Set<string>();

    // Indian phone patterns: +91 9876543210, +91-98765-43210, 09876543210, 9876543210
    const indianPhoneRegex = /(?:(?:\+91|91|0)[-.\s]?)?([6-9]\d{4}[-.\s]?\d{5})\b/g;
    let match: RegExpExecArray | null;

    while ((match = indianPhoneRegex.exec(text)) !== null) {
      const rawNumber = match[0].trim();
      const digitsOnly = rawNumber.replace(/\D/g, '');

      let normalizedMobile = '';
      if (digitsOnly.length === 10) {
        normalizedMobile = `+91${digitsOnly}`;
      } else if (digitsOnly.length === 12 && digitsOnly.startsWith('91')) {
        normalizedMobile = `+${digitsOnly}`;
      } else if (digitsOnly.length === 11 && digitsOnly.startsWith('0')) {
        normalizedMobile = `+91${digitsOnly.slice(1)}`;
      }

      if (normalizedMobile && !seen.has(normalizedMobile)) {
        seen.add(normalizedMobile);

        // Heuristic: If message mentions bank, government, or support but provides a mobile number
        const lowerText = text.toLowerCase();
        const claimsOfficialSupport =
          lowerText.includes('customer care') ||
          lowerText.includes('support') ||
          lowerText.includes('helpline') ||
          lowerText.includes('bank') ||
          lowerText.includes('sbi') ||
          lowerText.includes('hdfc') ||
          lowerText.includes('icici') ||
          lowerText.includes('kyc') ||
          lowerText.includes('electricity') ||
          lowerText.includes('manager') ||
          lowerText.includes('officer');

        const isRisk = claimsOfficialSupport;
        results.push({
          original: rawNumber,
          normalized: normalizedMobile,
          isIndian: true,
          riskLevel: isRisk ? 'HIGH' : 'LOW',
          riskReason: isRisk
            ? 'Private personal mobile number claiming to be official corporate or banking customer support'
            : undefined,
        });
      }
    }

    return results;
  }

  /**
   * Discovers and evaluates UPI IDs (Virtual Payment Addresses)
   */
  static extractUpiIds(text: string): ExtractedUpiIndicator[] {
    const results: ExtractedUpiIndicator[] = [];
    const seen = new Set<string>();

    // Pattern: username@provider
    const upiRegex = /\b([a-zA-Z0-9.\-_]{2,64})@([a-zA-Z]{2,32})\b/g;
    let match: RegExpExecArray | null;

    while ((match = upiRegex.exec(text)) !== null) {
      const raw = match[0];
      const handle = match[1];
      const provider = match[2].toLowerCase();

      // Skip common email domain extensions to avoid false positives on emails
      if (
        provider === 'com' ||
        provider === 'in' ||
        provider === 'org' ||
        provider === 'net' ||
        provider === 'edu' ||
        provider === 'gov' ||
        FREE_EMAIL_PROVIDERS.has(`${provider}.com`) ||
        FREE_EMAIL_PROVIDERS.has(provider)
      ) {
        continue;
      }

      const normalized = `${handle.toLowerCase()}@${provider}`;
      if (!seen.has(normalized)) {
        seen.add(normalized);

        const lowerHandle = handle.toLowerCase();
        const isSuspiciousWord = SUSPICIOUS_UPI_KEYWORDS.some((kw) => lowerHandle.includes(kw));
        const isKnownPsp = KNOWN_UPI_VPA_PROVIDERS.has(provider);

        let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' = 'LOW';
        let riskReason: string | undefined;

        if (isSuspiciousWord) {
          riskLevel = 'HIGH';
          riskReason = `UPI handle contains suspicious financial lure or impersonation keyword: "${handle}"`;
        } else if (!isKnownPsp) {
          riskLevel = 'MEDIUM';
          riskReason = `Uncommon or private UPI payment provider handle: @${provider}`;
        }

        results.push({
          original: raw,
          normalized,
          handle,
          provider,
          isSuspiciousKeyword: isSuspiciousWord,
          riskLevel,
          riskReason,
        });
      }
    }

    return results;
  }

  /**
   * Discovers Email Addresses and detects brand impersonation on free webmail
   */
  static extractEmails(text: string): ExtractedEmailIndicator[] {
    const results: ExtractedEmailIndicator[] = [];
    const seen = new Set<string>();

    const emailRegex = /\b([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g;
    let match: RegExpExecArray | null;

    while ((match = emailRegex.exec(text)) !== null) {
      const raw = match[0].toLowerCase();
      const domain = match[2].toLowerCase();
      const localPart = match[1].toLowerCase();

      if (!seen.has(raw)) {
        seen.add(raw);
        const isFree = FREE_EMAIL_PROVIDERS.has(domain);

        // Check if free webmail is masquerading as bank/official service
        let isBrandImpersonating = false;
        let impersonatedBrand: string | undefined;

        if (isFree) {
          if (localPart.includes('sbi') || localPart.includes('statebank')) {
            isBrandImpersonating = true;
            impersonatedBrand = 'State Bank of India';
          } else if (localPart.includes('hdfc')) {
            isBrandImpersonating = true;
            impersonatedBrand = 'HDFC Bank';
          } else if (localPart.includes('icici')) {
            isBrandImpersonating = true;
            impersonatedBrand = 'ICICI Bank';
          } else if (localPart.includes('paytm')) {
            isBrandImpersonating = true;
            impersonatedBrand = 'PayTM';
          } else if (localPart.includes('incometax') || localPart.includes('itdept')) {
            isBrandImpersonating = true;
            impersonatedBrand = 'Income Tax Department';
          } else if (localPart.includes('support') || localPart.includes('customercare') || localPart.includes('helpdesk')) {
            isBrandImpersonating = true;
            impersonatedBrand = 'Unspecified Corporate Entity';
          }
        }

        results.push({
          original: raw,
          domain,
          isFreeProvider: isFree,
          isBrandImpersonating,
          impersonatedBrand,
        });
      }
    }

    return results;
  }

  /**
   * Detects urgency pressure, threats, and credential demands
   */
  static extractSocialEngineeringSignals(text: string): string[] {
    const lower = text.toLowerCase();
    const signals = new Set<string>();

    for (const item of SOCIAL_ENGINEERING_PATTERNS) {
      if (lower.includes(item.keyword)) {
        signals.add(`${item.category}: "${item.keyword}"`);
      }
    }

    return Array.from(signals);
  }
}
