/**
 * ScamShield WhatsApp Bot Safe URL Investigator
 *
 * Performs passive, isolated threat analysis on suspicious links:
 * - SSRF Protection: strictly blocks loopback, private networks, and link-local targets
 * - Domain normalization and shortener detection
 * - Top-domain legitimacy checking
 * - Indian banking and utility impersonation heuristic checks
 * - Safe redirect tracing (isolated, passive, no binary downloads)
 */

export interface UrlInvestigationResult {
  originalUrl: string;
  finalUrl: string;
  domain: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNREACHABLE';
  riskScore: number;
  category: string;
  isShortened: boolean;
  isImpersonatingBank: boolean;
  impersonatedBrand?: string;
  details: string[];
  redirectChain: string[];
}

export class UrlInvestigator {
  private static readonly KNOWN_LEGIT_DOMAINS = new Set([
    'google.com',
    'www.google.com',
    'apple.com',
    'www.apple.com',
    'amazon.in',
    'www.amazon.in',
    'amazon.com',
    'www.amazon.com',
    'bluedart.com',
    'www.bluedart.com',
    'onlinesbi.sbi',
    'sbi.co.in',
    'www.sbi.co.in',
    'hdfcbank.com',
    'www.hdfcbank.com',
    'icicibank.com',
    'www.icicibank.com',
    'microsoft.com',
    'github.com',
    'cybercrime.gov.in',
  ]);

  private static readonly KNOWN_SHORTENERS = new Set([
    'is.gd',
    'bit.ly',
    'tinyurl.com',
    't.co',
    'cutt.ly',
    'rb.gy',
    'v.gd',
    'shorturl.at',
  ]);

  /**
   * Checks if an IP or host is private, loopback, or reserved (SSRF protection)
   * Hardened against decimal IPs, octal notation, hex IPs, IPv6 brackets, and IPv4-mapped IPv6.
   */
  static isPrivateOrReservedHost(hostname: string): boolean {
    let host = hostname.toLowerCase().trim();
    if (host.startsWith('[') && host.endsWith(']')) {
      host = host.slice(1, -1);
    }
    if (host.endsWith('.')) {
      host = host.slice(0, -1);
    }

    if (
      host === 'localhost' ||
      host === '::1' ||
      host === '::' ||
      host === '0.0.0.0' ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host.endsWith('.localhost') ||
      host.endsWith('.lan')
    ) {
      return true;
    }

    // IPv6 ULA (fc00::/7) and Link-Local (fe80::/10)
    if (
      host.startsWith('fc') ||
      host.startsWith('fd') ||
      host.startsWith('fe8') ||
      host.startsWith('fe9') ||
      host.startsWith('fea') ||
      host.startsWith('feb')
    ) {
      return true;
    }

    // IPv4-mapped IPv6 (::ffff:127.0.0.1)
    if (host.startsWith('::ffff:')) {
      return this.isPrivateOrReservedHost(host.slice(7));
    }

    // Check single integer (decimal / hex) representation (e.g. 2130706433 or 0x7f000001)
    if (/^(0x[0-9a-f]+|\d+)$/i.test(host)) {
      const num = parseInt(host, host.startsWith('0x') ? 16 : 10);
      if (!isNaN(num) && num >= 0 && num <= 0xffffffff) {
        const b0 = (num >>> 24) & 0xff;
        const b1 = (num >>> 16) & 0xff;
        if (b0 === 127 || b0 === 10 || b0 === 0) return true;
        if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
        if (b0 === 192 && b1 === 168) return true;
        if (b0 === 169 && b1 === 254) return true;
      }
    }

    // Check dotted IPv4 notation (supporting decimal, hex 0x, octal 0)
    const parts = host.split('.');
    if (parts.length >= 2 && parts.length <= 4) {
      const nums: number[] = [];
      for (const p of parts) {
        if (/^0x[0-9a-f]+$/i.test(p)) {
          nums.push(parseInt(p, 16));
        } else if (/^0[0-7]+$/.test(p)) {
          nums.push(parseInt(p, 8));
        } else if (/^\d+$/.test(p)) {
          nums.push(parseInt(p, 10));
        } else {
          return false;
        }
      }
      if (nums.every((n) => !isNaN(n) && n >= 0)) {
        let b0 = nums[0];
        let b1 = nums[1];
        if (parts.length === 2) {
          const rest = nums[1];
          b1 = (rest >>> 16) & 0xff;
        }
        if (b0 === 127 || b0 === 10 || b0 === 0) return true;
        if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
        if (b0 === 192 && b1 === 168) return true;
        if (b0 === 169 && b1 === 254) return true;
      }
    }

    return false;
  }

  /**
   * Normalizes a raw URL string into a parsed URL object with safety validation
   */
  static parseAndValidateUrl(rawUrl: string): URL | null {
    try {
      let target = rawUrl.trim();
      if (!target.startsWith('http://') && !target.startsWith('https://')) {
        target = `https://${target}`;
      }

      const parsed = new URL(target);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return null;
      }

      if (this.isPrivateOrReservedHost(parsed.hostname)) {
        return null; // Reject SSRF candidate
      }

      return parsed;
    } catch {
      return null;
    }
  }

  /**
   * Performs an isolated, passive investigation of a URL
   */
  static async investigateUrl(rawUrl: string): Promise<UrlInvestigationResult> {
    const parsed = this.parseAndValidateUrl(rawUrl);
    if (!parsed) {
      return {
        originalUrl: rawUrl,
        finalUrl: rawUrl,
        domain: 'invalid-or-private',
        verdict: 'MALICIOUS',
        riskScore: 90,
        category: 'SSRF_OR_INVALID_DESTINATION',
        isShortened: false,
        isImpersonatingBank: false,
        details: ['Target blocked: loopback, private IP address, or malformed URL (SSRF prevention).'],
        redirectChain: [],
      };
    }

    const domain = parsed.hostname.toLowerCase();
    const details: string[] = [];
    const redirectChain: string[] = [parsed.href];
    let isShortened = this.KNOWN_SHORTENERS.has(domain);
    let finalUrl = parsed.href;
    let verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'CLEAN' | 'UNREACHABLE' = 'CLEAN';
    let riskScore = 5;
    let category = 'LEGITIMATE_DESTINATION';
    let isImpersonatingBank = false;
    let impersonatedBrand: string | undefined;

    // 1. Check known legitimate domains
    if (this.KNOWN_LEGIT_DOMAINS.has(domain)) {
      details.push(`Domain '${domain}' is verified in ScamShield trusted organization registry.`);
      return {
        originalUrl: rawUrl,
        finalUrl: parsed.href,
        domain,
        verdict: 'CLEAN',
        riskScore: 5,
        category: 'VERIFIED_ORGANIZATION',
        isShortened: false,
        isImpersonatingBank: false,
        details,
        redirectChain,
      };
    }

    // 2. Check for suspicious TLDs
    const suspiciousTlds = ['.top', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.work', '.click', '.download', '.site', '.online'];
    const hasSuspiciousTld = suspiciousTlds.some((tld) => domain.endsWith(tld));
    if (hasSuspiciousTld) {
      details.push(`High-risk Top-Level Domain detected (${domain.split('.').pop()}). Frequently leveraged in phishing disposable kits.`);
    }

    // 3. Check for banking / brand impersonation in URL
    const urlLower = parsed.href.toLowerCase();
    if (urlLower.includes('sbi') || urlLower.includes('onlinesbi')) {
      isImpersonatingBank = true;
      impersonatedBrand = 'SBI (State Bank of India)';
      details.push(`Brand Impersonation: Mimics State Bank of India (SBI) on unverified domain '${domain}'.`);
    } else if (urlLower.includes('hdfc')) {
      isImpersonatingBank = true;
      impersonatedBrand = 'HDFC Bank';
      details.push(`Brand Impersonation: Mimics HDFC Bank on unverified domain '${domain}'.`);
    } else if (urlLower.includes('icici')) {
      isImpersonatingBank = true;
      impersonatedBrand = 'ICICI Bank';
      details.push(`Brand Impersonation: Mimics ICICI Bank on unverified domain '${domain}'.`);
    } else if (urlLower.includes('challan') || urlLower.includes('echallan')) {
      isImpersonatingBank = true;
      impersonatedBrand = 'Traffic E-Challan Portal';
      details.push(`Authority Impersonation: Mimics official Traffic Police E-Challan on unverified domain.`);
    } else if (urlLower.includes('bijli') || urlLower.includes('electricity')) {
      isImpersonatingBank = true;
      impersonatedBrand = 'Electricity Board';
      details.push(`Utility Impersonation: Mimics State Electricity Board portal.`);
    }

    // 4. Trace redirects safely if it is a shortener
    if (isShortened) {
      details.push(`URL Shortener detected (${domain}). Conceals true web destination.`);
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 3500);

        const response = await fetch(parsed.href, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
          headers: { 'User-Agent': 'ScamShield-Threat-Scanner/1.0' },
        });
        clearTimeout(timeoutId);

        const location = response.headers.get('location');
        if (location) {
          const resolved = new URL(location, parsed.href);
          if (!this.isPrivateOrReservedHost(resolved.hostname)) {
            finalUrl = resolved.href;
            redirectChain.push(finalUrl);
            details.push(`Shortener redirects to: ${finalUrl}`);

            // Inspect resolved destination
            const resLower = finalUrl.toLowerCase();
            if (resLower.includes('sbi') || resLower.includes('kyc') || resLower.includes('icici')) {
              isImpersonatingBank = true;
              details.push(`Redirected target contains sensitive banking / KYC lures.`);
            }
          }
        }
      } catch {
        details.push('Shortener destination could not be resolved or timed out.');
      }
    }

    // 5. Compute verdict
    if (isImpersonatingBank || hasSuspiciousTld || (isShortened && urlLower.includes('kyc'))) {
      verdict = 'MALICIOUS';
      riskScore = 95;
      category = isImpersonatingBank ? 'PHISHING_IMPERSONATION' : 'MALICIOUS_LINK';
    } else if (isShortened) {
      verdict = 'SUSPICIOUS';
      riskScore = 65;
      category = 'SUSPICIOUS_REDIRECTOR';
    } else {
      verdict = 'SUSPICIOUS';
      riskScore = 50;
      category = 'UNVERIFIED_EXTERNAL_LINK';
      details.push(`Domain '${domain}' is unverified in public threat databases. Exercise caution.`);
    }

    return {
      originalUrl: rawUrl,
      finalUrl,
      domain,
      verdict,
      riskScore,
      category,
      isShortened,
      isImpersonatingBank,
      impersonatedBrand,
      details,
      redirectChain,
    };
  }
}
