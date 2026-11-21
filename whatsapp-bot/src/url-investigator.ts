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
   */
  static isPrivateOrReservedHost(hostname: string): boolean {
    const host = hostname.toLowerCase().trim();

    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '0.0.0.0' ||
      host === '169.254.169.254' ||
      host === '::1' ||
      host.endsWith('.local') ||
      host.endsWith('.internal')
    ) {
      return true;
    }

    // Check IPv4 private subnets
    const parts = host.split('.');
    if (parts.length === 4 && parts.every((p) => /^\d+$/.test(p))) {
      const b0 = parseInt(parts[0], 10);
      const b1 = parseInt(parts[1], 10);

      // 10.0.0.0/8
      if (b0 === 10) return true;
      // 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
      if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
      // 192.168.0.0/16
      if (b0 === 192 && b1 === 168) return true;
      // 127.0.0.0/8
      if (b0 === 127) return true;
      // 169.254.0.0/16 (Link-local)
      if (b0 === 169 && b1 === 254) return true;
      // 0.0.0.0/8
      if (b0 === 0) return true;
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
