import crypto from 'crypto';

const ALLOWED_META_DOMAINS = [
  'lookaside.fbsbx.com',
  'whatsapp.net',
  'fbcdn.net',
  'facebook.com',
];

export class BotSecurity {
  /**
   * Validates media download URLs to prevent Server-Side Request Forgery (SSRF)
   */
  static isSafeMediaUrl(urlStr: string): boolean {
    try {
      const parsed = new URL(urlStr);

      if (parsed.protocol !== 'https:') {
        return false;
      }

      const hostname = parsed.hostname.toLowerCase();

      // Block local / private / loopback IP addresses
      if (
        hostname === 'localhost' ||
        hostname === '127.0.0.1' ||
        hostname === '0.0.0.0' ||
        hostname === '169.254.169.254' ||
        hostname.startsWith('10.') ||
        hostname.startsWith('192.168.') ||
        (hostname.startsWith('172.') && parseInt(hostname.split('.')[1], 10) >= 16 && parseInt(hostname.split('.')[1], 10) <= 31)
      ) {
        return false;
      }

      // Restrict strictly to official Meta/WhatsApp CDN domains
      const isAllowed = ALLOWED_META_DOMAINS.some(
        (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
      );

      return isAllowed;
    } catch {
      return false;
    }
  }

  /**
   * Verifies HMAC SHA-256 webhook signature sent by Meta in 'X-Hub-Signature-256'
   */
  static verifySignature(payload: string, signature: string, appSecret: string): boolean {
    if (!signature || !appSecret) return false;

    try {
      const hmac = crypto.createHmac('sha256', appSecret);
      const expected = `sha256=${hmac.update(payload).digest('hex')}`;
      return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
    } catch {
      return false;
    }
  }
}
