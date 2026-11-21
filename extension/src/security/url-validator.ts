/**
 * URL validation, canonicalization, and security gating
 */

const INTERNAL_SCHEMES = [
  'chrome:',
  'chrome-extension:',
  'edge:',
  'about:',
  'devtools:',
  'blob:',
  'data:',
  'javascript:',
  'file:',
  'view-source:',
];

const SENSITIVE_QUERY_PARAMS = new Set([
  'token',
  'auth',
  'jwt',
  'session',
  'session_id',
  'sessionid',
  'password',
  'pass',
  'key',
  'api_key',
  'apikey',
  'secret',
  'code',
  'access_token',
  'refresh_token',
  'oauth_token',
  'id_token',
]);

export interface CanonicalUrlResult {
  isValid: boolean;
  rawUrl: string;
  canonicalUrl: string;
  domain: string;
  hostname: string;
  protocol: string;
  port?: string;
  pathname: string;
  isInternal: boolean;
  isPrivateOrLoopback: boolean;
  error?: string;
}

export function isInternalBrowserScheme(urlStr: string): boolean {
  if (!urlStr) return true;
  const lower = urlStr.trim().toLowerCase();
  return INTERNAL_SCHEMES.some((scheme) => lower.startsWith(scheme));
}

export function isPrivateOrLoopbackHost(hostname: string): boolean {
  if (!hostname) return false;
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '').trim();

  // Localhost aliases
  if (host === 'localhost' || host === '0.0.0.0') return true;

  // IPv4 checks
  const ipv4Match = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [_, oct1, oct2, oct3, oct4] = ipv4Match.map(Number);
    if (oct1 > 255 || oct2 > 255 || oct3 > 255 || oct4 > 255) return false;

    // Loopback 127.0.0.0/8
    if (oct1 === 127) return true;
    // RFC 1918 Private: 10.0.0.0/8
    if (oct1 === 10) return true;
    // RFC 1918 Private: 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (oct1 === 172 && oct2 >= 16 && oct2 <= 31) return true;
    // RFC 1918 Private: 192.168.0.0/16
    if (oct1 === 192 && oct2 === 168) return true;
    // Link-local / Cloud metadata: 169.254.0.0/16
    if (oct1 === 169 && oct2 === 254) return true;
    // CGNAT 100.64.0.0/10
    if (oct1 === 100 && oct2 >= 64 && oct2 <= 127) return true;
  }

  // IPv6 checks
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') return true;
  if (host.startsWith('fe80:') || host.startsWith('fc00:') || host.startsWith('fd00:')) return true;

  return false;
}

export function canonicalizeUrl(rawUrl: string): CanonicalUrlResult {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return {
      isValid: false,
      rawUrl: rawUrl || '',
      canonicalUrl: '',
      domain: '',
      hostname: '',
      protocol: '',
      pathname: '',
      isInternal: false,
      isPrivateOrLoopback: false,
      error: 'Empty or invalid URL input',
    };
  }

  const trimmed = rawUrl.trim();
  if (isInternalBrowserScheme(trimmed)) {
    return {
      isValid: true,
      rawUrl: trimmed,
      canonicalUrl: trimmed,
      domain: '',
      hostname: '',
      protocol: trimmed.split(':')[0] + ':',
      pathname: '',
      isInternal: true,
      isPrivateOrLoopback: false,
    };
  }

  try {
    const parsed = new URL(trimmed);
    const protocol = parsed.protocol.toLowerCase();

    if (protocol !== 'http:' && protocol !== 'https:') {
      return {
        isValid: false,
        rawUrl: trimmed,
        canonicalUrl: trimmed,
        domain: '',
        hostname: '',
        protocol,
        pathname: '',
        isInternal: true,
        isPrivateOrLoopback: false,
        error: `Unsupported scheme: ${protocol}`,
      };
    }

    // Lowercase hostname and strip trailing dots
    let hostname = parsed.hostname.toLowerCase();
    while (hostname.endsWith('.')) {
      hostname = hostname.slice(0, -1);
    }

    const isPrivate = isPrivateOrLoopbackHost(hostname);

    // Sanitize query parameters: filter out auth tokens and tracking IDs
    const searchParams = new URLSearchParams(parsed.search);
    const cleanedParams = new URLSearchParams();

    for (const [key, value] of searchParams.entries()) {
      const lowerKey = key.toLowerCase();
      if (!SENSITIVE_QUERY_PARAMS.has(lowerKey)) {
        cleanedParams.append(key, value);
      }
    }

    // Sort parameters for deterministic caching
    cleanedParams.sort();
    const cleanSearch = cleanedParams.toString();
    const queryPart = cleanSearch ? `?${cleanSearch}` : '';

    // Reconstruct canonical URL (strictly stripping fragment #hash)
    const portPart = parsed.port ? `:${parsed.port}` : '';
    const pathname = parsed.pathname || '/';
    const canonicalUrl = `${protocol}//${hostname}${portPart}${pathname}${queryPart}`;

    return {
      isValid: true,
      rawUrl: trimmed,
      canonicalUrl,
      domain: hostname,
      hostname,
      protocol,
      port: parsed.port || undefined,
      pathname,
      isInternal: false,
      isPrivateOrLoopback: isPrivate,
    };
  } catch (err) {
    return {
      isValid: false,
      rawUrl: trimmed,
      canonicalUrl: trimmed,
      domain: '',
      hostname: '',
      protocol: '',
      pathname: '',
      isInternal: false,
      isPrivateOrLoopback: false,
      error: err instanceof Error ? err.message : 'URL parsing failed',
    };
  }
}
