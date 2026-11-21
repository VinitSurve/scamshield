/**
 * Domain normalization, homoglyph detection, root domain extraction, and impersonation detection
 */

// Common multi-part TLD suffixes
const MULTI_PART_TLDS = new Set([
  'co.in',
  'gov.in',
  'nic.in',
  'ac.in',
  'edu.in',
  'org.in',
  'net.in',
  'gen.in',
  'firm.in',
  'ind.in',
  'co.uk',
  'gov.uk',
  'org.uk',
  'ac.uk',
  'com.au',
  'gov.au',
  'edu.au',
  'org.au',
  'co.nz',
  'co.za',
  'com.br',
  'co.jp',
  'com.sg',
  'com.my',
]);

// High-value targeted brands and their official legitimate root domains
export const SENSITIVE_BRAND_REGISTRY: Record<string, { brandName: string; officialDomains: string[]; keywords: string[] }> = {
  sbi: {
    brandName: 'State Bank of India',
    officialDomains: ['sbi.co.in', 'onlinesbi.sbi', 'onlinesbi.com', 'statebankofindia.com'],
    keywords: ['onlinesbi', 'sbi-online', 'sbibank', 'sbiyono', 'yono-sbi', 'sbi-kyc'],
  },
  hdfc: {
    brandName: 'HDFC Bank',
    officialDomains: ['hdfcbank.com', 'hdfc.com', 'hdfcbank.net'],
    keywords: ['hdfcbank', 'hdfc-netbanking', 'hdfconline', 'hdfc-kyc'],
  },
  icici: {
    brandName: 'ICICI Bank',
    officialDomains: ['icicibank.com', 'icicibank.co.in'],
    keywords: ['icicibank', 'icicionline', 'icici-kyc', 'icici-netbanking'],
  },
  axis: {
    brandName: 'Axis Bank',
    officialDomains: ['axisbank.com', 'axisbank.co.in'],
    keywords: ['axisbank', 'axis-online', 'axis-netbanking', 'axis-kyc'],
  },
  paytm: {
    brandName: 'PayTM',
    officialDomains: ['paytm.com'],
    keywords: ['paytm-kyc', 'paytmbank', 'paytm-mall', 'paytm-update'],
  },
  phonepe: {
    brandName: 'PhonePe',
    officialDomains: ['phonepe.com'],
    keywords: ['phonepe-reward', 'phonepe-cashback', 'phonepe-kyc'],
  },
  incometax: {
    brandName: 'Income Tax Department of India',
    officialDomains: ['incometax.gov.in', 'incometaxindiaefiling.gov.in'],
    keywords: ['incometax-refund', 'tax-refund', 'it-refund', 'itr-refund'],
  },
  parivahan: {
    brandName: 'Parivahan Sewa (eChallan)',
    officialDomains: ['parivahan.gov.in', 'echallan.parivahan.gov.in'],
    keywords: ['echallan', 'e-challan', 'parivahan-pay', 'traffic-challan'],
  },
  msedcl: {
    brandName: 'Mahavitaran (MSEDCL Electricity)',
    officialDomains: ['mahadiscom.in', 'mahavitaran.in'],
    keywords: ['mahadiscom', 'msedcl-bill', 'electricity-bill-pay', 'bijli-bill'],
  },
  netflix: {
    brandName: 'Netflix',
    officialDomains: ['netflix.com'],
    keywords: ['netflix-verify', 'netflix-update', 'netflix-billing'],
  },
  paypal: {
    brandName: 'PayPal',
    officialDomains: ['paypal.com', 'paypal.me'],
    keywords: ['paypal-security', 'paypal-verify', 'paypal-login', 'paypal-update'],
  },
};

// Cyrillic and Greek homoglyphs commonly used in IDN homograph phishing attacks
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', // Cyrillic small a
  '\u0431': 'b', // Cyrillic small be
  '\u0432': 'v', // Cyrillic small ve
  '\u0433': 'g', // Cyrillic small ghe
  '\u0434': 'd', // Cyrillic small de
  '\u0435': 'e', // Cyrillic small ie
  '\u0436': 'zh',
  '\u0437': 'z',
  '\u0438': 'i',
  '\u043A': 'k',
  '\u043C': 'm',
  '\u043D': 'n',
  '\u043E': 'o', // Cyrillic small o
  '\u0440': 'p', // Cyrillic small er
  '\u0441': 'c', // Cyrillic small es
  '\u0442': 't',
  '\u0443': 'u',
  '\u0445': 'x', // Cyrillic small ha
  '\u044A': '',
  '\u044B': 'y',
  '\u044C': '',
  '\u044D': 'e',
  '\u044E': 'yu',
  '\u044F': 'ya',
  '\u03B1': 'a', // Greek small alpha
  '\u03B2': 'b', // Greek small beta
  '\u03BF': 'o', // Greek small omicron
  '\u03C1': 'p', // Greek small rho
};

export function isPunycode(hostname: string): boolean {
  if (!hostname) return false;
  return hostname.toLowerCase().split('.').some((part) => part.startsWith('xn--'));
}

export function cleanHomoglyphs(text: string): { cleaned: string; hasHomoglyphs: boolean } {
  let hasHomoglyphs = false;
  let cleaned = '';

  for (const char of text) {
    if (HOMOGLYPH_MAP[char]) {
      cleaned += HOMOGLYPH_MAP[char];
      hasHomoglyphs = true;
    } else {
      cleaned += char;
    }
  }

  return { cleaned, hasHomoglyphs };
}

export function extractRootDomain(hostname: string): string {
  if (!hostname) return '';
  const clean = hostname.toLowerCase().trim();

  // If it's an IP address, return as is
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(clean) || clean.includes(':')) {
    return clean;
  }

  const parts = clean.split('.');
  if (parts.length <= 2) return clean;

  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo)) {
    if (parts.length >= 3) {
      return parts.slice(-3).join('.');
    }
    return clean;
  }

  return parts.slice(-2).join('.');
}

export interface ImpersonationCheckResult {
  isImpersonating: boolean;
  impersonatedBrand?: string;
  legitimateDomains?: string[];
  matchedKeyword?: string;
  confidence: number;
}

export function detectBrandImpersonation(hostname: string): ImpersonationCheckResult {
  if (!hostname) {
    return { isImpersonating: false, confidence: 0 };
  }

  const normalized = hostname.toLowerCase().trim();
  const rootDomain = extractRootDomain(normalized);
  const { cleaned } = cleanHomoglyphs(normalized);

  for (const [key, brandInfo] of Object.entries(SENSITIVE_BRAND_REGISTRY)) {
    const isOfficial = brandInfo.officialDomains.some((official) => {
      const officialRoot = extractRootDomain(official);
      return rootDomain === officialRoot || normalized.endsWith(`.${officialRoot}`);
    });

    if (isOfficial) {
      // Legitimate brand site!
      continue;
    }

    // Check if the domain name or subdomains mimic the brand keywords
    for (const keyword of brandInfo.keywords) {
      if (normalized.includes(keyword) || cleaned.includes(keyword)) {
        return {
          isImpersonating: true,
          impersonatedBrand: brandInfo.brandName,
          legitimateDomains: brandInfo.officialDomains,
          matchedKeyword: keyword,
          confidence: 0.92,
        };
      }
    }

    // Also check direct brand key match with hyphens (e.g. "sbi-verification.top")
    const brandRegex = new RegExp(`(^|[-._])${key}([-._]|$)`, 'i');
    if (brandRegex.test(normalized) || brandRegex.test(cleaned)) {
      return {
        isImpersonating: true,
        impersonatedBrand: brandInfo.brandName,
        legitimateDomains: brandInfo.officialDomains,
        matchedKeyword: key,
        confidence: 0.85,
      };
    }
  }

  return { isImpersonating: false, confidence: 0 };
}
