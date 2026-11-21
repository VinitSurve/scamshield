import { describe, it, expect } from 'vitest';
import {
  extractRootDomain,
  isPunycode,
  cleanHomoglyphs,
  detectBrandImpersonation,
} from '../src/security/domain-normalizer';

describe('Domain Normalizer & Brand Impersonation Detector', () => {
  it('extracts root domains correctly handling multi-part country TLDs', () => {
    expect(extractRootDomain('sbi.co.in')).toBe('sbi.co.in');
    expect(extractRootDomain('netbanking.sbi.co.in')).toBe('sbi.co.in');
    expect(extractRootDomain('echallan.parivahan.gov.in')).toBe('parivahan.gov.in');
    expect(extractRootDomain('sub.example.co.uk')).toBe('example.co.uk');
    expect(extractRootDomain('login.google.com')).toBe('google.com');
    expect(extractRootDomain('phish.login.evil.top')).toBe('evil.top');
  });

  it('detects Punycode (IDN) encoded domain representations', () => {
    expect(isPunycode('xn--80ak6aa92e.com')).toBe(true);
    expect(isPunycode('google.com')).toBe(false);
    expect(isPunycode('sub.xn--bank-o1a.top')).toBe(true);
  });

  it('replaces Cyrillic and Greek homoglyphs with Latin characters to uncover spoofing', () => {
    // Cyrillic small 'а' (\u0430) and 'о' (\u043E)
    const spoofed = 'sbi-оnline.t\u043Ep';
    const { cleaned, hasHomoglyphs } = cleanHomoglyphs(spoofed);

    expect(hasHomoglyphs).toBe(true);
    expect(cleaned).toBe('sbi-online.top');
  });

  it('flags unauthorized domains that impersonate Indian financial brands', () => {
    // SBI Impersonation
    const sbiFake = detectBrandImpersonation('sbi-online-kyc-update.top');
    expect(sbiFake.isImpersonating).toBe(true);
    expect(sbiFake.impersonatedBrand).toBe('State Bank of India');

    // HDFC Impersonation
    const hdfcFake = detectBrandImpersonation('hdfc-netbanking-verify.xyz');
    expect(hdfcFake.isImpersonating).toBe(true);
    expect(hdfcFake.impersonatedBrand).toBe('HDFC Bank');

    // Parivahan Challan Impersonation
    const challanFake = detectBrandImpersonation('echallan-parivahan-pay.online');
    expect(challanFake.isImpersonating).toBe(true);
    expect(challanFake.impersonatedBrand).toBe('Parivahan Sewa (eChallan)');
  });

  it('does NOT falsely flag legitimate official brand domains as impersonators', () => {
    expect(detectBrandImpersonation('onlinesbi.sbi').isImpersonating).toBe(false);
    expect(detectBrandImpersonation('retail.onlinesbi.sbi').isImpersonating).toBe(false);
    expect(detectBrandImpersonation('sbi.co.in').isImpersonating).toBe(false);
    expect(detectBrandImpersonation('hdfcbank.com').isImpersonating).toBe(false);
    expect(detectBrandImpersonation('parivahan.gov.in').isImpersonating).toBe(false);
    expect(detectBrandImpersonation('paytm.com').isImpersonating).toBe(false);
  });
});
