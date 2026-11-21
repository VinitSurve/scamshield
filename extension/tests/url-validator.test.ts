import { describe, it, expect } from 'vitest';
import {
  canonicalizeUrl,
  isInternalBrowserScheme,
  isPrivateOrLoopbackHost,
} from '../src/security/url-validator';

describe('URL Validator & Canonicalizer', () => {
  it('correctly identifies internal browser schemes', () => {
    expect(isInternalBrowserScheme('chrome://extensions')).toBe(true);
    expect(isInternalBrowserScheme('chrome-extension://xyz/popup.html')).toBe(true);
    expect(isInternalBrowserScheme('about:blank')).toBe(true);
    expect(isInternalBrowserScheme('devtools://devtools')).toBe(true);
    expect(isInternalBrowserScheme('https://example.com')).toBe(false);
  });

  it('detects private IP addresses and loopback hosts (SSRF Prevention)', () => {
    expect(isPrivateOrLoopbackHost('localhost')).toBe(true);
    expect(isPrivateOrLoopbackHost('127.0.0.1')).toBe(true);
    expect(isPrivateOrLoopbackHost('127.0.1.5')).toBe(true);
    expect(isPrivateOrLoopbackHost('10.0.0.1')).toBe(true);
    expect(isPrivateOrLoopbackHost('172.16.0.5')).toBe(true);
    expect(isPrivateOrLoopbackHost('172.31.255.254')).toBe(true);
    expect(isPrivateOrLoopbackHost('192.168.1.1')).toBe(true);
    expect(isPrivateOrLoopbackHost('169.254.169.254')).toBe(true); // AWS/GCP Metadata IP
    expect(isPrivateOrLoopbackHost('100.64.0.1')).toBe(true); // CGNAT
    expect(isPrivateOrLoopbackHost('::1')).toBe(true); // IPv6 loopback
    expect(isPrivateOrLoopbackHost('fe80::1')).toBe(true); // IPv6 link-local

    // Public IPs should return false
    expect(isPrivateOrLoopbackHost('8.8.8.8')).toBe(false);
    expect(isPrivateOrLoopbackHost('1.1.1.1')).toBe(false);
    expect(isPrivateOrLoopbackHost('google.com')).toBe(false);
  });

  it('canonicalizes standard URLs and strips sensitive query parameters and hash fragments', () => {
    const raw = 'https://sbi-login.xyz/auth/login.php?user=test&token=SECRET_JWT_123&session_id=ABC#step2';
    const result = canonicalizeUrl(raw);

    expect(result.isValid).toBe(true);
    expect(result.domain).toBe('sbi-login.xyz');
    expect(result.canonicalUrl).not.toContain('SECRET_JWT_123');
    expect(result.canonicalUrl).not.toContain('session_id');
    expect(result.canonicalUrl).not.toContain('#step2');
    expect(result.canonicalUrl).toContain('user=test');
    expect(result.isInternal).toBe(false);
  });

  it('normalizes uppercase domains and removes trailing dots', () => {
    const raw = 'HTTPS://EXAMPLE.COM./path';
    const result = canonicalizeUrl(raw);

    expect(result.domain).toBe('example.com');
    expect(result.canonicalUrl).toBe('https://example.com/path');
  });

  it('handles invalid or malformed URL strings gracefully without crashing', () => {
    const result1 = canonicalizeUrl('');
    expect(result1.isValid).toBe(false);

    const result2 = canonicalizeUrl('not a url %%%');
    expect(result2.isValid).toBe(false);

    const result3 = canonicalizeUrl('ftp://unsupported.example');
    expect(result3.isValid).toBe(false);
  });
});
