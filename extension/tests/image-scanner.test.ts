import { describe, it, expect, beforeEach } from 'vitest';
import fs from 'fs';
import path from 'path';
import { IndicatorExtractor } from '../src/image/indicator-extractor';
import { QrDecoder } from '../src/image/qr-decoder';
import { ImageScanner } from '../src/image/image-scanner';
import { CacheService } from '../src/storage/cache-service';

describe('Image-Based Scam Detection Engine', () => {
  beforeEach(async () => {
    await CacheService.clearAll();
  });

  describe('Indicator Extractor', () => {
    it('extracts full URLs, protocol-less domains, and identifies shorteners', () => {
      const text = `
        Your SBI account has been locked.
        Update KYC immediately at https://sbi-online-kyc-verification.top/auth
        Also backup mirror: bit.ly/sbi-urgent-update or help-kyc.xyz/verify
      `;

      const indicators = IndicatorExtractor.extractUrls(text);
      expect(indicators.length).toBeGreaterThanOrEqual(2);

      const sbiUrl = indicators.find((u) => u.original.includes('sbi-online-kyc-verification.top'));
      expect(sbiUrl).toBeDefined();
      expect(sbiUrl?.domain).toBe('sbi-online-kyc-verification.top');
      expect(sbiUrl?.isShortener).toBe(false);

      const shortUrl = indicators.find((u) => u.domain.includes('bit.ly'));
      expect(shortUrl).toBeDefined();
      expect(shortUrl?.isShortener).toBe(true);
    });

    it('extracts Indian mobile numbers and flags private numbers claiming official banking support', () => {
      const text = `
        SBI Alert: NetBanking blocked. Call official bank helpline: +91 98765 43210 immediately.
      `;

      const phones = IndicatorExtractor.extractPhoneNumbers(text);
      expect(phones.length).toBe(1);
      expect(phones[0].normalized).toBe('+919876543210');
      expect(phones[0].isIndian).toBe(true);
      expect(phones[0].riskLevel).toBe('HIGH');
      expect(phones[0].riskReason).toContain('Private personal mobile number');
    });

    it('extracts UPI IDs and flags suspicious financial lure keywords', () => {
      const text = `
        Dear user, your Paytm cashback of Rs 2500 is pending.
        Approve refund via UPI: sbi-refund-helpdesk@paytm or normal-merchant@okhdfcbank
      `;

      const upis = IndicatorExtractor.extractUpiIds(text);
      expect(upis.length).toBe(2);

      const refundUpi = upis.find((u) => u.normalized.includes('sbi-refund-helpdesk@paytm'));
      expect(refundUpi).toBeDefined();
      expect(refundUpi?.isSuspiciousKeyword).toBe(true);
      expect(refundUpi?.riskLevel).toBe('HIGH');
      expect(refundUpi?.riskReason).toContain('suspicious financial lure');

      const normalUpi = upis.find((u) => u.normalized.includes('normal-merchant@okhdfcbank'));
      expect(normalUpi).toBeDefined();
      expect(normalUpi?.isSuspiciousKeyword).toBe(false);
      expect(normalUpi?.riskLevel).toBe('LOW');
    });

    it('extracts emails and flags brand impersonation on free webmail providers', () => {
      const text = `
        Official communication from SBI Support: sbi.customercare24x7@gmail.com
      `;

      const emails = IndicatorExtractor.extractEmails(text);
      expect(emails.length).toBe(1);
      expect(emails[0].original).toBe('sbi.customercare24x7@gmail.com');
      expect(emails[0].isFreeProvider).toBe(true);
      expect(emails[0].isBrandImpersonating).toBe(true);
      expect(emails[0].impersonatedBrand).toBe('State Bank of India');
    });

    it('detects social engineering pressure tactics in English and Hindi', () => {
      const text = `
        URGENT NOTICE! Your power will be disconnected today itself.
        Turant call kare nahi to account block ho jayega. Share OTP to cancel.
      `;

      const tactics = IndicatorExtractor.extractSocialEngineeringSignals(text);
      expect(tactics.length).toBeGreaterThanOrEqual(4);
      expect(tactics.some((t) => t.includes('Urgency Pressure'))).toBe(true);
      expect(tactics.some((t) => t.includes('Threat / Utility Fraud'))).toBe(true);
      expect(tactics.some((t) => t.includes('Threat / Account Block (Hindi)'))).toBe(true);
      expect(tactics.some((t) => t.includes('Credential Theft'))).toBe(true);
    });
  });

  describe('QR Decoder', () => {
    it('parses UPI payment URI correctly', () => {
      const qrData = 'upi://pay?pa=fake-refund-agent@upi&pn=SBI+Refund+Portal&am=1500';
      const parsed = QrDecoder.parseQrPayload(qrData);

      expect(parsed.type).toBe('UPI');
      expect(parsed.decodedUpi?.normalized).toBe('fake-refund-agent@upi');
      expect(parsed.decodedUpi?.isSuspiciousKeyword).toBe(true);
      expect(parsed.decodedUpi?.riskLevel).toBe('HIGH');
    });

    it('parses standard web URLs from QR payload', () => {
      const qrData = 'https://testsafebrowsing.appspot.com/s/malware.html';
      const parsed = QrDecoder.parseQrPayload(qrData);

      expect(parsed.type).toBe('URL');
      expect(parsed.decodedUrl).toBe('https://testsafebrowsing.appspot.com/s/malware.html');
    });
  });

  describe('End-to-End Image Scam Scanner Pipeline', () => {
    it('scans synthetic image containing phishing KYC lure and passes extracted URL to ReputationService', async () => {
      // Create synthetic test data URL containing an embedded phishing fixture
      const fixtureMessage = `
        IMPORTANT NOTICE: State Bank of India
        Your SBI NetBanking will be suspended within 24 hours.
        Complete your mandatory KYC update immediately:
        https://sbi-online-kyc-verification.top/login.php
        Support helpline: +91 9876543210
        Refunds: sbi-support-desk@paytm
      `;

      const base64Content = Buffer.from(fixtureMessage).toString('base64');
      const testDataUrl = `data:text/plain;base64,${base64Content}`;

      const result = await ImageScanner.scanImage(testDataUrl, {
        name: 'sbi-scam-screenshot.png',
        sizeBytes: 1024,
        mimeType: 'text/plain',
      });

      expect(result.scanId).toBeDefined();
      expect(result.ocrResult.extractedText).toContain('State Bank of India');

      // Check extracted indicators
      expect(result.indicators.urls.length).toBeGreaterThanOrEqual(1);
      expect(result.indicators.phones.length).toBe(1);
      expect(result.indicators.upiIds.length).toBe(1);

      // Verify that the extracted URL was passed to the existing ReputationService scanner!
      expect(result.securityChecks.urlChecks.length).toBeGreaterThanOrEqual(1);
      const urlCheck = result.securityChecks.urlChecks[0];
      expect(urlCheck.url).toContain('sbi-online-kyc-verification.top');
      expect(urlCheck.isBlocked).toBe(true);
      expect(urlCheck.verdict).toContain('CRITICAL');

      // Verify classification and risk score
      expect(result.scamClassification.category).toBe('FAKE_KYC');
      expect(result.verdict).toBe('CRITICAL');
      expect(result.overallRiskScore).toBeGreaterThanOrEqual(95);

      // Verify recommended actions
      expect(result.recommendedActions.length).toBeGreaterThan(0);
      expect(result.recommendedActions.some((a) => a.includes('Do NOT click or open any links'))).toBe(true);
      expect(result.recommendedActions.some((a) => a.includes('Never share OTPs'))).toBe(true);
    });

    it('rejects image files exceeding size limits gracefully without crashing', async () => {
      const oversizedBytes = 16 * 1024 * 1024; // 16 MB
      await expect(
        ImageScanner.scanImage('data:image/png;base64,AAAA', {
          name: 'huge.png',
          sizeBytes: oversizedBytes,
          mimeType: 'image/png',
        })
      ).rejects.toThrow('exceeds maximum allowed limit');
    });

    it('heals line-wrapped shortened URLs common in mobile SMS notifications', () => {
      const wrappedText = `
        Dear Customer your Icici bank Accounts KYC has been suspended
        Accounts https://is.gd/
        J9gaHq.iciciBank.KYC
      `;

      const urls = IndicatorExtractor.extractUrls(wrappedText);
      expect(urls.length).toBe(1);
      expect(urls[0].original).toBe('https://is.gd/J9gaHq.iciciBank.KYC');
      expect(urls[0].isShortener).toBe(true);
      expect(urls[0].domain).toBe('is.gd');
    });

    it('rejects unsupported image MIME types gracefully', async () => {
      await expect(
        ImageScanner.scanImage('data:application/pdf;base64,AAAA', {
          name: 'scam.pdf',
          sizeBytes: 1024,
          mimeType: 'application/pdf',
        })
      ).rejects.toThrow('Unsupported image format');
    });

    it('returns UNVERIFIED and cautionary 20% score when an image yields no OCR text (never 0% clean)', async () => {
      // Mock an empty data URL that produces no OCR text
      const emptyDataUrl = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

      const result = await ImageScanner.scanImage(emptyDataUrl, {
        name: 'blank-image.png',
        sizeBytes: 68,
        mimeType: 'image/png',
      });

      expect(result.verdict).toBe('UNVERIFIED');
      expect(result.overallRiskScore).toBe(20);
      expect(result.isUnverified).toBe(true);
      expect(result.analysisStatus).toBe('INCOMPLETE');
      expect(result.scamClassification.primaryThreatSummary).toContain('IMAGE ANALYSIS INCOMPLETE');
      expect(result.recommendedActions.length).toBeGreaterThan(0);
      expect(result.diagnostics).toBeDefined();
      expect(result.diagnostics.ocrEngine).toBeDefined();
    });

    it('scans the actual real-world ICICI fake KYC screenshot fixture and identifies the scam with CRITICAL severity', async () => {
      const fixturePath = path.join(__dirname, 'fixtures/real-scam-sms.jpeg');
      expect(fs.existsSync(fixturePath)).toBe(true);

      const buffer = fs.readFileSync(fixturePath);
      const dataUrl = `data:image/jpeg;base64,${buffer.toString('base64')}`;

      const result = await ImageScanner.scanImage(dataUrl, {
        name: 'real-scam-sms.jpeg',
        sizeBytes: buffer.length,
        mimeType: 'image/jpeg',
      });

      // Verify OCR extracted recognizable fragments
      expect(result.ocrResult.extractedText.length).toBeGreaterThan(50);
      const lowerOcr = result.ocrResult.extractedText.toLowerCase();
      expect(lowerOcr).toContain('customer');
      expect(lowerOcr).toContain('icici');
      expect(lowerOcr).toContain('kyc');
      expect(lowerOcr).toContain('suspended');

      // Verify shortened URL was extracted and identified as shortener
      expect(result.indicators.urls.length).toBeGreaterThanOrEqual(1);
      const isGdUrl = result.indicators.urls.find((u) => u.original.includes('is.gd'));
      expect(isGdUrl).toBeDefined();
      expect(isGdUrl?.isShortener).toBe(true);

      // Verify sender phone number was extracted
      expect(result.indicators.phones.length).toBeGreaterThanOrEqual(1);
      const phone = result.indicators.phones[0];
      expect(phone.isIndian).toBe(true);
      expect(phone.riskLevel).toBe('HIGH');

      // Verify final verdict and risk score
      expect(result.scamClassification.category).toBe('FAKE_KYC');
      expect(result.verdict).toBe('CRITICAL');
      expect(result.overallRiskScore).toBeGreaterThanOrEqual(85);
      expect(result.isUnverified).toBe(false);
      expect(result.analysisStatus).toBe('COMPLETE');

      // Verify developer diagnostics telemetry
      expect(result.diagnostics).toBeDefined();
      expect(result.diagnostics.imageSizeBytes).toBe(buffer.length);
      expect(result.diagnostics.ocrDurationMs).toBeGreaterThan(0);
      expect(result.diagnostics.ocrTextLength).toBeGreaterThan(50);
    });
  });
});
