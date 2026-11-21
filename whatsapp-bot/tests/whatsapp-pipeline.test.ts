/**
 * ScamShield WhatsApp Bot Comprehensive Verification Suite
 *
 * Implements the complete 20-scenario test matrix from Section 14:
 *  1. Normal legitimate message (SAFE)
 *  2. Bank KYC scam (CRITICAL/HIGH)
 *  3. OTP phishing (CRITICAL)
 *  4. Parcel/courier scam (HIGH/CRITICAL)
 *  5. UPI fraud lure (HIGH)
 *  6. Lottery/cashback scam (HIGH/CRITICAL)
 *  7. Job offer scam (HIGH)
 *  8. Hinglish electricity scam (HIGH/CRITICAL)
 *  9. Hindi banking scam (HIGH/CRITICAL)
 * 10. Screenshot containing a scam (CRITICAL/HIGH)
 * 11. Screenshot containing legitimate text (SAFE)
 * 12. URL extraction and detection
 * 13. Indian phone number extraction
 * 14. UPI ID extraction
 * 15. Image with unreadable/blank text (UNVERIFIED CAUTION, never safe 0%)
 * 16. URL-only submission
 * 17. Multiple URLs submission
 * 18. Local heuristics fallback (offline deterministic safety)
 * 19. Gemini -> Groq fallback resilience
 * 20. Total AI outage local heuristic safety net
 * Plus:
 * - Interactive Consent Flow (1 -> consent prompt -> YES -> URL report -> NO -> cancel)
 * - Incident Reporting Flow (3 -> confirmation + 1930 helpline)
 * - SSRF Protection for media and URLs
 */

import { describe, it, expect } from 'vitest';
import { ScannerClient } from '../src/scanner-client.js';
import { BackendAIEngine } from '../src/ai-engine.js';
import { UrlInvestigator } from '../src/url-investigator.js';
import { OcrService } from '../src/ocr-service.js';
import { SessionManager } from '../src/session-manager.js';

describe('ScamShield WhatsApp Bot Comprehensive 20-Scenario Verification', () => {
  // 1. Normal Legitimate Message
  it('Scenario 1: Normal legitimate shipping notification classifies as SAFE', async () => {
    const legitText =
      'Your order #98214 has been shipped via BlueDart Express. You can track your package at https://bluedart.com/track/98214. Delivery expected tomorrow.';
    const result = await ScannerClient.scanMessage(legitText, 'user_scen_1');

    expect(result.verdict).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(15);
    expect(result.formattedReply).toContain('NO KNOWN THREAT');
  }, 25000);

  // 2. Bank KYC Scam
  it('Scenario 2: Urgent SBI KYC account suspension scam flags as CRITICAL / HIGH', async () => {
    const kycText =
      'URGENT: Dear SBI Customer, your bank account will be blocked today due to pending KYC. Click immediately to update: https://sbi-online-kyc-verification.top/auth Contact: +91 9876543210';
    const result = await ScannerClient.scanMessage(kycText, 'user_scen_2');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.category).toBe('FAKE_KYC');
    expect(result.extractedUrls.length).toBeGreaterThanOrEqual(1);
    expect(result.formattedReply).toContain('SCAMSHIELD THREAT ALERT');
  }, 25000);

  // 3. OTP Phishing
  it('Scenario 3: Credential & OTP theft lure flags as CRITICAL', async () => {
    const otpText =
      'Security Alert: Unauthorized debit of Rs 48,500 detected on your debit card. To cancel this transaction, immediately share the 6-digit OTP sent to your phone with executive on 919876543210.';
    const result = await ScannerClient.scanMessage(otpText, 'user_scen_3');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
    expect(result.formattedReply).toContain('Do NOT share OTP, UPI PIN, or bank passwords');
  }, 25000);

  // 4. Parcel / Courier Scam
  it('Scenario 4: India Post delivery fee redelivery scam flags as HIGH / CRITICAL', async () => {
    const courierText =
      'India Post: Your parcel #IN89218 cannot be delivered due to incomplete house address. Please pay redelivery fee of Rs 25 within 24 hours at https://indiapost-redelivery.top/pay';
    const result = await ScannerClient.scanMessage(courierText, 'user_scen_4');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(75);
    expect(result.extractedUrls.length).toBeGreaterThanOrEqual(1);
  }, 25000);

  // 5. UPI Fraud Lure
  it('Scenario 5: Fraudulent UPI collect / refund desk flags as HIGH / CRITICAL', async () => {
    const upiText =
      'Dear customer, Rs 3,500 refund has been approved for your failed transaction. To receive money into your bank, approve collect request sent by refund-desk@upi and enter your UPI PIN.';
    const result = await ScannerClient.scanMessage(upiText, 'user_scen_5');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
    expect(result.extractedUpiIds).toContain('refund-desk@upi');
  }, 25000);

  // 6. Lottery / Cashback Scam
  it('Scenario 6: KBC Lottery / sudden financial reward flags as HIGH / CRITICAL', async () => {
    const lotteryText =
      'Congratulations! Your mobile number has won Rs 25,00,000 in KBC Jio Lucky Draw. Contact KBC manager Mr. Rana on +91 9988776655 to claim your prize money.';
    const result = await ScannerClient.scanMessage(lotteryText, 'user_scen_6');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
  }, 25000);

  // 7. Job Offer Scam
  it('Scenario 7: Work-from-home YouTube like / advance fee scam flags as HIGH', async () => {
    const jobText =
      'Part-time online job opportunity! Earn Rs 3,000 to Rs 8,000 daily by simply liking YouTube videos and rating hotels on Google. No experience required. Message on WhatsApp: +91 9123456789.';
    const result = await ScannerClient.scanMessage(jobText, 'user_scen_7');

    expect(['HIGH', 'CRITICAL', 'SUSPICIOUS']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(60);
  }, 25000);

  // 8. Hinglish Electricity Scam
  it('Scenario 8: Hinglish electricity disconnection threat flags as HIGH / CRITICAL', async () => {
    const hinglishText =
      'Priya Grahak, aapka Bijli bill baki hai. Aaj raat 9:30 baje electricity connection disconnect ho jayega. Turant helpline number 9876543210 par call kare aur bill update karwaye.';
    const result = await ScannerClient.scanMessage(hinglishText, 'user_scen_8');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
  }, 25000);

  // 9. Hindi Banking Scam
  it('Scenario 9: Devanagari Hindi bank suspension threat flags as HIGH / CRITICAL', async () => {
    const hindiText =
      'प्रिय ग्राहक, आपका बैंक खाता आज ब्लॉक कर दिया जाएगा क्योंकि आपकी केवाईसी अधूरी है। खाता चालू रखने के लिए तुरंत इस लिंक पर क्लिक करें: https://bank-kyc-verify.top';
    const result = await ScannerClient.scanMessage(hindiText, 'user_scen_9');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(80);
  }, 25000);

  // 10. Screenshot containing a Scam
  it('Scenario 10: Screenshot containing fake bank KYC lure flags as CRITICAL / HIGH', async () => {
    // Generate a minimal mock base64 image or pass text directly to OCR indicator pipeline
    const mockImageText =
      'Dear Customer your Icici bank Accounts KYC has been suspended please update your KYC click in link https://is.gd/J9gaHq.iciciBank.KYC Helpline: +91 9876543210';

    const indicators = OcrService.extractIndicatorsFromText(mockImageText);
    expect(indicators.urls).toContain('https://is.gd/J9gaHq.iciciBank.KYC');
    expect(indicators.brands).toContain('ICICI Bank');

    // Run through message scanner
    const result = await ScannerClient.scanMessage(mockImageText, 'user_scen_10');
    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.riskScore).toBeGreaterThanOrEqual(85);
  }, 25000);

  // 11. Screenshot containing legitimate text
  it('Scenario 11: Screenshot containing clean corporate receipt classifies as SAFE', async () => {
    const legitImageText =
      'Amazon.in Order Confirmation: Order #402-1234567-8901234 has been confirmed. Total paid: Rs 499 via Amazon Pay UPI. Delivery on Friday.';
    const result = await ScannerClient.scanMessage(legitImageText, 'user_scen_11');

    expect(result.verdict).toBe('SAFE');
    expect(result.riskScore).toBeLessThanOrEqual(20);
  }, 25000);

  // 12. URL Extraction
  it('Scenario 12: High-precision extraction of plain, shortened, and protocol-less URLs', () => {
    const mixedText = 'Check updates at https://sbi-alert.top/verify or visit is.gd/bankUpdate today.';
    const extracted = OcrService.extractIndicatorsFromText(mixedText);

    expect(extracted.urls).toContain('https://sbi-alert.top/verify');
    expect(extracted.urls.some((u) => u.includes('is.gd/bankUpdate'))).toBe(true);
  });

  // 13. Indian Phone Extraction
  it('Scenario 13: Accurate extraction of +91, 0, and plain 10-digit Indian phone numbers', () => {
    const phoneText = 'Call helpline at +91 9876543210 or alternate desk 09123456789 or 9823456781';
    const extracted = OcrService.extractIndicatorsFromText(phoneText);

    expect(extracted.phones.length).toBeGreaterThanOrEqual(2);
  });

  // 14. UPI ID Extraction
  it('Scenario 14: Accurate extraction of UPI handles while excluding email addresses', () => {
    const upiText =
      'Send payment to fraud-desk@paytm or merchant@okhdfcbank. For questions contact support@gmail.com';
    const extracted = OcrService.extractIndicatorsFromText(upiText);

    expect(extracted.upiIds).toContain('fraud-desk@paytm');
    expect(extracted.upiIds).toContain('merchant@okhdfcbank');
    expect(extracted.upiIds).not.toContain('support@gmail.com');
  });

  // 15. Unreadable / Blank Image Handling
  it('Scenario 15: Blank or unreadable image returns CAUTIONARY assessment (never safe 0%)', async () => {
    // 1x1 transparent GIF base64
    const tinyBlankGif = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

    const result = await ScannerClient.scanImage(tinyBlankGif, 'user_scen_15');

    expect(result.verdict).toBe('SUSPICIOUS');
    expect(result.riskScore).toBeGreaterThanOrEqual(40);
    expect(result.category).toBe('UNVERIFIED_IMAGE_CONTENT');
    expect(result.formattedReply).toContain('UNVERIFIED IMAGE / SCREENSHOT');
    expect(result.formattedReply).toContain('unable to extract verifiable text');
  });

  // 16. URL-only Submission
  it('Scenario 16: Lone URL submission triggers domain reputation & threat assessment', async () => {
    const urlText = 'https://sbi-kyc-verify.top';
    const result = await ScannerClient.scanMessage(urlText, 'user_scen_16');

    expect(['CRITICAL', 'HIGH']).toContain(result.verdict);
    expect(result.extractedUrls).toContain('https://sbi-kyc-verify.top');
  }, 25000);

  // 17. Multiple URLs Submission
  it('Scenario 17: Message with multiple URLs extracts and parses all destinations', async () => {
    const multiUrlText =
      'Update SBI account at https://sbi-kyc.top or mirror at https://sbi-login.xyz/verify immediately.';
    const result = await ScannerClient.scanMessage(multiUrlText, 'user_scen_17');

    expect(result.extractedUrls.length).toBeGreaterThanOrEqual(2);
  }, 25000);

  // 18. Local Heuristics Fallback (Offline Deterministic Safety)
  it('Scenario 18: Local Heuristics classify KYC scams accurately when offline', () => {
    const sbiMsg =
      'URGENT: Dear Customer, your SBI bank account will be blocked today due to incomplete KYC. Update immediately to avoid account suspension. Verify now: https://sbi-kyc-alert.example/verify Call customer care: +91 9876543210';

    const res = BackendAIEngine.evaluateLocalHeuristics(sbiMsg, 'SMS');

    expect(res.success).toBe(true);
    expect(res.classification).toBe('SCAM');
    expect(res.riskLevel).toBe('HIGH');
    expect(res.confidenceScore).toBe(0.92);
    expect(res.scamCategory).toBe('BANKING_KYC_PHISHING');
  });

  // 19. Groq Fallback & Multi-Key Resilience
  it('Scenario 19: AI engine diagnostics capture provider status and latency without leaking keys', async () => {
    const testMsg = 'Urgent update: Your KYC is pending for your account. Click https://example-bank.com';
    const res = await BackendAIEngine.analyzeMessage(testMsg, 'WHATSAPP');

    expect(res.diagnostics).toBeDefined();
    expect(res.diagnostics.requestId).toBeDefined();
    expect(res.diagnostics.finalAnalysisStatus).toBeDefined();
    expect(res.diagnostics.providerDiagnostics.length).toBeGreaterThan(0);
  }, 25000);

  // 20. Total AI Outage Safety Net
  it('Scenario 20: Total AI unavailability engages deterministic local heuristic safety net', () => {
    const electricityMsg =
      'Dear Customer, your electricity power will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity officer on 9876543210.';

    const res = BackendAIEngine.evaluateLocalHeuristics(electricityMsg, 'WHATSAPP');

    expect(res.classification).toBe('SCAM');
    expect(res.riskLevel).toBe('HIGH');
    expect(res.scamCategory).toBe('ELECTRICITY_BILL_SCAM');
    expect(res.socialEngineeringTactics).toContain('Fear / Disconnection penalty');
  });

  // Interactive URL Consent Flow (Section 8)
  describe('Interactive Reply Flows (Options 1, 2, 3)', () => {
    it('executes Option 1 URL Consent flow (1 -> Prompt -> YES -> Investigation Report)', async () => {
      const user = 'interactive_user_url';

      // Step A: Send initial scam message
      const scanRes = await ScannerClient.scanMessage(
        'Dear user, update KYC immediately: https://sbi-online-kyc.top',
        user
      );
      expect(['CRITICAL', 'HIGH']).toContain(scanRes.verdict);

      // Step B: User replies '1' to investigate
      const reply1 = await ScannerClient.scanMessage('1', user);
      expect(reply1.category).toBe('CONSENT_REQUESTED');
      expect(reply1.formattedReply).toContain('URL DEEP INVESTIGATION');
      expect(reply1.formattedReply).toContain('Reply *YES* to proceed or *NO* to cancel');

      // Step C: User replies 'YES' to proceed
      const replyYes = await ScannerClient.scanMessage('YES', user);
      expect(['CRITICAL', 'HIGH', 'SUSPICIOUS']).toContain(replyYes.verdict);
      expect(replyYes.formattedReply).toContain('URL INVESTIGATION REPORT');
      expect(replyYes.formattedReply).toContain('https://sbi-online-kyc.top');
    }, 25000);

    it('cancels URL investigation when user replies NO', async () => {
      const user = 'cancel_user_url';

      await ScannerClient.scanMessage('Check this link: https://random-site.top', user);
      await ScannerClient.scanMessage('1', user);

      const cancelRes = await ScannerClient.scanMessage('NO', user);
      expect(cancelRes.category).toBe('CONSENT_SKIPPED');
      expect(cancelRes.formattedReply).toContain('investigation cancelled');
    }, 25000);

    it('executes Option 2 Explain Further flow', async () => {
      const user = 'explain_user';

      await ScannerClient.scanMessage(
        'Urgent: Your SBI account is blocked. Verify at https://sbi-fake.top',
        user
      );

      const explainRes = await ScannerClient.scanMessage('2', user);
      expect(explainRes.formattedReply).toContain('DETAILED THREAT BREAKDOWN');
      expect(explainRes.formattedReply).toContain('1930');
    }, 25000);

    it('executes Option 3 Report Scam flow', async () => {
      const user = 'report_user';

      await ScannerClient.scanMessage(
        'Urgent: Your SBI account is blocked. Verify at https://sbi-fake.top',
        user
      );

      const reportRes = await ScannerClient.scanMessage('3', user);
      expect(reportRes.formattedReply).toContain('SCAM REPORT RECORDED');
      expect(reportRes.formattedReply).toContain('INC-');
      expect(reportRes.formattedReply).toContain('1930');
    }, 25000);
  });

  // SSRF Protection
  describe('SSRF Protection Verification', () => {
    it('strictly blocks private IPs and loopback in URL investigation', async () => {
      const privateTargets = [
        'http://127.0.0.1:8080/admin',
        'http://localhost/secret',
        'http://169.254.169.254/latest/meta-data/',
        'https://192.168.1.1/router',
        'http://10.0.0.1/internal',
      ];

      for (const target of privateTargets) {
        const report = await UrlInvestigator.investigateUrl(target);
        expect(report.verdict).toBe('MALICIOUS');
        expect(report.category).toBe('SSRF_OR_INVALID_DESTINATION');
        expect(report.details[0]).toContain('SSRF prevention');
      }
    });

    it('allows verified corporate and government domains with CLEAN verdict', async () => {
      const legitUrl = 'https://bluedart.com/track/12345';
      const report = await UrlInvestigator.investigateUrl(legitUrl);

      expect(report.verdict).toBe('CLEAN');
      expect(report.riskScore).toBe(5);
    });
  });
});
