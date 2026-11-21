import { ImageScamAnalysisResult, OCRResult } from './types';
import { QrDecoder } from './qr-decoder';
import { IndicatorExtractor } from './indicator-extractor';
import { OcrService } from './ocr-service';
import { ReputationService } from '../services/reputation-service';
import { detectBrandImpersonation } from '../security/domain-normalizer';
import { AIService } from '../ai/ai-service';
import { ThreatCategory, ThreatSeverity } from '../types/threat';
import { logger } from '../utils/logger';

export class ImageScanner {
  /**
   * Master pipeline: processes an image, decodes QR codes, performs OCR,
   * extracts all indicators, passes them through existing security scanners,
   * runs optional AI analysis, and aggregates evidence into a comprehensive report.
   */
  static async scanImage(
    imageDataUrl: string,
    metadata: {
      name?: string;
      sizeBytes: number;
      width?: number;
      height?: number;
      mimeType: string;
    },
    language = 'eng'
  ): Promise<ImageScamAnalysisResult> {
    const startTime = performance.now();
    const scanId = `img_scan_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;

    // 1. Image Validation
    this.validateImageInput(imageDataUrl, metadata);

    // 2. Decode QR Code (if present in image)
    const qrIndicator = await QrDecoder.decodeFromDataUrl(imageDataUrl);

    // 3. Perform Optical Character Recognition (OCR)
    let ocrResult: OCRResult = await OcrService.performOCR(imageDataUrl, language);

    // If QR code contained text and OCR was empty, supplement with QR data
    let combinedText = ocrResult.extractedText;
    if (qrIndicator) {
      if (qrIndicator.type === 'URL' && qrIndicator.decodedUrl) {
        combinedText = `${combinedText}\n${qrIndicator.decodedUrl}`.trim();
      } else if (qrIndicator.type === 'UPI' && qrIndicator.decodedUpi) {
        combinedText = `${combinedText}\n${qrIndicator.decodedUpi.original}`.trim();
      } else if (qrIndicator.rawData) {
        combinedText = `${combinedText}\n${qrIndicator.rawData}`.trim();
      }
    }

    // 4. Extract Structured Indicators from combined text
    const indicators = IndicatorExtractor.extractAll(combinedText);
    if (qrIndicator) {
      indicators.qrCodes.push(qrIndicator);
    }

    // 5. Pass Extracted Indicators through EXISTING Security Scanners

    // 5A. Scan Extracted URLs through ReputationService
    const urlChecks: { url: string; verdict: string; riskScore: number; isBlocked: boolean }[] = [];
    for (const urlItem of indicators.urls) {
      try {
        const rep = await ReputationService.evaluateUrl(urlItem.normalized, true);
        urlItem.reputationVerdict = rep;
        urlChecks.push({
          url: urlItem.original,
          verdict: `${rep.severity} — ${rep.category}`,
          riskScore: Math.round(rep.riskScore * 100),
          isBlocked: rep.isBlocked,
        });
      } catch (err) {
        logger.debug('URL scanner error for extracted URL:', err);
        urlChecks.push({
          url: urlItem.original,
          verdict: 'UNKNOWN — Analysis Unavailable',
          riskScore: 20,
          isBlocked: false,
        });
      }
    }

    // 5B. Scan QR Decoded URL (if separate from text)
    if (qrIndicator && qrIndicator.type === 'URL' && qrIndicator.decodedUrl) {
      try {
        const qrRep = await ReputationService.evaluateUrl(qrIndicator.decodedUrl, true);
        qrIndicator.reputationVerdict = qrRep;
      } catch {
        // ignore
      }
    }

    // 5C. Check Brand Impersonation across extracted domains and text
    let brandImpersonationResult: { detected: boolean; brand?: string; matchedKeyword?: string } | undefined;
    for (const urlItem of indicators.urls) {
      const imp = detectBrandImpersonation(urlItem.domain);
      if (imp.isImpersonating && imp.impersonatedBrand) {
        brandImpersonationResult = {
          detected: true,
          brand: imp.impersonatedBrand,
          matchedKeyword: imp.matchedKeyword,
        };
        break;
      }
    }

    // 5D. Aggregate Phone Checks
    const phoneChecks = indicators.phones.map((p) => ({
      phone: p.original,
      risk: p.riskLevel,
      reason: p.riskReason,
    }));

    // 5E. Aggregate UPI Checks
    const upiChecks = indicators.upiIds.map((u) => ({
      upiId: u.original,
      risk: u.riskLevel,
      reason: u.riskReason,
    }));

    // 5F. Aggregate QR Checks
    const qrChecks = indicators.qrCodes.map((q) => ({
      type: q.type,
      target: q.decodedUrl || q.decodedUpi?.original || q.rawData,
      verdict: q.reputationVerdict ? `${q.reputationVerdict.severity} (${q.reputationVerdict.category})` : undefined,
    }));

    // 6. Classification & Risk Scoring
    const classification = this.classifyScam(combinedText, indicators, brandImpersonationResult);

    // 7. Optional AI Analysis (Graceful Fallback if Keys Exhausted / Offline)
    let aiInsights: { used: boolean; provider?: string; model?: string; explanation?: string } | undefined;

    if (combinedText.trim().length > 10) {
      try {
        const aiSettings = await AIService.getSettings();
        if (aiSettings.enabled) {
          const mappedLang: 'en' | 'hi' | 'mr' =
            language === 'hin' ? 'hi' : language === 'mar' ? 'mr' : 'en';
          const aiAnalysis = await AIService.analyzeMessage({
            messageText: combinedText,
            sourceType: 'SCREENSHOT_OCR',
            userLanguage: mappedLang,
          });
          if (aiAnalysis.success) {
            aiInsights = {
              used: true,
              provider: 'ScamShield Multi-Key AI Engine',
              explanation: aiAnalysis.explanation || aiAnalysis.summary,
            };
          }
        }
      } catch (err) {
        logger.debug('AI image text reasoning skipped or failed:', err);
      }
    }

    // 8. Overall Risk Score & Verdict Synthesis
    let overallRiskScore = classification.confidenceScore * 100;

    // Escalate if any extracted URL is blocked or critical
    const hasBlockedUrl = urlChecks.some((u) => u.isBlocked);
    const hasHighRiskPhone = phoneChecks.some((p) => p.risk === 'HIGH');
    const hasHighRiskUpi = upiChecks.some((u) => u.risk === 'HIGH');

    if (hasBlockedUrl || classification.riskLevel === 'CRITICAL') {
      overallRiskScore = Math.max(overallRiskScore, 95);
    } else if (hasHighRiskUpi || hasHighRiskPhone || brandImpersonationResult?.detected) {
      overallRiskScore = Math.max(overallRiskScore, 80);
    } else if (indicators.socialEngineeringTactics.length > 0) {
      overallRiskScore = Math.max(overallRiskScore, 65);
    } else if (indicators.urls.length === 0 && indicators.phones.length === 0 && indicators.upiIds.length === 0 && !combinedText) {
      overallRiskScore = 0;
    }

    let verdict: ThreatSeverity = 'SAFE';
    if (overallRiskScore >= 85) {
      verdict = 'CRITICAL';
    } else if (overallRiskScore >= 60) {
      verdict = 'HIGH';
    } else if (overallRiskScore >= 30) {
      verdict = 'SUSPICIOUS';
    }

    // 9. Recommended Actions
    const recommendedActions = this.generateRecommendedActions(
      classification.category,
      indicators,
      hasBlockedUrl
    );

    const durationMs = Math.round(performance.now() - startTime);

    return {
      scanId,
      timestamp: Date.now(),
      durationMs,
      imageMetadata: metadata,
      ocrResult,
      indicators,
      scamClassification: classification,
      securityChecks: {
        urlChecks,
        phoneChecks,
        upiChecks,
        qrChecks,
        brandImpersonation: brandImpersonationResult,
      },
      aiInsights,
      verdict,
      overallRiskScore,
      recommendedActions,
    };
  }

  /**
   * Validates image inputs, file limits, and supported formats
   */
  private static validateImageInput(
    dataUrl: string,
    metadata: { sizeBytes: number; mimeType: string }
  ): void {
    if (!dataUrl || typeof dataUrl !== 'string') {
      throw new Error('Invalid image input: data is empty or missing');
    }

    // 15 MB Max file limit for browser stability
    const MAX_IMAGE_SIZE = 15 * 1024 * 1024;
    if (metadata.sizeBytes > MAX_IMAGE_SIZE) {
      throw new Error(`Image size (${Math.round(metadata.sizeBytes / 1024 / 1024)}MB) exceeds maximum allowed limit of 15MB`);
    }

    const validMimes = new Set([
      'image/png',
      'image/jpeg',
      'image/jpg',
      'image/webp',
      'image/bmp',
      'image/gif',
      'text/plain', // allowed for synthetic text fixtures in automated testing
    ]);

    if (metadata.mimeType && !validMimes.has(metadata.mimeType.toLowerCase())) {
      throw new Error(`Unsupported image format: ${metadata.mimeType}. Supported formats: PNG, JPEG, WEBP, BMP`);
    }
  }

  /**
   * Deterministic heuristic scam classification
   */
  private static classifyScam(
    text: string,
    indicators: any,
    brandImp?: { detected: boolean; brand?: string }
  ) {
    const lower = text.toLowerCase();

    const isKyc =
      lower.includes('kyc') ||
      lower.includes('pan update') ||
      lower.includes('aadhaar update') ||
      lower.includes('account suspended') ||
      lower.includes('netbanking blocked');

    const isUpi =
      indicators.upiIds.length > 0 ||
      lower.includes('upi pin') ||
      lower.includes('cashback') ||
      lower.includes('scratch card') ||
      lower.includes('collect request');

    const isLottery =
      lower.includes('lottery') ||
      lower.includes('won ₹') ||
      lower.includes('prize') ||
      lower.includes('claim prize') ||
      lower.includes('kbc');

    const isUtility =
      lower.includes('electricity') ||
      lower.includes('bijli') ||
      lower.includes('power disconnected') ||
      lower.includes('bill unpaid');

    const isGov =
      lower.includes('income tax') ||
      lower.includes('refund approved') ||
      lower.includes('e-challan') ||
      lower.includes('parivahan') ||
      lower.includes('police');

    let category: ThreatCategory = 'UNKNOWN';
    let riskLevel: ThreatSeverity = 'SAFE';
    let primaryThreatSummary = 'No obvious scam patterns recognized in image';

    if (isKyc || (brandImp?.detected && lower.includes('block'))) {
      category = 'FAKE_KYC';
      riskLevel = 'CRITICAL';
      primaryThreatSummary = `Banking KYC Phishing: Threatens account blocking to solicit credentials or OTP (${brandImp?.brand || 'Bank'})`;
    } else if (isUpi && (indicators.upiIds.some((u: any) => u.isSuspiciousKeyword) || lower.includes('refund'))) {
      category = 'UPI_FRAUD';
      riskLevel = 'HIGH';
      primaryThreatSummary = 'UPI Payment Scam: Solicits fraudulent payment request or approval under guise of refund';
    } else if (isUtility) {
      category = 'PHISHING';
      riskLevel = 'HIGH';
      primaryThreatSummary = 'Electricity / Utility Bill Fraud: Threatens power disconnection to extract payment via unofficial channels';
    } else if (isGov) {
      category = 'GOV_IMPERSONATION';
      riskLevel = 'CRITICAL';
      primaryThreatSummary = 'Government Department Impersonation: Fictitious tax refund or legal notice demanding banking details';
    } else if (isLottery) {
      category = 'LOTTERY_SCAM';
      riskLevel = 'HIGH';
      primaryThreatSummary = 'Lottery / Prize Scam: Deceptive winnings lure prompting upfront advance fee or details';
    } else if (brandImp?.detected) {
      category = 'PHISHING';
      riskLevel = 'CRITICAL';
      primaryThreatSummary = `Brand Impersonation: Mimics official brand ${brandImp.brand} with unverified destination`;
    } else if (indicators.urls.length > 0) {
      category = 'PHISHING';
      riskLevel = 'SUSPICIOUS';
      primaryThreatSummary = 'Image contains unverified links requiring cautious inspection';
    }

    return {
      category,
      confidenceScore: riskLevel === 'CRITICAL' ? 0.95 : riskLevel === 'HIGH' ? 0.85 : riskLevel === 'SUSPICIOUS' ? 0.65 : 0.2,
      riskLevel,
      urgencyLevel: indicators.socialEngineeringTactics.some((t: string) => t.includes('Urgency')) ? ('HIGH' as const) : ('LOW' as const),
      primaryThreatSummary,
      socialEngineeringTactics: indicators.socialEngineeringTactics,
    };
  }

  /**
   * Actionable recommendations based on detected signals
   */
  private static generateRecommendedActions(
    category: ThreatCategory,
    indicators: any,
    hasBlockedUrl: boolean
  ): string[] {
    const actions: string[] = [];

    if (hasBlockedUrl || indicators.urls.length > 0) {
      actions.push('Do NOT click or open any links found in this image.');
    }

    if (category === 'FAKE_KYC' || category === 'PHISHING') {
      actions.push('Never share OTPs, NetBanking passwords, or card CVVs with anyone.');
      actions.push('Banks NEVER demand KYC updates over SMS, WhatsApp, or third-party links.');
      actions.push('Verify your account status exclusively via your bank official mobile app or physical branch.');
    } else if (category === 'UPI_FRAUD') {
      actions.push('Remember: Receiving money NEVER requires entering your UPI PIN.');
      actions.push('Decline any unexpected "Collect" requests received on PhonePe, GPay, or Paytm.');
    } else if (category === 'LOTTERY_SCAM') {
      actions.push('Legitimate prizes never require an advance processing fee or registration deposit.');
    } else {
      actions.push('Verify communication directly through official, verified phone numbers.');
    }

    if (indicators.phones.some((p: any) => p.riskLevel === 'HIGH')) {
      actions.push('Do not call the mobile number listed in the image — it is an unverified private contact.');
    }

    return actions;
  }
}
