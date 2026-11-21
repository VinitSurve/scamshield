import { ImageScamAnalysisResult, ImageDiagnosticTelemetry } from './types';
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
   * Master pipeline: processes an image, decodes QR codes, performs multi-pass OCR,
   * falls back to Groq/Gemini Vision AI if local OCR fails, extracts all indicators,
   * passes them through existing security scanners, runs optional AI reasoning,
   * and aggregates evidence into a comprehensive report.
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
    this.validateImageInput(metadata);

    // 2. Decode QR Code (if present in image)
    const qrIndicator = await QrDecoder.decodeFromDataUrl(imageDataUrl);

    // 3. Perform Optical Character Recognition (OCR) with Local Tesseract & Multi-Pass Preprocessing
    let ocrResult = await OcrService.performOCR(imageDataUrl, language);

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

    // 4. Vision Fallback: If Local OCR failed or extracted minimal unusable text (< 15 chars)
    let aiFallbackAttempted = false;
    let aiFallbackStatus: 'SUCCESS' | 'FAILED' | 'SKIPPED' | 'KEYS_EXHAUSTED' = 'SKIPPED';
    let aiProvider: string | undefined;
    let aiModel: string | undefined;

    if (!combinedText || combinedText.trim().length < 15) {
      aiFallbackAttempted = true;
      try {
        const visionResult = await this.tryVisionFallback(imageDataUrl);
        if (visionResult.success && visionResult.extractedText) {
          combinedText = visionResult.extractedText;
          ocrResult.extractedText = visionResult.extractedText;
          ocrResult.sourceEngine = 'AI_VISION';
          ocrResult.status = 'SUCCESS';
          aiFallbackStatus = 'SUCCESS';
          aiProvider = visionResult.provider;
          aiModel = visionResult.model;
        } else {
          aiFallbackStatus = visionResult.error?.includes('exhausted')
            ? 'KEYS_EXHAUSTED'
            : 'FAILED';
        }
      } catch (visionErr) {
        logger.debug('Vision fallback error:', visionErr);
        aiFallbackStatus = 'FAILED';
      }
    }

    const durationMs = Math.round(performance.now() - startTime);

    // 5. Build Developer Diagnostic Telemetry
    const diagnostics: ImageDiagnosticTelemetry = {
      fileType: metadata.mimeType || 'image/jpeg',
      imageDimensions: `${metadata.width || 'auto'}x${metadata.height || 'auto'}`,
      imageSizeBytes: metadata.sizeBytes,
      selectedLanguage: language,
      ocrEngine: ocrResult.sourceEngine,
      ocrInitialization: 'OK',
      workerStatus: (ocrResult as any).diagnostics?.workerStatus || 'READY',
      wasmStatus: (ocrResult as any).diagnostics?.wasmStatus || 'READY',
      languageDataStatus: (ocrResult as any).diagnostics?.languageDataStatus || 'LOCAL_EMBEDDED',
      ocrDurationMs: ocrResult.processingTimeMs,
      ocrTextLength: combinedText.length,
      ocrStatus: combinedText ? 'SUCCESS' : 'FAILED',
      passesAttempted: (ocrResult as any).passesAttempted || 1,
      preprocessingTechniques: (ocrResult as any).preprocessingTechniques || [],
      aiFallbackAttempted,
      aiProvider,
      aiModel,
      aiFallbackStatus,
      aiFallbackOutputSnippet: aiProvider ? combinedText.slice(0, 150) : undefined,
    };

    // 6. Security Critical Check: If both Local OCR and Vision failed to extract readable text
    if (!combinedText || combinedText.trim().length === 0) {
      return {
        scanId,
        timestamp: Date.now(),
        durationMs,
        analysisStatus: 'INCOMPLETE',
        isUnverified: true,
        imageMetadata: metadata,
        ocrResult,
        indicators: {
          urls: [],
          phones: [],
          upiIds: [],
          emails: [],
          qrCodes: qrIndicator ? [qrIndicator] : [],
          socialEngineeringTactics: [],
        },
        scamClassification: {
          category: 'UNKNOWN',
          confidenceScore: 0,
          riskLevel: 'SAFE',
          urgencyLevel: 'NONE',
          primaryThreatSummary:
            'IMAGE ANALYSIS INCOMPLETE: We could not reliably extract text from this image. The image has NOT been verified as safe.',
          socialEngineeringTactics: [],
        },
        securityChecks: {
          urlChecks: [],
          phoneChecks: [],
          upiChecks: [],
          qrChecks: qrIndicator
            ? [
                {
                  type: qrIndicator.type,
                  target: qrIndicator.decodedUrl || qrIndicator.rawData,
                  verdict: 'UNVERIFIED',
                },
              ]
            : [],
        },
        diagnostics,
        verdict: 'UNVERIFIED',
        overallRiskScore: 20, // Strict caution score: Never display 0% clean for unanalyzable images
        recommendedActions: [
          'Upload a clearer screenshot with sharp, readable text',
          'Crop the image directly around the message or notification',
          'Avoid taking photos of screens with glare or moiré patterns',
        ],
      };
    }

    // 7. Extract Structured Indicators from combined text
    const indicators = IndicatorExtractor.extractAll(combinedText);
    if (qrIndicator) {
      indicators.qrCodes.push(qrIndicator);
    }

    // 8. Pass Extracted Indicators through EXISTING Security Scanners

    // 8A. Scan Extracted URLs through ReputationService
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

    // 8B. Scan QR Decoded URL (if separate from text)
    if (qrIndicator && qrIndicator.type === 'URL' && qrIndicator.decodedUrl) {
      try {
        const qrRep = await ReputationService.evaluateUrl(qrIndicator.decodedUrl, true);
        qrIndicator.reputationVerdict = qrRep;
      } catch {
        // ignore
      }
    }

    // 8C. Check Brand Impersonation across extracted domains and text
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

    // 8D. Aggregate Phone Checks
    const phoneChecks = indicators.phones.map((p) => ({
      phone: p.original,
      risk: p.riskLevel,
      reason: p.riskReason,
    }));

    // 8E. Aggregate UPI Checks
    const upiChecks = indicators.upiIds.map((u) => ({
      upiId: u.original,
      risk: u.riskLevel,
      reason: u.riskReason,
    }));

    // 8F. Aggregate QR Checks
    const qrChecks = indicators.qrCodes.map((q) => ({
      type: q.type,
      target: q.decodedUrl || q.decodedUpi?.original || q.rawData,
      verdict: q.reputationVerdict ? `${q.reputationVerdict.severity} (${q.reputationVerdict.category})` : undefined,
    }));

    // 9. Classification & Risk Scoring
    const classification = this.classifyScam(combinedText, indicators, brandImpersonationResult);

    // 10. Optional AI Analysis (Graceful Fallback if Keys Exhausted / Offline)
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

    // 11. Overall Risk Score & Verdict Synthesis
    let overallRiskScore = classification.confidenceScore * 100;

    const hasBlockedUrl = urlChecks.some((u) => u.isBlocked);
    const hasHighRiskPhone = phoneChecks.some((p) => p.risk === 'HIGH');
    const hasHighRiskUpi = upiChecks.some((u) => u.risk === 'HIGH');
    const hasShortener = indicators.urls.some((u) => u.isShortener);

    if (hasBlockedUrl || classification.riskLevel === 'CRITICAL') {
      overallRiskScore = Math.max(overallRiskScore, 95);
    } else if (hasShortener && classification.category === 'FAKE_KYC') {
      overallRiskScore = Math.max(overallRiskScore, 95);
    } else if (hasHighRiskUpi || hasHighRiskPhone || brandImpersonationResult?.detected || hasShortener) {
      overallRiskScore = Math.max(overallRiskScore, 85);
    } else if (indicators.socialEngineeringTactics.length > 0) {
      overallRiskScore = Math.max(overallRiskScore, 65);
    } else if (indicators.urls.length === 0 && indicators.phones.length === 0 && indicators.upiIds.length === 0) {
      overallRiskScore = 5;
    }

    let verdict: ThreatSeverity = 'SAFE';
    if (overallRiskScore >= 85) {
      verdict = 'CRITICAL';
    } else if (overallRiskScore >= 60) {
      verdict = 'HIGH';
    } else if (overallRiskScore >= 30) {
      verdict = 'SUSPICIOUS';
    }

    // 12. Recommended Actions
    const recommendedActions = this.generateRecommendedActions(
      classification.category,
      hasBlockedUrl
    );

    return {
      scanId,
      timestamp: Date.now(),
      durationMs,
      analysisStatus: 'COMPLETE',
      isUnverified: false,
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
      diagnostics,
      verdict,
      overallRiskScore,
      recommendedActions,
    };
  }

  /**
   * Attempts Vision text extraction: queries backend service first, then local KeyManager
   */
  private static async tryVisionFallback(imageDataUrl: string): Promise<{
    success: boolean;
    extractedText: string;
    provider?: string;
    model?: string;
    error?: string;
  }> {
    // 1. Try Backend Vision Endpoint (e.g. localhost:3001 or cloud API)
    try {
      const backendUrl = 'http://localhost:3001/api/v1/analyze/image-vision';
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 4000);

      const resp = await fetch(backendUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ imageDataUrl }),
        signal: controller.signal,
      });
      clearTimeout(timer);

      if (resp.ok) {
        const data = await resp.json();
        if (data.extractedText) {
          return {
            success: true,
            extractedText: data.extractedText,
            provider: data.provider || 'groq',
            model: data.model || 'qwen/qwen3.8-27b',
          };
        }
      }
    } catch {
      // Backend not running, seamlessly proceed to direct ProviderRouter
    }

    // 2. Direct ProviderRouter Vision Fallback
    try {
      const res = await AIService.extractTextWithVisionFallback(imageDataUrl);
      if (res.success && res.extractedText) {
        return {
          success: true,
          extractedText: res.extractedText,
          provider: res.providerUsed,
          model: res.modelUsed,
        };
      }
      return { success: false, extractedText: '', error: res.error };
    } catch (err: any) {
      return { success: false, extractedText: '', error: err.message };
    }
  }

  /**
   * Validates image format and file size limits
   */
  private static validateImageInput(
    metadata: { sizeBytes: number; mimeType?: string }
  ) {
    const MAX_ALLOWED_BYTES = 15 * 1024 * 1024; // 15MB limit
    if (metadata.sizeBytes > MAX_ALLOWED_BYTES) {
      throw new Error(
        `Image size (${Math.round(metadata.sizeBytes / (1024 * 1024))}MB) exceeds maximum allowed limit of 15MB.`
      );
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
      lower.includes('accounts kyc') ||
      lower.includes('has been suspended') ||
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
    }

    return {
      category,
      confidenceScore: riskLevel === 'CRITICAL' ? 0.95 : riskLevel === 'HIGH' ? 0.8 : 0.2,
      riskLevel,
      urgencyLevel: (isKyc || isUtility ? 'HIGH' : 'MEDIUM') as 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE',
      primaryThreatSummary,
      socialEngineeringTactics: indicators.socialEngineeringTactics,
    };
  }

  /**
   * Actionable recommendations
   */
  private static generateRecommendedActions(
    category: ThreatCategory,
    hasBlockedUrl: boolean
  ): string[] {
    const actions: string[] = [];

    if (category === 'FAKE_KYC' || category === 'PHISHING' || hasBlockedUrl) {
      actions.push('Do NOT click or open any links found in the screenshot.');
      actions.push('Never share OTPs, PINs, passwords, or banking credentials.');
      actions.push('Banks NEVER demand KYC updates through unofficial shortened links or personal SMS.');
      actions.push('Report the incident to the National Cyber Crime Reporting Portal (cybercrime.gov.in) or call 1930.');
    } else if (category === 'UPI_FRAUD') {
      actions.push('Do NOT approve any pending UPI collect requests.');
      actions.push('Remember: Entering your UPI PIN always DEDUCTS money from your account, never receives it.');
    } else {
      actions.push('Verify any urgent requests directly with the official service provider via their verified portal.');
    }

    return actions;
  }
}
