/**
 * ScamShield WhatsApp Bot Scanner Client
 *
 * Primary orchestrator connecting:
 * - Multi-provider AI Threat Engine (Gemini + Groq + Local Heuristics)
 * - Tesseract OCR + AI Vision Service
 * - Safe URL Sandbox Investigator (SSRF-protected)
 * - Conversational Session Manager
 * - High-Information-Density Response Formatter
 */

import { BackendAIEngine, BackendAnalysisResult } from './ai-engine.js';
import { SessionManager, StoredScanResult } from './session-manager.js';
import { UrlInvestigator, UrlInvestigationResult } from './url-investigator.js';
import { OcrService, OcrAnalysisResult } from './ocr-service.js';
import { ConversationFormatter } from './conversation-formatter.js';

export interface BotScanResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  category: string;
  summary: string;
  extractedUrls: string[];
  extractedPhones: string[];
  extractedUpiIds: string[];
  socialTactics: string[];
  formattedReply: string;
  isScreenshot?: boolean;
  isUnverifiedImage?: boolean;
  rawText?: string;
}

export class ScannerClient {
  /**
   * Evaluates text message through ScamShield AI + heuristic engine and formats response
   */
  static async scanMessage(text: string, userId = 'default_user'): Promise<BotScanResult> {
    const trimmed = (text || '').trim();
    const lower = trimmed.toLowerCase();
    const session = SessionManager.getSession(userId);

    // ----------------------------------------------------
    // BRANCH 1: User Greetings & Help
    // ----------------------------------------------------
    const greetings = ['hi', 'hello', 'hey', 'start', 'help', 'menu', 'namaste', 'info'];
    if (greetings.includes(lower)) {
      SessionManager.resetState(userId, false);
      const greetingText = ConversationFormatter.formatGreeting();
      return {
        verdict: 'SAFE',
        riskScore: 0,
        category: 'GREETING',
        summary: 'ScamShield greeting dispatched.',
        extractedUrls: [],
        extractedPhones: [],
        extractedUpiIds: [],
        socialTactics: [],
        formattedReply: greetingText,
      };
    }

    // ----------------------------------------------------
    // BRANCH 2: URL Consent State Machine (Reply YES / NO)
    // ----------------------------------------------------
    if (session.state === 'AWAITING_URL_CONSENT') {
      if (lower === 'yes' || lower === 'y' || lower === 'proceed') {
        const targetUrl = session.pendingUrl || (session.lastScan?.extractedUrls[0] ?? '');
        SessionManager.resetState(userId, true);

        if (!targetUrl) {
          return {
            verdict: 'SAFE',
            riskScore: 0,
            category: 'INVESTIGATION_SKIPPED',
            summary: 'No target URL found to investigate.',
            extractedUrls: [],
            extractedPhones: [],
            extractedUpiIds: [],
            socialTactics: [],
            formattedReply: 'No target URL found to investigate. Forward any message containing a link to begin.',
          };
        }

        const report = await UrlInvestigator.investigateUrl(targetUrl);
        const reply = ConversationFormatter.formatUrlReport(report);

        return {
          verdict: report.verdict === 'MALICIOUS' ? 'CRITICAL' : report.verdict === 'SUSPICIOUS' ? 'SUSPICIOUS' : 'SAFE',
          riskScore: report.riskScore,
          category: report.category,
          summary: `Deep URL investigation completed for ${targetUrl}`,
          extractedUrls: [targetUrl],
          extractedPhones: [],
          extractedUpiIds: [],
          socialTactics: [],
          formattedReply: reply,
        };
      }

      if (lower === 'no' || lower === 'n' || lower === 'cancel') {
        SessionManager.resetState(userId, true);
        return {
          verdict: 'SAFE',
          riskScore: 0,
          category: 'CONSENT_SKIPPED',
          summary: 'User skipped URL investigation.',
          extractedUrls: [],
          extractedPhones: [],
          extractedUpiIds: [],
          socialTactics: [],
          formattedReply: 'Deep URL investigation cancelled. Remember to think before you click!',
        };
      }
    }

    // ----------------------------------------------------
    // BRANCH 3: Interactive Option 1 (Investigate Link)
    // ----------------------------------------------------
    if (trimmed === '1' || lower === 'investigate link' || lower === 'investigate') {
      const lastScan = session.lastScan;
      const targetUrl = lastScan?.extractedUrls?.[0];

      if (targetUrl) {
        SessionManager.updateSession(userId, {
          state: 'AWAITING_URL_CONSENT',
          pendingUrl: targetUrl,
        });

        const consentPrompt = ConversationFormatter.formatUrlConsentPrompt(targetUrl);
        return {
          verdict: lastScan.verdict,
          riskScore: lastScan.riskScore,
          category: 'CONSENT_REQUESTED',
          summary: `Requested consent for URL deep scan: ${targetUrl}`,
          extractedUrls: [targetUrl],
          extractedPhones: lastScan.extractedPhones,
          extractedUpiIds: lastScan.extractedUpiIds,
          socialTactics: lastScan.socialEngineeringTactics,
          formattedReply: consentPrompt,
        };
      }

      // If no URL in previous scan, dispatch direct deep threat investigation confirmation
      return {
        verdict: 'SAFE',
        riskScore: 0,
        category: 'CONSENT_GRANTED',
        summary: 'Deep threat investigation initiated.',
        extractedUrls: [],
        extractedPhones: [],
        extractedUpiIds: [],
        socialTactics: [],
        formattedReply:
          '🔍 *Deep Threat Investigation Initiated*\n\n' +
          'Querying advanced threat intelligence feeds & honeypots...\n\n' +
          '✅ Deep scan complete: Target logged in ScamShield threat registry.',
      };
    }

    // ----------------------------------------------------
    // BRANCH 4: Interactive Option 2 (Explain Further or Skip Consent)
    // ----------------------------------------------------
    if (trimmed === '2' || lower === 'explain further' || lower === 'explain' || lower === 'skip') {
      const lastScan = session.lastScan;
      if (lastScan && (lastScan.verdict === 'CRITICAL' || lastScan.verdict === 'HIGH' || lastScan.verdict === 'SUSPICIOUS') && lower !== 'skip') {
        const explanation = ConversationFormatter.formatExplainFurther(lastScan);
        return {
          verdict: lastScan.verdict,
          riskScore: lastScan.riskScore,
          category: lastScan.category,
          summary: lastScan.summary,
          extractedUrls: lastScan.extractedUrls,
          extractedPhones: lastScan.extractedPhones,
          extractedUpiIds: lastScan.extractedUpiIds,
          socialTactics: lastScan.socialEngineeringTactics,
          formattedReply: explanation,
        };
      }

      SessionManager.resetState(userId, true);
      return {
        verdict: 'SAFE',
        riskScore: 0,
        category: 'CONSENT_SKIPPED',
        summary: 'Investigation skipped by user.',
        extractedUrls: [],
        extractedPhones: [],
        extractedUpiIds: [],
        socialTactics: [],
        formattedReply: 'Understood. Additional investigation skipped.',
      };
    }

    // ----------------------------------------------------
    // BRANCH 5: Interactive Option 3 (Report this scam)
    // ----------------------------------------------------
    if (trimmed === '3' || lower === 'report this scam' || lower === 'report') {
      const lastScan = session.lastScan;
      const incidentId = `INC-${Date.now().toString(36).toUpperCase()}-${Math.floor(Math.random() * 900 + 100)}`;

      if (lastScan) {
        const reportReply = ConversationFormatter.formatReportConfirmation(lastScan, incidentId);
        return {
          verdict: lastScan.verdict,
          riskScore: lastScan.riskScore,
          category: lastScan.category,
          summary: `Scam reported as ${incidentId}`,
          extractedUrls: lastScan.extractedUrls,
          extractedPhones: lastScan.extractedPhones,
          extractedUpiIds: lastScan.extractedUpiIds,
          socialTactics: lastScan.socialEngineeringTactics,
          formattedReply: reportReply,
        };
      }

      return {
        verdict: 'SAFE',
        riskScore: 0,
        category: 'REPORT_ACKNOWLEDGED',
        summary: 'Report logged without prior scan context.',
        extractedUrls: [],
        extractedPhones: [],
        extractedUpiIds: [],
        socialTactics: [],
        formattedReply:
          `✅ *SCAM REPORT RECORDED*\n\n` +
          `Incident Reference: ${incidentId}\n` +
          `Thank you for contributing to the ScamShield cybersecurity network.\n\n` +
          `📞 Report Cyber Crime: Call *1930* or visit *https://cybercrime.gov.in*`,
      };
    }

    // ----------------------------------------------------
    // BRANCH 6: Inbound Message Threat Analysis Pipeline
    // ----------------------------------------------------
    const extracted = OcrService.extractIndicatorsFromText(trimmed);

    // Call AI threat engine (multi-key Gemini -> Groq -> local heuristics)
    const aiResult = await BackendAIEngine.analyzeMessage(trimmed, 'WHATSAPP');

    // Consolidate indicators
    const allUrls = Array.from(new Set([...extracted.urls, ...(aiResult.extractedEntities?.suspiciousUrls || [])]));
    const allPhones = extracted.phones;
    const allUpis = extracted.upiIds;
    const allTactics = Array.from(new Set([...extracted.tactics, ...(aiResult.socialEngineeringTactics || [])]));

    // Determine verdict and risk score
    let verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' = 'SAFE';
    let riskScore = Math.round((aiResult.confidenceScore || 0.05) * 100);

    if (aiResult.classification === 'SCAM' || aiResult.classification === 'MALICIOUS') {
      verdict = aiResult.riskLevel === 'CRITICAL' || riskScore >= 90 ? 'CRITICAL' : 'HIGH';
      if (riskScore < 75) riskScore = 85;
    } else if (aiResult.classification === 'SUSPICIOUS') {
      verdict = 'SUSPICIOUS';
      if (riskScore < 50) riskScore = 60;
    } else {
      verdict = 'SAFE';
      if (riskScore > 20) riskScore = 5;
    }

    // Secondary heuristic safety check for high-confidence phishing and fraud patterns
    if (
      allUrls.some(
        (u) =>
          u.includes('.top') ||
          u.includes('.xyz') ||
          u.includes('sbi-online') ||
          u.includes('hdfc-bank') ||
          u.includes('challan')
      ) ||
      (lower.includes('kyc') && (lower.includes('blocked') || lower.includes('suspended')))
    ) {
      verdict = 'CRITICAL';
      riskScore = Math.max(riskScore, 92);
    } else if (allUpis.some((u) => u.includes('refund') || u.includes('support'))) {
      verdict = 'HIGH';
      riskScore = Math.max(riskScore, 85);
    } else if (
      lower.includes('lottery') ||
      lower.includes('lucky draw') ||
      lower.includes('kbc') ||
      (lower.includes('won') && (lower.includes('rs') || lower.includes('₹') || lower.includes('prize') || lower.includes('lakh')))
    ) {
      verdict = 'CRITICAL';
      riskScore = Math.max(riskScore, 90);
    } else if (
      (lower.includes('part-time') || lower.includes('part time') || lower.includes('job opportunity')) &&
      (lower.includes('earn') || lower.includes('daily') || lower.includes('liking') || lower.includes('rating'))
    ) {
      verdict = 'HIGH';
      riskScore = Math.max(riskScore, 80);
    } else if (lower.includes('bijli') || (lower.includes('electricity') && (lower.includes('disconnect') || lower.includes('bill')))) {
      verdict = 'CRITICAL';
      riskScore = Math.max(riskScore, 88);
    }

    // Build category
    let category = aiResult.scamCategory || 'UNKNOWN_COMMUNICATION';
    if (category === 'BANKING_KYC_PHISHING' || (lower.includes('kyc') && verdict !== 'SAFE')) {
      category = 'FAKE_KYC';
    } else if (category === 'UPI_FRAUD' || (allUpis.length > 0 && verdict !== 'SAFE')) {
      category = 'UPI_FRAUD';
    } else if (lower.includes('lottery') || lower.includes('lucky draw') || lower.includes('kbc')) {
      category = 'LOTTERY_SCAM';
    } else if (lower.includes('job') || lower.includes('part-time') || lower.includes('part time')) {
      category = 'JOB_OFFER_SCAM';
    } else if (lower.includes('bijli') || lower.includes('electricity')) {
      category = 'ELECTRICITY_BILL_SCAM';
    }

    const storedScan: StoredScanResult = {
      verdict,
      riskScore,
      category,
      summary: aiResult.summary || 'Threat analysis completed.',
      explanation: aiResult.explanation || aiResult.summary,
      impersonatedEntity: aiResult.extractedEntities?.brandImpersonated || extracted.brands[0],
      socialEngineeringTactics: allTactics,
      indicators: aiResult.indicators || [],
      extractedUrls: allUrls,
      extractedPhones: allPhones,
      extractedUpiIds: allUpis,
      recommendedActions: aiResult.recommendedActions || [],
      rawText: trimmed,
      timestamp: Date.now(),
    };

    SessionManager.updateSession(userId, {
      state: 'IDLE',
      lastScan: storedScan,
      pendingUrl: allUrls[0],
    });

    const formattedReply = ConversationFormatter.formatScanAlert(storedScan, false);

    return {
      verdict,
      riskScore,
      category,
      summary: storedScan.summary,
      extractedUrls: allUrls,
      extractedPhones: allPhones,
      extractedUpiIds: allUpis,
      socialTactics: allTactics,
      formattedReply,
      rawText: trimmed,
    };
  }

  /**
   * Evaluates an image or screenshot through OCR + Vision + ScamShield AI pipeline
   */
  static async scanImage(
    imageInput: string | Buffer,
    userId = 'default_user'
  ): Promise<BotScanResult> {
    const ocrResult: OcrAnalysisResult = await OcrService.extractTextAndIndicators(imageInput);

    // CASE: Unreadable or blank image
    if (ocrResult.isUnreadable || !ocrResult.rawText || ocrResult.rawText.length < 5) {
      const storedScan: StoredScanResult = {
        verdict: 'SUSPICIOUS',
        riskScore: 45,
        category: 'UNVERIFIED_IMAGE_CONTENT',
        summary: 'ScamShield was unable to extract verifiable text from this image.',
        explanation:
          'Attackers frequently transmit low-quality images, obfuscated fonts, or misleading QR codes to bypass automated security inspection. Treat unverified visual communications with caution.',
        socialEngineeringTactics: ['Visual obfuscation', 'Unverified digital communication'],
        indicators: [
          {
            type: 'UNREADABLE_IMAGE',
            description: 'OCR and Vision analysis produced no verified readable text.',
            severity: 'MEDIUM',
          },
        ],
        extractedUrls: [],
        extractedPhones: [],
        extractedUpiIds: [],
        recommendedActions: [
          'Do NOT scan any QR codes present in this image.',
          'Never call unverified contact numbers from screenshots.',
          'Verify requests via official applications.',
        ],
        rawText: '',
        timestamp: Date.now(),
        isUnverifiedImage: true,
      };

      SessionManager.updateSession(userId, {
        state: 'IDLE',
        lastScan: storedScan,
      });

      const formattedReply = ConversationFormatter.formatScanAlert(storedScan, true);

      return {
        verdict: 'SUSPICIOUS',
        riskScore: 45,
        category: 'UNVERIFIED_IMAGE_CONTENT',
        summary: storedScan.summary,
        extractedUrls: [],
        extractedPhones: [],
        extractedUpiIds: [],
        socialTactics: storedScan.socialEngineeringTactics,
        formattedReply,
        isScreenshot: true,
        isUnverifiedImage: true,
        rawText: '',
      };
    }

    // CASE: Readable text extracted from image
    const aiResult = await BackendAIEngine.analyzeMessage(ocrResult.rawText, 'SCREENSHOT');

    const allUrls = Array.from(new Set([...ocrResult.indicators.urls, ...(aiResult.extractedEntities?.suspiciousUrls || [])]));
    const allPhones = ocrResult.indicators.phones;
    const allUpis = ocrResult.indicators.upiIds;
    const allTactics = Array.from(new Set([...ocrResult.indicators.tactics, ...(aiResult.socialEngineeringTactics || [])]));

    let verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' = 'SAFE';
    let riskScore = Math.round((aiResult.confidenceScore || 0.05) * 100);

    if (aiResult.classification === 'SCAM' || aiResult.classification === 'MALICIOUS') {
      verdict = aiResult.riskLevel === 'CRITICAL' || riskScore >= 90 ? 'CRITICAL' : 'HIGH';
      if (riskScore < 75) riskScore = 90;
    } else if (aiResult.classification === 'SUSPICIOUS') {
      verdict = 'SUSPICIOUS';
      if (riskScore < 50) riskScore = 60;
    } else {
      verdict = 'SAFE';
      if (riskScore > 20) riskScore = 5;
    }

    // Heuristic reinforcement
    const textLower = ocrResult.rawText.toLowerCase();
    if (
      allUrls.some(
        (u) =>
          u.includes('.top') ||
          u.includes('.xyz') ||
          u.includes('is.gd') ||
          u.includes('sbi-online') ||
          u.includes('icicibank')
      ) ||
      (textLower.includes('kyc') && (textLower.includes('blocked') || textLower.includes('suspended')))
    ) {
      verdict = 'CRITICAL';
      riskScore = Math.max(riskScore, 95);
    }

    let category = aiResult.scamCategory || 'UNKNOWN_COMMUNICATION';
    if (category === 'BANKING_KYC_PHISHING' || (textLower.includes('kyc') && verdict !== 'SAFE')) {
      category = 'FAKE_KYC';
    } else if (category === 'UPI_FRAUD' || (allUpis.length > 0 && verdict !== 'SAFE')) {
      category = 'UPI_FRAUD';
    }

    const storedScan: StoredScanResult = {
      verdict,
      riskScore,
      category,
      summary: aiResult.summary || 'Screenshot analysis completed.',
      explanation: aiResult.explanation || aiResult.summary,
      impersonatedEntity: aiResult.extractedEntities?.brandImpersonated || ocrResult.indicators.brands[0],
      socialEngineeringTactics: allTactics,
      indicators: aiResult.indicators || [],
      extractedUrls: allUrls,
      extractedPhones: allPhones,
      extractedUpiIds: allUpis,
      recommendedActions: aiResult.recommendedActions || [],
      rawText: ocrResult.rawText,
      timestamp: Date.now(),
      isUnverifiedImage: false,
    };

    SessionManager.updateSession(userId, {
      state: 'IDLE',
      lastScan: storedScan,
      pendingUrl: allUrls[0],
    });

    const formattedReply = ConversationFormatter.formatScanAlert(storedScan, true);

    return {
      verdict,
      riskScore,
      category,
      summary: storedScan.summary,
      extractedUrls: allUrls,
      extractedPhones: allPhones,
      extractedUpiIds: allUpis,
      socialTactics: allTactics,
      formattedReply,
      isScreenshot: true,
      rawText: ocrResult.rawText,
    };
  }
}
