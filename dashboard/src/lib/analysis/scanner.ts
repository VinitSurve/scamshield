/**
 * ScamShield Unified Analysis Client & Engine
 *
 * Integrates with live ScamShield backend APIs (multi-key AI + Groq Vision + ML Models)
 * with robust local heuristic fallback.
 */

import { SafeDocumentParser, ExtractedDocumentContent } from './document-parser';

export interface AnalysisResult {
  riskScore: number;
  riskClassification: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  category: string;
  confidence: number;
  explanation: string;
  modelPrediction: string;
  extractedEntities: {
    urls: string[];
    domains: string[];
    phones: string[];
    upiIds: string[];
    emails: string[];
  };
  securityRecommendations: string[];
  socialTactics: string[];
  ocrText?: string;
  language: string;
  sourceType: string;
  analyzedAt: string;
}

export class ScamShieldScanner {
  private static backendUrl = process.env.SCAMSHIELD_BACKEND_URL || 'http://localhost:3001';

  /**
   * Scans a text message (SMS, WhatsApp, Telegram, Email body, etc.)
   */
  static async scanText(
    text: string,
    sourceType = 'MESSAGE',
    language = 'en'
  ): Promise<AnalysisResult> {
    const trimmed = (text || '').trim();
    if (!trimmed) {
      return this.emptyResult('EMPTY_INPUT');
    }

    // Try live ScamShield Backend API
    try {
      const response = await fetch(`${this.backendUrl}/api/v1/analyze/message`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messageText: trimmed,
          sourceType,
          userLanguage: language,
        }),
        signal: AbortSignal.timeout(4000),
      });

      if (response.ok) {
        const data = await response.json();
        return this.formatBackendResult(data, trimmed, sourceType, language);
      }
    } catch {
      // Backend offline or timeout -> Engage local deterministic engine
    }

    return this.localHeuristicAnalysis(trimmed, sourceType, language);
  }

  /**
   * Scans an isolated URL
   */
  static async scanUrl(url: string): Promise<AnalysisResult> {
    const trimmed = (url || '').trim();
    const cleanUrl = trimmed.startsWith('http') ? trimmed : `http://${trimmed}`;

    try {
      const response = await fetch(`${this.backendUrl}/api/v1/bot/investigate-url`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: cleanUrl }),
        signal: AbortSignal.timeout(4000),
      });

      if (response.ok) {
        const report = await response.json();
        const score = report.riskScore || 0;
        const verdict =
          report.verdict === 'MALICIOUS'
            ? 'CRITICAL'
            : report.verdict === 'SUSPICIOUS'
            ? 'SUSPICIOUS'
            : 'SAFE';

        return {
          riskScore: score,
          riskClassification: verdict,
          category: report.category || 'SUSPICIOUS_URL',
          confidence: score / 100,
          explanation: report.details?.join(' ') || 'URL risk assessment complete.',
          modelPrediction: verdict,
          extractedEntities: {
            urls: [cleanUrl],
            domains: [report.domain || ''],
            phones: [],
            upiIds: [],
            emails: [],
          },
          securityRecommendations: [
            verdict === 'SAFE'
              ? 'Domain verified in official directories. Always verify HTTPS is active.'
              : 'Do NOT open this link or submit any banking or personal credentials.',
            'Report suspected fraud websites to 1930 or cybercrime.gov.in',
          ],
          socialTactics: report.details || [],
          language: 'en',
          sourceType: 'URL',
          analyzedAt: new Date().toISOString(),
        };
      }
    } catch {
      // Fallback
    }

    return this.localHeuristicAnalysis(cleanUrl, 'URL', 'en');
  }

  /**
   * Scans an uploaded file (Image, PDF, DOCX, CSV, TXT)
   */
  static async scanDocument(
    buffer: Buffer,
    mimeType: string,
    filename: string
  ): Promise<AnalysisResult> {
    // 1. If it's an image, attempt Vision OCR via backend
    if (mimeType.startsWith('image/')) {
      const base64 = `data:${mimeType};base64,${buffer.toString('base64')}`;
      try {
        const response = await fetch(`${this.backendUrl}/api/v1/analyze/image-vision`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ imageDataUrl: base64 }),
          signal: AbortSignal.timeout(6000),
        });

        if (response.ok) {
          const ocrData = await response.json();
          const extractedText = ocrData.extractedText || '';
          const result = await this.scanText(extractedText, 'IMAGE_SCREENSHOT');
          result.ocrText = extractedText;
          return result;
        }
      } catch {
        // Fallback to text parser
      }
    }

    // 2. Safe Document Extraction
    const doc = await SafeDocumentParser.parseDocument(buffer, mimeType, filename);
    const result = await this.scanText(doc.text, `FILE_${mimeType.split('/')[1]?.toUpperCase()}`);
    result.extractedEntities.urls = Array.from(new Set([...result.extractedEntities.urls, ...doc.urls]));
    result.extractedEntities.phones = Array.from(new Set([...result.extractedEntities.phones, ...doc.phones]));
    result.extractedEntities.upiIds = Array.from(new Set([...result.extractedEntities.upiIds, ...doc.upiIds]));
    result.extractedEntities.emails = Array.from(new Set([...result.extractedEntities.emails, ...doc.emails]));

    if (doc.metadata.suspiciousJsDetected) {
      result.riskScore = Math.max(result.riskScore, 85);
      result.riskClassification = 'HIGH';
      result.socialTactics.push('Malicious PDF embedded JavaScript detected');
    }
    if (doc.metadata.vbaMacroDetected) {
      result.riskScore = Math.max(result.riskScore, 90);
      result.riskClassification = 'CRITICAL';
      result.socialTactics.push('Suspicious VBA Macro detected in DOCX structure');
    }

    return result;
  }

  /**
   * Local Deterministic Threat Engine (Rule & Indicator Extraction)
   */
  private static localHeuristicAnalysis(
    rawText: string,
    sourceType: string,
    language: string
  ): AnalysisResult {
    // Adversarial Normalization & De-obfuscation
    const normalized = rawText
      .replace(/[\u200B-\u200D\uFEFF]/g, '')
      .replace(/\b([A-Za-z])\s+([A-Za-z])\s+([A-Za-z])(?:\s+([A-Za-z]))*(?:\s+([A-Za-z]))*\b/g, (m) => m.replace(/\s+/g, ''))
      .replace(/\b([A-Za-z])[\._\-]+([A-Za-z])[\._\-]+([A-Za-z])\b/g, (m) => m.replace(/[\._\-]+/g, ''))
      .replace(/[\u0430]/g, 'a').replace(/[\u043E]/g, 'o').replace(/[\u0435]/g, 'e').replace(/[\u0440]/g, 'p')
      .replace(/urgnet/gi, 'urgent').replace(/verfiy/gi, 'verify').replace(/acount/gi, 'account').replace(/immedaitely/gi, 'immediately');

    const text = normalized;
    const lower = text.toLowerCase();
    let score = 5;
    let category = 'LEGITIMATE_COMMUNICATION';
    const tactics: string[] = [];

    // Extract Entities
    const urls = Array.from(new Set(text.match(/https?:\/\/[^\s<>\"'()]+/gi) || []));
    const phones = Array.from(new Set(text.match(/(?:\+91|0)?[-\s]?[6-9]\d{4}[-\s]?\d{5}/g) || []));
    const upiIds = Array.from(
      new Set(text.match(/[\w\.\-]+@(okhdfcbank|okaxis|oksbi|okicici|paytm|ybl|apl|upi|axl|ibl)/gi) || [])
    );
    const emails = Array.from(new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/gi) || []));
    const domains = urls.map((u) => {
      try {
        return new URL(u).hostname;
      } catch {
        return '';
      }
    }).filter(Boolean);

    // Rule 1: Bank KYC Scam
    if (
      (lower.includes('kyc') || lower.includes('pan') || lower.includes('aadhaar')) &&
      (lower.includes('suspend') || lower.includes('block') || lower.includes('deactivat') || lower.includes('freeze'))
    ) {
      score = Math.max(score, 95);
      category = 'BANKING_KYC';
      tactics.push('Account suspension threat', 'Urgency pressure', 'Impersonated Bank KYC');
    }

    // Rule 2: Electricity Disconnection Scam
    if (
      (lower.includes('electricity') || lower.includes('power') || lower.includes('bijli') || lower.includes('light bill') || lower.includes('msedcl') || lower.includes('bescom')) &&
      (lower.includes('disconnect') || lower.includes('kat diya') || lower.includes('band keli') || lower.includes('tonight'))
    ) {
      score = Math.max(score, 92);
      category = 'ELECTRICITY';
      tactics.push('Utility disconnection threat', 'Night cutoff panic trigger', 'Private contact helpline');
    }

    // Rule 3: Digital Arrest / Police Extortion
    if (
      (lower.includes('cbi') || lower.includes('police') || lower.includes('ed') || lower.includes('customs') || lower.includes('narcotics')) &&
      (lower.includes('arrest') || lower.includes('digital arrest') || lower.includes('video call') || lower.includes('warrant') || lower.includes('skype'))
    ) {
      score = Math.max(score, 98);
      category = 'DIGITAL_ARREST';
      tactics.push('Law enforcement impersonation', 'Digital arrest threat', 'Video call interrogation demand');
    }

    // Rule 4: Job Offer / Telegram Task
    if (
      (lower.includes('part time') || lower.includes('work from home') || lower.includes('daily earnings') || lower.includes('youtube video')) &&
      (lower.includes('telegram') || lower.includes('whatsapp') || lower.includes('payout') || lower.includes('salary'))
    ) {
      score = Math.max(score, 88);
      category = 'JOB_OFFER';
      tactics.push('Unrealistic daily wage promise', 'Prepaid task trap', 'Telegram redirection');
    }

    // Rule 5: UPI Collect Refund Fraud
    if (
      (lower.includes('refund') || lower.includes('cashback') || lower.includes('prize') || lower.includes('lottery')) &&
      (lower.includes('upi pin') || lower.includes('collect request') || lower.includes('enter pin'))
    ) {
      score = Math.max(score, 94);
      category = 'UPI_FRAUD';
      tactics.push('Reverse UPI collect trap', 'PIN entry to receive money deception');
    }

    // Rule 6: Phishing TLDs (.top, .xyz, .cc, is.gd, bit.ly)
    if (domains.some((d) => d.endsWith('.top') || d.endsWith('.xyz') || d.endsWith('.cc') || d.includes('is.gd'))) {
      score = Math.max(score, 90);
      if (category === 'LEGITIMATE_COMMUNICATION') category = 'PHISHING_URL';
      tactics.push('High-risk phishing top-level domain (.top / .xyz / shortener)');
    }

    // Determine Classification
    let classification: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' = 'SAFE';
    if (score >= 90) classification = 'CRITICAL';
    else if (score >= 70) classification = 'HIGH';
    else if (score >= 35) classification = 'SUSPICIOUS';

    return {
      riskScore: score,
      riskClassification: classification,
      category,
      confidence: score / 100,
      explanation:
        classification === 'SAFE'
          ? 'No obvious phishing indicators or coercive threats detected in content.'
          : `High-risk cyber threat signals detected matching ${category.replace(/_/g, ' ')} patterns.`,
      modelPrediction: classification,
      extractedEntities: { urls, domains, phones, upiIds, emails },
      securityRecommendations: this.getRecommendations(category, classification),
      socialTactics: tactics,
      language,
      sourceType,
      analyzedAt: new Date().toISOString(),
    };
  }

  private static formatBackendResult(
    data: any,
    _text: string,
    sourceType: string,
    language: string
  ): AnalysisResult {
    const score = Math.round((data.confidenceScore || 0.1) * 100);
    const classification =
      data.riskLevel === 'CRITICAL' || score >= 90
        ? 'CRITICAL'
        : data.riskLevel === 'HIGH' || score >= 70
        ? 'HIGH'
        : data.classification === 'SUSPICIOUS' || score >= 35
        ? 'SUSPICIOUS'
        : 'SAFE';

    const category = data.threatCategory || 'UNKNOWN_THREAT';
    const entities = data.extractedEntities || {};

    return {
      riskScore: score,
      riskClassification: classification,
      category,
      confidence: data.confidenceScore || score / 100,
      explanation: data.summary || 'Threat analysis complete.',
      modelPrediction: classification,
      extractedEntities: {
        urls: entities.suspiciousUrls || [],
        domains: (entities.suspiciousUrls || []).map((u: string) => {
          try {
            return new URL(u).hostname;
          } catch {
            return '';
          }
        }),
        phones: entities.contactNumbers || [],
        upiIds: entities.upiHandles || [],
        emails: [],
      },
      securityRecommendations: data.recommendations || this.getRecommendations(category, classification),
      socialTactics: data.socialEngineeringTactics || [],
      language,
      sourceType,
      analyzedAt: new Date().toISOString(),
    };
  }

  private static getRecommendations(
    category: string,
    verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL'
  ): string[] {
    if (verdict === 'SAFE') {
      return [
        'Always remain vigilant. Legitimate organizations never ask for passwords or PINs.',
        'Official banks never ask for KYC updates over SMS or WhatsApp links.',
      ];
    }

    const cat = category.toUpperCase();
    const list: string[] = [
      'Do NOT click or open any links.',
      'Do NOT share OTP, UPI PIN, passwords, or personal details.',
    ];

    if (cat.includes('KYC') || cat.includes('BANK')) {
      list.push('Official banks NEVER ask for KYC updates via SMS or WhatsApp links.');
    } else if (cat.includes('ELECTRICITY') || cat.includes('POWER')) {
      list.push('Power utilities NEVER cut electricity within hours via SMS or ask to call private numbers.');
    } else if (cat.includes('DIGITAL_ARREST') || cat.includes('POLICE') || cat.includes('CBI')) {
      list.push('Police, CBI, ED, and courts NEVER conduct interrogations or digital arrests on video calls.');
    } else if (cat.includes('UPI')) {
      list.push('Entering your UPI PIN DEDUCTS money. You NEVER need to enter a PIN to receive refunds.');
    }

    list.push('Report this incident to 1930 (National Cyber Crime Helpline) or https://cybercrime.gov.in');
    return list;
  }

  private static emptyResult(reason: string): AnalysisResult {
    return {
      riskScore: 0,
      riskClassification: 'SAFE',
      category: reason,
      confidence: 1.0,
      explanation: 'No content provided for analysis.',
      modelPrediction: 'SAFE',
      extractedEntities: { urls: [], domains: [], phones: [], upiIds: [], emails: [] },
      securityRecommendations: ['Provide message, link, or document to scan.'],
      socialTactics: [],
      language: 'en',
      sourceType: 'EMPTY',
      analyzedAt: new Date().toISOString(),
    };
  }
}
