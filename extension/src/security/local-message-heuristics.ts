/**
 * ScamShield — Local Message Heuristic Analysis Engine
 *
 * Provides offline, zero-latency heuristic threat analysis for SMS, WhatsApp, and email messages.
 * Acts as an uncompromising safety net when AI providers are unavailable, rate-limited,
 * or offline.
 *
 * Inspects for:
 * - Brand Impersonation (Banks, Telecom, Utilities, Government)
 * - Urgent coercion and account suspension threats
 * - KYC / Pan Card / Aadhaar lures
 * - Financial / Payment demands, OTP theft, UPI fraud
 * - Fake lotteries, cashback, and advance fee scams
 * - Suspicious URLs, shorteners, unverified domains
 * - Unofficial phone numbers and customer care lures
 */

import { StructuredScamAnalysis, ThreatIndicator } from '../ai/types';

export class LocalMessageHeuristics {
  private static readonly BANKING_BRANDS = [
    { name: 'SBI', regex: /\b(sbi|state\s*bank(\s*of\s*india)?|yono)\b/i },
    { name: 'HDFC', regex: /\b(hdfc(\s*bank)?)\b/i },
    { name: 'ICICI', regex: /\b(icici(\s*bank)?)\b/i },
    { name: 'Axis Bank', regex: /\b(axis(\s*bank)?)\b/i },
    { name: 'Punjab National Bank', regex: /\b(pnb|punjab\s*national\s*bank)\b/i },
    { name: 'Bank of Baroda', regex: /\b(bob|bank\s*of\s*baroda)\b/i },
    { name: 'Kotak Mahindra', regex: /\b(kotak(\s*mahindra)?)\b/i },
    { name: 'Paytm', regex: /\b(paytm(\s*payments?\s*bank)?)\b/i },
    { name: 'PhonePe', regex: /\b(phone\s*pe)\b/i },
    { name: 'Google Pay', regex: /\b(gpay|google\s*pay)\b/i },
  ];

  private static readonly UTILITY_BRANDS = [
    { name: 'Electricity Department', regex: /\b(electricity(\s*office|\s*bill|\s*power)?|bijli)\b/i },
    { name: 'BSNL / MTNL', regex: /\b(bsnl|mtnl)\b/i },
    { name: 'Jio', regex: /\b(jio|reliance\s*jio)\b/i },
    { name: 'Airtel', regex: /\b(airtel)\b/i },
  ];

  private static readonly KYC_PATTERNS = [
    /\b(kyc(\s*update|\s*verification|\s*document|\s*suspended|\s*expired|\s*pending)?)\b/i,
    /\b(pan(\s*card)?\s*(update|verify|blocked|link))\b/i,
    /\b(aadhaar\s*(update|link|suspended))\b/i,
    /\b(re-?kyc)\b/i,
    /\b(update\s*(your\s*)?(kyc|details|profile))\b/i,
  ];

  private static readonly URGENT_THREAT_PATTERNS = [
    /\b(urgent|immediately|turant|abhi|without\s*delay)\b/i,
    /\b(blocked(\s*today)?|block\s*your\s*account|account\s*will\s*be\s*blocked)\b/i,
    /\b(suspend(ed|sion)?|deactivat(ed|ion)?)\b/i,
    /\b(disconnect(ed|ion)?\s*(tonight|today|at\s*\d+))\b/i,
    /\b(within\s*(24|12|48)?\s*hours?)\b/i,
    /\b(penalty|legal\s*action|police|arrest|fir\s*registered)\b/i,
  ];

  private static readonly CREDENTIAL_OTP_PATTERNS = [
    /\b(otp|one\s*time\s*password)\b/i,
    /\b(upi\s*pin|atm\s*pin|secret\s*pin)\b/i,
    /\b(cvv|card\s*number|expiry\s*date)\b/i,
    /\b(netbanking\s*password|login\s*password)\b/i,
  ];

  private static readonly FINANCIAL_DEMAND_PATTERNS = [
    /\b(transfer\s*money|pay\s*now|send\s*(rs\.?|inr|₹))\b/i,
    /\b(processing\s*fee|registration\s*fee|advance\s*charge|refundable\s*deposit)\b/i,
    /\b(cashback|lottery|lucky\s*draw|won\s*(rs\.?|₹|\$)|cash\s*prize|prize|jeeta\s*hai)\b/i,
    /\b(claim\s*reward|claim\s*prize|gift\s*card)\b/i,
  ];

  private static readonly URL_REGEX = /(?:https?:\/\/|www\.)[^\s<>"'{}|\\^`[\]]+/gi;
  private static readonly PHONE_REGEX = /(?:\+91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}\b/g;
  private static readonly UPI_REGEX = /[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}/g;

  /**
   * Analyzes message using local threat signatures and heuristics
   */
  static analyze(
    messageText: string,
    _sourceType: 'SMS' | 'WHATSAPP' | 'EMAIL' | 'SOCIAL_MEDIA' | 'SCREENSHOT_OCR' | 'OTHER' = 'SMS',
    diagnostics?: any
  ): StructuredScamAnalysis {
    const text = messageText.trim();
    const indicators: ThreatIndicator[] = [];
    const tactics: string[] = [];

    // 1. Detect Brand Impersonation
    let impersonatedBrand: string | null = null;
    for (const b of [...this.BANKING_BRANDS, ...this.UTILITY_BRANDS]) {
      if (b.regex.test(text)) {
        impersonatedBrand = b.name;
        indicators.push({
          type: 'BRAND_IMPERSONATION',
          description: `Message impersonates official entity: ${b.name}`,
          severity: 'HIGH',
        });
        tactics.push('authority_impersonation');
        break;
      }
    }

    // 2. Detect KYC Lures
    let kycDetected = false;
    for (const p of this.KYC_PATTERNS) {
      if (p.test(text)) {
        kycDetected = true;
        indicators.push({
          type: 'KYC_FRAUD_LURE',
          description: 'Demands urgent KYC verification or documentation update',
          severity: 'HIGH',
        });
        tactics.push('compliance_lure');
        break;
      }
    }

    // 3. Detect Urgent Threats & Coercion
    let urgencyDetected = false;
    for (const p of this.URGENT_THREAT_PATTERNS) {
      if (p.test(text)) {
        urgencyDetected = true;
        indicators.push({
          type: 'COERCIVE_THREAT',
          description: 'Pressures recipient with immediate account blockage, disconnection, or suspension',
          severity: 'HIGH',
        });
        tactics.push('urgency');
        tactics.push('fear');
        break;
      }
    }

    // 4. Detect Credential / OTP Theft
    let otpDetected = false;
    for (const p of this.CREDENTIAL_OTP_PATTERNS) {
      if (p.test(text)) {
        otpDetected = true;
        indicators.push({
          type: 'CREDENTIAL_THEFT',
          description: 'Explicitly requests confidential OTP, UPI PIN, or bank credentials',
          severity: 'HIGH',
        });
        tactics.push('credential_harvesting');
        break;
      }
    }

    // 5. Detect Advance Fee / Lottery / Cashback
    let lotteryDetected = false;
    for (const p of this.FINANCIAL_DEMAND_PATTERNS) {
      if (p.test(text)) {
        lotteryDetected = true;
        indicators.push({
          type: 'FINANCIAL_LURE',
          description: 'Promises unrealistic cashback, lottery winnings, or requests advance processing fees',
          severity: 'MEDIUM',
        });
        tactics.push('greed_incentive');
        break;
      }
    }

    // 6. Extract URLs
    const rawUrls = text.match(this.URL_REGEX) || [];
    const suspiciousUrls: string[] = [];
    for (const u of rawUrls) {
      suspiciousUrls.push(u);
      indicators.push({
        type: 'SUSPICIOUS_URL',
        description: `Contains external unverified link: ${u}`,
        severity: 'HIGH',
      });
    }

    // 7. Extract Phone Numbers
    const phoneMatches = text.match(this.PHONE_REGEX) || [];
    const phoneNumbers = Array.from(new Set(phoneMatches));
    for (const p of phoneNumbers) {
      indicators.push({
        type: 'UNOFFICIAL_CONTACT',
        description: `Directs contact to non-bank mobile number: ${p}`,
        severity: 'MEDIUM',
      });
    }

    // 8. Extract UPI handles
    const upiMatches = text.match(this.UPI_REGEX) || [];
    const upiIds = Array.from(new Set(upiMatches));
    for (const upi of upiIds) {
      indicators.push({
        type: 'UNVERIFIED_UPI_ID',
        description: `Unverified UPI payment identifier: ${upi}`,
        severity: 'HIGH',
      });
    }

    // Calculate Risk Score & Classification
    let riskScore = 0;
    let classification: 'SAFE' | 'SUSPICIOUS' | 'SCAM' | 'MALICIOUS' = 'SAFE';
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW';
    let scamCategory = 'LEGITIMATE_COMMUNICATION';

    if (impersonatedBrand && (kycDetected || urgencyDetected)) {
      riskScore = 0.92;
      classification = 'SCAM';
      riskLevel = 'HIGH';
      scamCategory = 'BANKING_KYC_PHISHING';
    } else if (otpDetected) {
      riskScore = 0.95;
      classification = 'SCAM';
      riskLevel = 'CRITICAL';
      scamCategory = 'OTP_CREDENTIAL_THEFT';
    } else if (lotteryDetected && (suspiciousUrls.length > 0 || upiIds.length > 0)) {
      riskScore = 0.85;
      classification = 'SCAM';
      riskLevel = 'HIGH';
      scamCategory = 'UPI_LOTTERY_FRAUD';
    } else if (urgencyDetected && (suspiciousUrls.length > 0 || phoneNumbers.length > 0)) {
      riskScore = 0.75;
      classification = 'SUSPICIOUS';
      riskLevel = 'HIGH';
      scamCategory = 'URGENT_COERCION_PHISHING';
    } else if (suspiciousUrls.length > 0 || phoneNumbers.length > 0) {
      riskScore = 0.45;
      classification = 'SUSPICIOUS';
      riskLevel = 'MEDIUM';
      scamCategory = 'UNVERIFIED_LINK_COMMUNICATION';
    } else {
      // Clean / Legitimate
      riskScore = 0.05;
      classification = 'SAFE';
      riskLevel = 'LOW';
      scamCategory = 'LEGITIMATE_COMMUNICATION';
    }

    // Generate Evidence-Based Summary & Rationale
    let summary: string;
    let explanation: string;
    const actions: string[] = [];

    if (classification === 'SCAM' || classification === 'SUSPICIOUS') {
      const detectedPoints: string[] = [];
      if (impersonatedBrand) detectedPoints.push(`${impersonatedBrand} brand impersonation`);
      if (kycDetected) detectedPoints.push('KYC-related request');
      if (urgencyDetected) detectedPoints.push('Account suspension threat');
      if (suspiciousUrls.length > 0) detectedPoints.push('Suspicious URL');
      if (phoneNumbers.length > 0) detectedPoints.push('Unverified mobile contact');
      if (otpDetected) detectedPoints.push('Request for confidential OTP/PIN');

      summary = `AI ANALYSIS UNAVAILABLE. Provider requests failed or timed out. However, local security checks detected:\n• ${detectedPoints.join('\n• ')}\n\nLocal assessment: ${riskLevel === 'CRITICAL' ? 'CRITICAL RISK' : 'HIGH RISK'}.\n(This result is based on local heuristic analysis, not AI inference.)`;
      explanation = `The message exhibits prominent ${scamCategory.toLowerCase().replace(/_/g, ' ')} patterns. Legitimate organizations and banks never demand immediate KYC updates through SMS links or threaten immediate same-day account suspension via unofficial numbers.`;

      if (suspiciousUrls.length > 0) {
        actions.push(`Do NOT click on ${suspiciousUrls[0]}`);
      }
      if (phoneNumbers.length > 0) {
        actions.push(`Do NOT call the mobile number ${phoneNumbers[0]}`);
      }
      actions.push('Never share OTP, passwords, or UPI PIN under any circumstances.');
      actions.push('Report suspicious fraudulent messages to the National Cybercrime Portal (cybercrime.gov.in or call 1930).');
      if (impersonatedBrand) {
        actions.push(`Verify account standing directly through the official ${impersonatedBrand} app or official branch.`);
      }
    } else {
      summary = 'Local security analysis detected no obvious phishing indicators, brand impersonation lures, or coercive suspension threats.';
      explanation = 'The message text contains normal communication patterns without recognizable urgency, financial extortion, or malicious external links.';
      actions.push('Message appears standard, but always exercise caution before clicking unexpected external links.');
    }

    return {
      success: true,
      classification,
      riskLevel,
      confidenceScore: riskScore,
      scamCategory,
      summary,
      socialEngineeringTactics: Array.from(new Set(tactics)),
      indicators,
      extractedEntities: {
        brandImpersonated: impersonatedBrand || undefined,
        suspiciousUrls: suspiciousUrls.length > 0 ? suspiciousUrls : undefined,
        paymentRequests: upiIds.length > 0 ? upiIds : undefined,
        requestedActions: kycDetected
          ? ['Update KYC immediately', 'Click link to verify']
          : urgencyDetected
          ? ['Take urgent action']
          : undefined,
      },
      recommendedActions: actions,
      explanation,
      latencyMs: diagnostics?.latencyMs || 5,
      isLocalHeuristicFallback: true,
      aiStatus: 'FAILED',
      securityStatus: 'SUCCESS',
      diagnostics: diagnostics || {
        requestId: `local_${Date.now()}`,
        timestamp: new Date().toISOString(),
        backendReachable: false,
        finalAnalysisStatus: 'LOCAL_HEURISTIC_FALLBACK',
      },
    };
  }
}
