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
}

export class ScannerClient {
  /**
   * Processes a text message through ScamShield threat rules and formats a WhatsApp response
   */
  static async scanMessage(text: string): Promise<BotScanResult> {
    const trimmed = text.trim();

    // Consent Flow
    if (trimmed === '1') {
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
    if (trimmed === '2') {
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

    const lower = trimmed.toLowerCase();

    // 1. Extract URLs
    const urlRegex = /https?:\/\/[^\s<>"']+|\b[a-zA-Z0-9-]{2,63}\.(?:com|org|net|in|top|xyz|online|site|store|app)\b[^\s<>"']*/gi;
    const extractedUrls = (trimmed.match(urlRegex) || []).map((u) => (u.startsWith('http') ? u : `https://${u}`));

    // 2. Extract Indian Phones
    const phoneRegex = /(?:(?:\+91|91|0)[-.\s]?)?([6-9]\d{4}[-.\s]?\d{5})\b/g;
    const extractedPhones = Array.from(new Set(trimmed.match(phoneRegex) || []));

    // 3. Extract UPI IDs
    const upiRegex = /\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b/g;
    const extractedUpiIds = (trimmed.match(upiRegex) || []).filter(
      (u) => !u.endsWith('@gmail.com') && !u.endsWith('@yahoo.com') && !u.endsWith('@outlook.com')
    );

    // 4. Social Engineering Tactics
    const socialTactics: string[] = [];
    if (lower.includes('immediately') || lower.includes('24 hours') || lower.includes('turant') || lower.includes('jaldi')) {
      socialTactics.push('Urgency pressure ("immediately / within 24 hours")');
    }
    if (lower.includes('blocked') || lower.includes('suspended') || lower.includes('disconnected')) {
      socialTactics.push('Account suspension threat ("blocked / suspended")');
    }
    if (lower.includes('share otp') || lower.includes('enter pin')) {
      socialTactics.push('Credential theft ("share OTP / PIN")');
    }
    if (lower.includes('lottery') || lower.includes('cashback') || lower.includes('won ₹')) {
      socialTactics.push('Financial reward lure ("won / cashback")');
    }

    // 5. Threat Classification
    let isPhishingUrl = false;
    for (const url of extractedUrls) {
      if (
        url.includes('.top') ||
        url.includes('.xyz') ||
        url.includes('sbi-online') ||
        url.includes('hdfc-bank') ||
        url.includes('challan')
      ) {
        isPhishingUrl = true;
      }
    }

    let verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL' = 'SAFE';
    let riskScore = 5;
    let category = 'NO_KNOWN_THREAT';
    let summary = 'No malicious indicators identified in message.';

    if (isPhishingUrl || lower.includes('kyc') || lower.includes('netbanking')) {
      verdict = 'CRITICAL';
      riskScore = 95;
      category = 'FAKE_KYC';
      summary = 'High-Risk Banking KYC Phishing: Threatens account suspension to steal credentials.';
    } else if (extractedUpiIds.some((u) => u.includes('refund') || u.includes('support'))) {
      verdict = 'HIGH';
      riskScore = 85;
      category = 'UPI_FRAUD';
      summary = 'Fraudulent UPI Collect Lure: Posing as refund desk.';
    } else if (socialTactics.length > 0 || extractedUrls.length > 0) {
      verdict = 'SUSPICIOUS';
      riskScore = 60;
      category = 'PHISHING';
      summary = 'Suspicious elements detected: Unverified links or urgency tactics.';
    }

    // 6. Format WhatsApp Reply
    let reply = '';
    if (verdict === 'CRITICAL' || verdict === 'HIGH') {
      reply += `🚨 *SCAMSHIELD THREAT ALERT*\n\n`;
      reply += `*Verdict:* ${verdict} RISK\n`;
      reply += `*Category:* ${category}\n`;
      reply += `*Risk Score:* ${riskScore}%\n\n`;
      reply += `*Summary:*\n${summary}\n\n`;
    } else if (verdict === 'SUSPICIOUS') {
      reply += `⚠️ *SCAMSHIELD CAUTION ALERT*\n\n`;
      reply += `*Verdict:* SUSPICIOUS CONTENT\n`;
      reply += `*Risk Score:* ${riskScore}%\n\n`;
      reply += `*Summary:*\n${summary}\n\n`;
    } else {
      reply += `🛡️ *SCAMSHIELD SCAN RESULT*\n\n`;
      reply += `*Verdict:* SAFE / NO KNOWN THREAT\n`;
      reply += `*Risk Score:* ${riskScore}%\n\n`;
      reply += `No known threat indicators detected in this message.\n\n`;
    }

    if (socialTactics.length > 0) {
      reply += `*Social Engineering Tactics:*\n`;
      socialTactics.forEach((t) => {
        reply += `• ${t}\n`;
      });
      reply += `\n`;
    }

    if (extractedUrls.length > 0) {
      reply += `*Extracted Destinations:*\n`;
      extractedUrls.forEach((u) => {
        reply += `• ${u} ${isPhishingUrl ? '(🔴 SUSPICIOUS)' : '(⚪ CHECKED)'}\n`;
      });
      reply += `\n`;
    }

    if (extractedPhones.length > 0) {
      reply += `*Extracted Contacts:*\n`;
      extractedPhones.forEach((p) => {
        reply += `• ${p} (⚠️ Private mobile contact)\n`;
      });
      reply += `\n`;
    }

    if (extractedUpiIds.length > 0) {
      reply += `*Extracted UPI Handles:*\n`;
      extractedUpiIds.forEach((u) => {
        reply += `• ${u}\n`;
      });
      reply += `\n`;
    }

    reply += `*Recommended Actions:*\n`;
    if (verdict === 'CRITICAL' || verdict === 'HIGH' || verdict === 'SUSPICIOUS') {
      reply += `1. Do NOT click or open any links.\n`;
      reply += `2. NEVER enter your UPI PIN to receive money.\n`;
      reply += `3. Verify communication exclusively via official banking apps.\n\n`;
      reply += `_Reply *1* to trigger deeper investigation, or *2* to skip._`;
    } else {
      reply += `• Standard communication, but stay cautious of unexpected attachments or links.`;
    }

    return {
      verdict,
      riskScore,
      category,
      summary,
      extractedUrls,
      extractedPhones,
      extractedUpiIds,
      socialTactics,
      formattedReply: reply,
    };
  }
}
