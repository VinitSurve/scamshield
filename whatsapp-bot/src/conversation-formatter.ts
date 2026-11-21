/**
 * ScamShield WhatsApp Bot Conversation Formatter
 *
 * Implements clean, professional, high-information-density WhatsApp response layouts:
 * - Threat Alert (High / Critical) with clear category, indicators, and recommended actions
 * - Caution Alert (Suspicious / Medium)
 * - Safe Advisory (Clean messages)
 * - Unverified Image warning (never falsely zero-risk)
 * - Deep URL investigation consent prompt and reports
 * - Detailed threat breakdowns ("Explain further")
 * - Scam reporting confirmations
 */

import { StoredScanResult } from './session-manager.js';
import { UrlInvestigationResult } from './url-investigator.js';

export class ConversationFormatter {
  /**
   * Formats initial greeting message
   */
  static formatGreeting(): string {
    return (
      `🛡️ *ScamShield Cyber Threat Assistant*\n` +
      `_Think Before You Click_\n\n` +
      `Forward or send me any suspicious communication to instantly check for cyber threats:\n\n` +
      `📩 *SMS or WhatsApp forwards*\n` +
      `📸 *Screenshots of messages or payment requests*\n` +
      `🔗 *Links and suspicious websites*\n` +
      `📞 *Phone numbers claiming to be bank helplines*\n` +
      `💸 *UPI IDs requesting refunds or payments*\n\n` +
      `_Send your message or screenshot now to start analysis._`
    );
  }

  /**
   * Formats primary threat analysis alert for incoming messages or screenshots
   */
  static formatScanAlert(scan: StoredScanResult, isScreenshot = false): string {
    const verdict = scan.verdict;
    const prefix = isScreenshot ? 'SCREENSHOT SCAN' : 'THREAT ANALYSIS';

    // CASE 1: Unverified Image / Unreadable Content
    if (scan.isUnverifiedImage) {
      return (
        `⚠️ *UNVERIFIED IMAGE / SCREENSHOT*\n` +
        `ScamShield ${prefix}\n\n` +
        `*Risk Level:* ${scan.riskScore}% (CAUTION)\n` +
        `*Category:* UNVERIFIED_IMAGE_CONTENT\n\n` +
        `*SUMMARY*\n` +
        `ScamShield was unable to extract verifiable text from this image. Fraudsters frequently use low-resolution images, hidden text, or deceptive QR codes to evade security filters.\n\n` +
        `*RECOMMENDED ACTIONS*\n` +
        `1. Do NOT scan any QR code in this image.\n` +
        `2. Do NOT click links or call numbers shown in unverified screenshots.\n` +
        `3. If this claims to be from a bank or utility, verify directly via their official application.\n\n` +
        `_Reply *3* to flag this image as suspicious in community reports._`
      );
    }

    // CASE 2: High or Critical Risk
    if (verdict === 'CRITICAL' || verdict === 'HIGH') {
      let msg = `🚨 *SCAMSHIELD THREAT ALERT — ${verdict} RISK*\n`;
      msg += `ScamShield ${prefix}\n\n`;
      msg += `*Category:* ${scan.category.replace(/_/g, ' ')}\n`;
      msg += `*Risk Level:* ${scan.riskScore}% (${verdict})\n`;

      if (scan.impersonatedEntity) {
        msg += `*Impersonated Entity:* ${scan.impersonatedEntity}\n`;
      }
      msg += `\n`;

      msg += `*WHY IT IS SUSPICIOUS*\n`;
      if (scan.socialEngineeringTactics.length > 0) {
        scan.socialEngineeringTactics.forEach((tactic) => {
          msg += `• ${tactic}\n`;
        });
      } else {
        msg += `• High-probability threat indicators matching known scam patterns.\n`;
        msg += `• Urges recipient to take immediate unverified financial or credentials action.\n`;
      }
      msg += `\n`;

      msg += `*INDICATORS DETECTED*\n`;
      if (scan.extractedUrls.length > 0) {
        scan.extractedUrls.forEach((url) => {
          msg += `• Suspicious Link: ${url} (Unverified)\n`;
        });
      }
      if (scan.extractedPhones.length > 0) {
        scan.extractedPhones.forEach((phone) => {
          msg += `• Contact Number: ${phone} (Private Mobile, Not Official Bank Desk)\n`;
        });
      }
      if (scan.extractedUpiIds.length > 0) {
        scan.extractedUpiIds.forEach((upi) => {
          msg += `• UPI Handle: ${upi} (Fraudulent Collect Target)\n`;
        });
      }
      msg += `• Threat Classification: ${scan.category.replace(/_/g, ' ')}\n\n`;

      msg += `*RECOMMENDED ACTIONS*\n`;
      msg += `1. Do NOT click or open any links.\n`;
      msg += `2. Do NOT share OTP, UPI PIN, or bank passwords.\n`;
      msg += `3. Official banks NEVER ask for KYC updates via SMS links.\n`;
      msg += `4. Report this communication to 1930 (National Cyber Crime Helpline).\n\n`;

      msg += `*Reply:*\n`;
      msg += `*1* - Investigate link safely (Reply *1* to trigger deeper investigation)\n`;
      msg += `*2* - Explain further\n`;
      msg += `*3* - Report this scam`;

      return msg;
    }

    // CASE 3: Suspicious / Medium Risk
    if (verdict === 'SUSPICIOUS') {
      let msg = `⚠️ *SCAMSHIELD CAUTION ALERT — SUSPICIOUS CONTENT*\n`;
      msg += `ScamShield ${prefix}\n\n`;
      msg += `*Risk Level:* ${scan.riskScore}% (SUSPICIOUS)\n`;
      msg += `*Category:* ${scan.category.replace(/_/g, ' ')}\n\n`;

      msg += `*WHY IT IS SUSPICIOUS*\n`;
      if (scan.socialEngineeringTactics.length > 0) {
        scan.socialEngineeringTactics.forEach((tactic) => {
          msg += `• ${tactic}\n`;
        });
      } else {
        msg += `• Unverified sender or unverified external link.\n`;
      }
      msg += `\n`;

      msg += `*INDICATORS DETECTED*\n`;
      if (scan.extractedUrls.length > 0) {
        scan.extractedUrls.forEach((url) => {
          msg += `• Link: ${url}\n`;
        });
      }
      if (scan.extractedPhones.length > 0) {
        scan.extractedPhones.forEach((phone) => {
          msg += `• Contact Number: ${phone}\n`;
        });
      }
      if (scan.extractedUpiIds.length > 0) {
        scan.extractedUpiIds.forEach((upi) => {
          msg += `• UPI Handle: ${upi}\n`;
        });
      }
      msg += `\n`;

      msg += `*RECOMMENDED ACTIONS*\n`;
      msg += `1. Exercise extreme caution before responding or interacting.\n`;
      msg += `2. Verify sender identity through official channels.\n`;
      msg += `3. Never send money or enter credentials on unverified websites.\n\n`;

      msg += `*Reply:*\n`;
      msg += `*1* - Investigate link safely (Reply *1* to trigger deeper investigation)\n`;
      msg += `*2* - Explain further\n`;
      msg += `*3* - Report this scam`;

      return msg;
    }

    // CASE 4: Safe / No Known Threat
    return (
      `🛡️ *SCAMSHIELD SCAN RESULT: SAFE / NO KNOWN THREAT*\n` +
      `ScamShield ${prefix}\n\n` +
      `*Risk Level:* ${scan.riskScore}% (SAFE)\n` +
      `*Category:* ${scan.category.replace(/_/g, ' ')}\n\n` +
      `*SUMMARY*\n` +
      `${scan.summary || 'Standard notification or message with no known malicious indicators detected.'}\n\n` +
      `*SAFETY ADVISORY*\n` +
      `Always remain vigilant. Legitimate organizations and banks will NEVER ask you to disclose passwords, OTPs, or enter your UPI PIN to receive money.`
    );
  }

  /**
   * Formats URL deep investigation consent prompt (Reply 1)
   */
  static formatUrlConsentPrompt(targetUrl: string): string {
    return (
      `⚠️ *URL DEEP INVESTIGATION*\n\n` +
      `Target URL:\n` +
      `${targetUrl}\n\n` +
      `ScamShield will perform passive DNS, TLS certificate inspection, domain age analysis, and redirect tracing in an isolated sandbox. We do not download executable files or submit forms.\n\n` +
      `Do you want to proceed?\n` +
      `Reply *YES* to proceed or *NO* to cancel.`
    );
  }

  /**
   * Formats URL investigation findings
   */
  static formatUrlReport(report: UrlInvestigationResult): string {
    let msg = `🔍 *URL INVESTIGATION REPORT*\n\n`;
    msg += `*Target:* ${report.originalUrl}\n`;
    if (report.isShortened || report.finalUrl !== report.originalUrl) {
      msg += `*Final Destination:* ${report.finalUrl}\n`;
    }
    msg += `*Domain:* ${report.domain}\n`;
    msg += `*Verdict:* ${report.verdict} (${report.riskScore}% Risk)\n`;
    msg += `*Category:* ${report.category.replace(/_/g, ' ')}\n\n`;

    msg += `*INVESTIGATION FINDINGS*\n`;
    report.details.forEach((d) => {
      msg += `• ${d}\n`;
    });
    msg += `\n`;

    msg += `*RECOMMENDATION*\n`;
    if (report.verdict === 'MALICIOUS') {
      msg += `🚨 BLOCK AND DO NOT OPEN. This link points to a confirmed phishing or malicious destination.`;
    } else if (report.verdict === 'SUSPICIOUS') {
      msg += `⚠️ CAUTION. The destination domain cannot be verified as legitimate. Avoid submitting passwords or card details.`;
    } else {
      msg += `✅ This domain is verified in trusted organization directories. Always ensure HTTPS is active.`;
    }

    return msg;
  }

  /**
   * Formats detailed threat breakdown ("2 - Explain further")
   */
  static formatExplainFurther(scan: StoredScanResult): string {
    let msg = `📘 *DETAILED THREAT BREAKDOWN*\n\n`;
    msg += `${scan.explanation || scan.summary}\n\n`;

    if (scan.socialEngineeringTactics.length > 0) {
      msg += `*Social Engineering Tactics Detected:*\n`;
      scan.socialEngineeringTactics.forEach((t) => {
        msg += `• ${t}\n`;
      });
      msg += `\n`;
    }

    msg += `*How Scammers Exploit This:*\n`;
    msg += `Attackers use psychological triggers (fear of account closure, sudden greed from lottery winnings, or panic from utility disconnections) to force victims into hurried decisions before they can consult trusted advisors.\n\n`;

    msg += `*Official Protective Resources:*\n`;
    msg += `• Indian Cybercrime Reporting: Call 1930\n`;
    msg += `• Portal: https://cybercrime.gov.in\n`;
    msg += `• RBI Sachet Portal: https://sachet.rbi.org.in`;

    return msg;
  }

  /**
   * Formats scam report confirmation ("3 - Report this scam")
   */
  static formatReportConfirmation(scan: StoredScanResult, incidentId: string): string {
    return (
      `✅ *SCAM REPORT RECORDED*\n\n` +
      `Thank you for helping protect the community!\n` +
      `This incident has been logged in the ScamShield community threat database and will protect other users.\n\n` +
      `*Report ID:* ${incidentId}\n` +
      `*Category:* ${scan.category.replace(/_/g, ' ')}\n` +
      `*Risk Score:* ${scan.riskScore}%\n\n` +
      `To file an official legal complaint with law enforcement authorities:\n` +
      `📞 National Cyber Crime Helpline: *1930*\n` +
      `🌐 Cybercrime Reporting Portal: *https://cybercrime.gov.in*`
    );
  }
}
