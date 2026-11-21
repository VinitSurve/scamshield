/**
 * ScamShield In-Browser Passive DOM Heuristic Scanner
 * PRIVACY GUARANTEE: This script NEVER records keystrokes, form input values, or passwords.
 * It only inspects element metadata to detect credential harvesting pages on unrated domains.
 */

import { SafeMessaging } from '../security/safe-messaging';
import { DomHeuristicReport } from '../types/threat';
import { isPunycode } from '../security/domain-normalizer';

const SUSPICIOUS_KEYWORDS = [
  'sbi',
  'onlinesbi',
  'hdfc',
  'icici',
  'axis bank',
  'paytm',
  'phonepe',
  'income tax',
  'echallan',
  'bijli bill',
  'electricity bill',
  'kyc update',
  'pan card link',
];

function analyzeDom(): DomHeuristicReport {
  const domain = window.location.hostname.toLowerCase();
  const url = window.location.href;

  // 1. Check for password input presence
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const hasPasswordField = passwordInputs.length > 0;

  // 2. Check for payment / OTP input markers by element attribute (NOT value)
  const allInputs = document.querySelectorAll('input');
  let hasCreditCardField = false;
  let hasOtpField = false;

  allInputs.forEach((input) => {
    const name = (input.name || '').toLowerCase();
    const id = (input.id || '').toLowerCase();
    const placeholder = (input.placeholder || '').toLowerCase();
    const combined = `${name} ${id} ${placeholder}`;

    if (combined.includes('cvv') || combined.includes('cardnumber') || combined.includes('card_num')) {
      hasCreditCardField = true;
    }
    if (combined.includes('otp') || combined.includes('one-time') || combined.includes('passcode')) {
      hasOtpField = true;
    }
  });

  // 3. Check for brand impersonation keywords in title or text headers
  const pageTitle = (document.title || '').toLowerCase();
  const headings = Array.from(document.querySelectorAll('h1, h2'))
    .map((h) => (h.textContent || '').toLowerCase())
    .join(' ');
  const combinedText = `${pageTitle} ${headings}`;

  const impersonationKeywordsFound = SUSPICIOUS_KEYWORDS.filter((keyword) =>
    combinedText.includes(keyword)
  );

  // 4. Check external form action
  let externalFormAction: string | undefined;
  const forms = document.querySelectorAll('form');
  forms.forEach((form) => {
    const action = form.getAttribute('action') || '';
    if (action.startsWith('http://') || action.startsWith('https://')) {
      try {
        const actionHost = new URL(action).hostname.toLowerCase();
        if (actionHost !== domain) {
          externalFormAction = actionHost;
        }
      } catch {
        // Ignore invalid URL
      }
    }
  });

  return {
    domain,
    url,
    hasPasswordField,
    hasCreditCardField,
    hasOtpField,
    formCount: forms.length,
    impersonationKeywordsFound,
    externalFormAction,
    hasPunycode: isPunycode(domain),
  };
}

// Execute analysis after document is idle
setTimeout(async () => {
  try {
    const report = analyzeDom();
    if (report.hasPasswordField || report.impersonationKeywordsFound.length > 0 || report.hasPunycode) {
      await SafeMessaging.sendToBackground('REPORT_PAGE_HEURISTICS', report);
    }
  } catch (err) {
    // Fail silently in content script
  }
}, 1200);
