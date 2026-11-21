/**
 * ScamShield Gmail Web Security Guard
 * Scoped strictly to https://mail.google.com/*
 * Detects sender display name vs actual SMTP address mismatches & brand impersonation
 */

import { detectBrandImpersonation, extractRootDomain } from '../security/domain-normalizer';

const PILL_ID_ATTR = 'data-scamshield-pill';

function scanGmailHeaders(): void {
  // Gmail renders sender cards with class 'gD' or span with 'email' attribute
  const senderElements = document.querySelectorAll('span.gD, span[email]:not([' + PILL_ID_ATTR + '])');

  senderElements.forEach((el) => {
    // Avoid double injection
    if (el.getAttribute(PILL_ID_ATTR)) return;
    el.setAttribute(PILL_ID_ATTR, 'inspected');

    const displayName = (el.textContent || el.getAttribute('name') || '').trim();
    const emailAddress = (el.getAttribute('email') || '').toLowerCase().trim();

    if (!emailAddress || !emailAddress.includes('@')) return;

    const emailDomain = emailAddress.split('@')[1];
    const rootDomain = extractRootDomain(emailDomain);

    // Check if display name claims to be a sensitive brand
    const impersonation = detectBrandImpersonation(displayName);

    const pill = document.createElement('span');
    pill.style.display = 'inline-flex';
    pill.style.alignItems = 'center';
    pill.style.gap = '4px';
    pill.style.marginLeft = '8px';
    pill.style.padding = '2px 8px';
    pill.style.borderRadius = '9999px';
    pill.style.fontSize = '11px';
    pill.style.fontWeight = '600';
    pill.style.fontFamily = 'system-ui, sans-serif';
    pill.style.letterSpacing = '0.02em';

    if (impersonation.isImpersonating && impersonation.impersonatedBrand) {
      const isDomainAligned = impersonation.legitimateDomains?.some(
        (legit) => rootDomain === extractRootDomain(legit)
      );

      if (!isDomainAligned) {
        // High-Risk Impersonation detected!
        pill.style.backgroundColor = '#ef4444';
        pill.style.color = '#ffffff';
        pill.innerHTML = `🛡️ ScamShield: Fake ${impersonation.impersonatedBrand} Lure (${emailDomain})`;
        pill.title = `Warning: The sender claims to be ${impersonation.impersonatedBrand}, but the actual email domain is ${emailDomain}. Do NOT click links or share credentials!`;
        el.parentElement?.appendChild(pill);
        return;
      }
    }

    // Free webmail service alert for official claims
    const freeWebmailDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com'];
    if (freeWebmailDomains.includes(rootDomain) && impersonation.isImpersonating) {
      pill.style.backgroundColor = '#f59e0b';
      pill.style.color = '#000000';
      pill.innerHTML = `🛡️ ScamShield Warning: Bank claim from free webmail (${rootDomain})`;
      el.parentElement?.appendChild(pill);
    }
  });
}

// Observe Gmail DOM mutations when user clicks emails
const observer = new MutationObserver(() => {
  scanGmailHeaders();
});

observer.observe(document.body, {
  childList: true,
  subtree: true,
});

// Initial scan
setTimeout(scanGmailHeaders, 2000);
