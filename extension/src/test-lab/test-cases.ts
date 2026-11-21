import { TestCase } from './types';

export const CONTROLLED_TEST_CASES: TestCase[] = [
  // 1. Legitimate Mainstream Websites (Tranco Anchors)
  {
    id: 'LEGIT_GOOGLE',
    title: 'Legitimate Mainstream — Google',
    categoryLabel: 'Legitimate Mainstream',
    targetUrl: 'https://google.com',
    description: 'Mainstream search engine verified against Tranco Top 100K high-trust anchor list.',
    expectedSeverity: 'SAFE',
    expectedCategory: 'LEGITIMATE',
    expectedSource: 'TRANCO_ANCHOR',
  },
  {
    id: 'LEGIT_GITHUB',
    title: 'Legitimate Mainstream — GitHub',
    categoryLabel: 'Legitimate Mainstream',
    targetUrl: 'https://github.com',
    description: 'Developer code hosting platform verified as trusted anchor.',
    expectedSeverity: 'SAFE',
    expectedCategory: 'LEGITIMATE',
    expectedSource: 'TRANCO_ANCHOR',
  },
  {
    id: 'LEGIT_MICROSOFT',
    title: 'Legitimate Mainstream — Microsoft',
    categoryLabel: 'Legitimate Mainstream',
    targetUrl: 'https://microsoft.com',
    description: 'Enterprise cloud and software provider verified as trusted anchor.',
    expectedSeverity: 'SAFE',
    expectedCategory: 'LEGITIMATE',
    expectedSource: 'TRANCO_ANCHOR',
  },
  {
    id: 'LEGIT_AMAZON_IN',
    title: 'Legitimate Mainstream — Amazon India',
    categoryLabel: 'Legitimate Mainstream',
    targetUrl: 'https://amazon.in',
    description: 'Major Indian consumer e-commerce portal verified as trusted anchor.',
    expectedSeverity: 'SAFE',
    expectedCategory: 'LEGITIMATE',
    expectedSource: 'TRANCO_ANCHOR',
  },

  // 2. Suspicious Brand-Impersonation Domains (Synthetic .example TLDs)
  {
    id: 'IMPERSONATION_SBI',
    title: 'Brand Impersonation — State Bank of India',
    categoryLabel: 'Brand Impersonation',
    targetUrl: 'https://sbi-online-kyc-verification.example',
    description: 'Synthetic .example domain mimicking State Bank of India (SBI NetBanking) via keyword hijacking.',
    expectedSeverity: ['CRITICAL', 'HIGH'],
    expectedCategory: 'PHISHING',
    expectedSource: 'HEURISTIC',
  },
  {
    id: 'IMPERSONATION_HDFC',
    title: 'Brand Impersonation — HDFC Bank',
    categoryLabel: 'Brand Impersonation',
    targetUrl: 'https://hdfc-bank-secure-login.example',
    description: 'Synthetic .example domain mimicking HDFC Bank NetBanking login gateway.',
    expectedSeverity: ['CRITICAL', 'HIGH'],
    expectedCategory: 'PHISHING',
    expectedSource: 'HEURISTIC',
  },
  {
    id: 'IMPERSONATION_PHONEPE',
    title: 'Brand Impersonation — PhonePe Payment',
    categoryLabel: 'Brand Impersonation',
    targetUrl: 'https://phonepe-account-verify.example',
    description: 'Synthetic .example domain mimicking PhonePe reward or account verification portal.',
    expectedSeverity: ['CRITICAL', 'HIGH'],
    expectedCategory: 'PHISHING',
    expectedSource: 'HEURISTIC',
  },

  // 3. Known Threat Simulation (Offline Threat Fixture)
  {
    id: 'MALICIOUS_OFFLINE_KYC',
    title: 'Known Threat Simulation — Verified Phishing Fixture',
    categoryLabel: 'Known Threat Fixture',
    targetUrl: 'https://sbi-online-kyc-verification.top',
    description: 'Confirmed high-confidence malicious domain present in local threat intelligence blocklist.',
    expectedSeverity: 'CRITICAL',
    expectedCategory: 'FAKE_KYC',
    expectedSource: 'OFFLINE_RULE',
  },

  // 4. Suspicious Deceptive Redirect Chain Simulation
  {
    id: 'SIMULATED_REDIRECT_CHAIN',
    title: 'Deceptive Redirect Chain Simulation',
    categoryLabel: 'Redirect Chain',
    targetUrl: 'https://shortener.example/promo',
    description: 'Simulated 3-hop redirect bouncing from a URL shortener through an affiliate tracker into a known phishing site.',
    expectedSeverity: ['CRITICAL', 'HIGH', 'SUSPICIOUS'],
    expectedCategory: ['FAKE_KYC', 'PHISHING', 'DECEPTIVE_REDIRECT'],
    isRedirectSimulation: true,
    simulationHops: [
      'https://shortener.example/promo',
      'https://affiliate-tracker.example/click?id=99',
      'https://sbi-online-kyc-verification.top',
    ],
  },

  // 5. Invalid / Malformed Input Safety Fixture
  {
    id: 'INVALID_URL_SAFETY',
    title: 'Input Safety — Malformed URL Handling',
    categoryLabel: 'Input Resilience',
    targetUrl: 'not a valid url %%%',
    description: 'Malformed string input to verify the scanner fails gracefully without crashing or throwing unhandled errors.',
    expectedSeverity: ['SAFE', 'UNKNOWN'],
    expectedCategory: ['LEGITIMATE', 'UNKNOWN'],
  },
];
