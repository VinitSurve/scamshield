export type SupportedLanguage = 'en' | 'hi' | 'mr';

export interface UserSettings {
  protectionEnabled: boolean;
  blockMaliciousDomains: boolean;
  warnSuspiciousWebsites: boolean;
  enableRedirectProtection: boolean;
  enableGmailProtection: boolean;
  communityReportingEnabled: boolean;
  apiBaseUrl: string;
  demoMode: boolean;
  language: SupportedLanguage;
  whitelistedDomains: string[];
  telemetryConsent: boolean;
  enableDnrBlocking: boolean;
}

export const DEFAULT_SETTINGS: UserSettings = {
  protectionEnabled: true,
  blockMaliciousDomains: true,
  warnSuspiciousWebsites: true,
  enableRedirectProtection: true,
  enableGmailProtection: true,
  communityReportingEnabled: true,
  apiBaseUrl: 'https://api.scamshield.org',
  demoMode: false,
  language: 'en',
  whitelistedDomains: [],
  telemetryConsent: false,
  enableDnrBlocking: true,
};
