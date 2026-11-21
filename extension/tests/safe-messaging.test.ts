import { describe, it, expect } from 'vitest';
import { SafeMessaging } from '../src/security/safe-messaging';

describe('Safe Messaging Security & Sender Verification', () => {
  it('validates sender originating from matching extension runtime ID', () => {
    const validSender = {
      id: chrome.runtime.id,
      url: `chrome-extension://${chrome.runtime.id}/popup.html`,
    } as chrome.runtime.MessageSender;

    expect(SafeMessaging.isTrustedSender(validSender)).toBe(true);
  });

  it('validates sender originating from content script in an active tab', () => {
    const validContentSender = {
      id: chrome.runtime.id,
      tab: { id: 101, url: 'https://example.com' } as chrome.tabs.Tab,
    } as chrome.runtime.MessageSender;

    expect(SafeMessaging.isTrustedSender(validContentSender)).toBe(true);
  });

  it('rejects messages originating from unauthorized external extensions or web pages', () => {
    const maliciousSender = {
      id: 'malicious-extension-id-attacking-us',
      url: 'https://evil-hacker.com',
    } as chrome.runtime.MessageSender;

    expect(SafeMessaging.isTrustedSender(maliciousSender)).toBe(false);
  });

  it('rejects messages with undefined or missing sender runtime ID', () => {
    const emptySender = {} as chrome.runtime.MessageSender;
    expect(SafeMessaging.isTrustedSender(emptySender)).toBe(false);
  });
});
