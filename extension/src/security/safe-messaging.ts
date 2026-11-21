import { BaseExtensionMessage, ExtensionActionType } from '../types/messages';

export class SafeMessaging {
  /**
   * Send a strongly-typed message to the background service worker with timeout protection
   */
  static async sendToBackground<TResponse = unknown, TPayload = unknown>(
    type: ExtensionActionType,
    payload?: TPayload,
    timeoutMs = 6000
  ): Promise<TResponse> {
    const message: BaseExtensionMessage<TPayload> = {
      type,
      payload: payload as TPayload,
      timestamp: Date.now(),
    };

    return new Promise((resolve, reject) => {
      let resolved = false;

      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          reject(new Error(`Message timeout after ${timeoutMs}ms for action: ${type}`));
        }
      }, timeoutMs);

      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (resolved) return;
          resolved = true;
          clearTimeout(timer);

          const lastError = chrome.runtime.lastError;
          if (lastError) {
            reject(new Error(lastError.message || `Failed to communicate with service worker`));
            return;
          }

          resolve(response as TResponse);
        });
      } catch (err) {
        if (!resolved) {
          resolved = true;
          clearTimeout(timer);
          reject(err);
        }
      }
    });
  }

  /**
   * Verify sender context to reject untrusted cross-extension or external webpage messages
   */
  static isTrustedSender(sender: chrome.runtime.MessageSender): boolean {
    // 1. Must match our exact extension runtime ID
    if (!sender || sender.id !== chrome.runtime.id) {
      return false;
    }

    // 2. Sender must originate from extension context or legitimate tab
    const url = sender.url || '';
    const isExtensionPage = url.startsWith(`chrome-extension://${chrome.runtime.id}`);
    const isContentScriptInTab = Boolean(sender.tab && sender.tab.id);

    return isExtensionPage || isContentScriptInTab;
  }
}
