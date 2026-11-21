/**
 * ScamShield WhatsApp Bot — Resilient WhatsApp Client
 *
 * Implements:
 * - Meta WhatsApp Cloud API outbound messaging
 * - Meta Error 131031 ("Business account has been locked") detection & circuit breaking
 * - Permanent vs transient error differentiation
 * - Exponential backoff retry logic for transient errors (429, 5xx)
 * - Zero-retry policy for permanent errors (131031, 131030, 190)
 * - Mock / Demo simulation mode with explicit non-delivery tracking
 * - Full pipeline simulation support
 */

import { config } from './config.js';
import { providerManager } from './provider-state.js';
import { ScannerClient, BotScanResult } from './scanner-client.js';

export interface DeliveryResult {
  success: boolean;
  isSimulated: boolean;
  mode: 'demo' | 'mock' | 'cloud_api';
  status: 'DELIVERED' | 'SIMULATED_SUCCESS' | 'BLOCKED' | 'FAILED';
  recipient: string;
  messageId?: string;
  error?: string;
  errorCode?: number;
  httpStatus?: number;
  attempts: number;
}

export interface SimulationResult {
  sender: string;
  type: 'text' | 'image';
  scanResult: BotScanResult;
  formattedReply: string;
  deliveryResult: DeliveryResult;
  providerStatus: string;
}

export class WhatsAppClient {
  private static instance: WhatsAppClient;

  // Custom fetch function injected for testing
  private fetchFn: typeof fetch = globalThis.fetch;

  private constructor() {}

  public static getInstance(): WhatsAppClient {
    if (!WhatsAppClient.instance) {
      WhatsAppClient.instance = new WhatsAppClient();
    }
    return WhatsAppClient.instance;
  }

  /**
   * Allows injecting a custom fetch function (useful for deterministic mock testing)
   */
  public setFetchFn(fn: typeof fetch): void {
    this.fetchFn = fn;
  }

  public resetFetchFn(): void {
    this.fetchFn = globalThis.fetch;
  }

  /**
   * Identifies whether an error is permanent (no retries should be attempted)
   */
  public static isPermanentError(code?: number, message?: string): boolean {
    if (!code && !message) return false;

    // Meta Error 131031: Business account locked
    // Meta Error 131030: Payment issue
    // Meta Error 190: Invalid OAuth / expired token
    // Meta Error 100: Invalid parameter / template
    const permanentCodes = [131031, 131030, 190, 100];
    if (code && permanentCodes.includes(code)) {
      return true;
    }

    if (message) {
      const lower = message.toLowerCase();
      if (
        lower.includes('business account has been locked') ||
        lower.includes('business account locked') ||
        lower.includes('account has been locked') ||
        lower.includes('invalid oauth access token') ||
        lower.includes('payment issue')
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Identifies whether an error is transient (temporary rate limit or server error)
   */
  public static isTransientError(httpStatus: number, code?: number): boolean {
    if (httpStatus === 429) return true;
    if (httpStatus >= 500 && httpStatus <= 504) return true;
    if (code === 130429 || code === 131000) return true;
    return false;
  }

  /**
   * Sends a message to a recipient phone number, respecting provider blocked state,
   * mock/demo modes, and transient retry policies.
   */
  public async sendMessage(
    recipientPhone: string,
    messageText: string,
    options?: {
      forceSimulate?: boolean;
      maxRetries?: number;
      baseDelayMs?: number;
    }
  ): Promise<DeliveryResult> {
    const mode = config.mode;
    const maxRetries = options?.maxRetries ?? 3;
    const baseDelayMs = options?.baseDelayMs ?? 150;

    // -------------------------------------------------------------------------
    // 1. CIRCUIT BREAKER: If provider is BLOCKED, immediately halt outbound call
    // -------------------------------------------------------------------------
    if (providerManager.getIsBlocked()) {
      const blockReason = providerManager.getBlockReason() || 'WhatsApp Business Account Locked by Meta';
      const blockCode = providerManager.getBlockCode() || 131031;

      console.warn(`[WhatsAppClient] Delivery aborted for ${recipientPhone}: Provider is BLOCKED (${blockReason})`);
      providerManager.recordBlockedDrop(recipientPhone);

      return {
        success: false,
        isSimulated: false,
        mode,
        status: 'BLOCKED',
        recipient: recipientPhone,
        error: blockReason,
        errorCode: blockCode,
        attempts: 0,
      };
    }

    // -------------------------------------------------------------------------
    // 2. MOCK / DEMO SIMULATION MODE
    // -------------------------------------------------------------------------
    const isMockMode =
      mode === 'mock' ||
      mode === 'demo' ||
      options?.forceSimulate ||
      !config.accessToken ||
      !config.phoneNumberId;

    if (isMockMode) {
      const simulatedId = `mock-msg-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
      providerManager.recordSuccess(recipientPhone, simulatedId, true);

      console.log(`[WhatsAppClient] [SIMULATION] Message delivered to ${recipientPhone} (ID: ${simulatedId})`);

      return {
        success: true,
        isSimulated: true,
        mode,
        status: 'SIMULATED_SUCCESS',
        recipient: recipientPhone,
        messageId: simulatedId,
        attempts: 1,
      };
    }

    // -------------------------------------------------------------------------
    // 3. META WHATSAPP CLOUD API (mode === 'cloud_api')
    // -------------------------------------------------------------------------
    const url = `https://graph.facebook.com/v21.0/${config.phoneNumberId}/messages`;
    let attempts = 0;

    while (attempts < maxRetries) {
      attempts += 1;

      try {
        const response = await this.fetchFn(url, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${config.accessToken}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            messaging_product: 'whatsapp',
            to: recipientPhone,
            type: 'text',
            text: { body: messageText },
          }),
        });

        // 3a. Success
        if (response.ok) {
          const data: any = await response.json().catch(() => ({}));
          const messageId = data?.messages?.[0]?.id || `wamid.${Date.now()}`;
          providerManager.recordSuccess(recipientPhone, messageId, false);

          console.log(`[WhatsAppClient] Message delivered via Meta Cloud API to ${recipientPhone} (ID: ${messageId})`);
          return {
            success: true,
            isSimulated: false,
            mode: 'cloud_api',
            status: 'DELIVERED',
            recipient: recipientPhone,
            messageId,
            httpStatus: response.status,
            attempts,
          };
        }

        // 3b. Failure handling & error parsing
        const errorText = await response.text();
        let parsedCode: number | undefined;
        let parsedMessage: string = errorText;

        try {
          const parsedJson = JSON.parse(errorText);
          const metaError = parsedJson?.error || {};
          parsedCode = metaError.code;
          parsedMessage = metaError.message || errorText;
        } catch {
          // Keep raw text
        }

        // Check for Meta Error 131031 (Business account locked)
        if (parsedCode === 131031 || WhatsAppClient.isPermanentError(parsedCode, parsedMessage)) {
          const lockReason = `Meta WhatsApp Business Account Locked: ${parsedMessage} (Error ${parsedCode || 131031})`;
          providerManager.markBlocked(parsedCode || 131031, lockReason);

          console.error(`[WhatsAppClient] CRITICAL: Meta Business Account Locked! ${lockReason}`);

          // NEVER retry a locked account!
          return {
            success: false,
            isSimulated: false,
            mode: 'cloud_api',
            status: 'BLOCKED',
            recipient: recipientPhone,
            error: lockReason,
            errorCode: parsedCode || 131031,
            httpStatus: response.status,
            attempts,
          };
        }

        // Check for transient errors (429, 5xx)
        const isTransient = WhatsAppClient.isTransientError(response.status, parsedCode);
        if (isTransient && attempts < maxRetries) {
          providerManager.recordRetry();
          providerManager.recordError(parsedCode, parsedMessage, true, response.status);

          const delay = baseDelayMs * Math.pow(2, attempts - 1);
          console.warn(`[WhatsAppClient] Transient Meta API error (${response.status}/${parsedCode}). Retrying in ${delay}ms (attempt ${attempts}/${maxRetries})...`);
          await new Promise((resolve) => setTimeout(resolve, delay));
          continue;
        }

        // Non-transient or retries exhausted
        providerManager.recordError(parsedCode, parsedMessage, false, response.status);
        console.error(`[WhatsAppClient] Meta API delivery failed: ${response.status} - ${parsedMessage}`);

        return {
          success: false,
          isSimulated: false,
          mode: 'cloud_api',
          status: 'FAILED',
          recipient: recipientPhone,
          error: parsedMessage,
          errorCode: parsedCode,
          httpStatus: response.status,
          attempts,
        };
      } catch (networkErr: any) {
        // Network timeout / connection drop
        const errMsg = networkErr?.message || 'Network error connecting to Meta WhatsApp API';

        if (attempts < maxRetries) {
          providerManager.recordRetry();
          providerManager.recordError(undefined, errMsg, true);

          const delay = baseDelayMs * Math.pow(2, attempts - 1);
          console.warn(`[WhatsAppClient] Network error: ${errMsg}. Retrying in ${delay}ms (attempt ${attempts}/${maxRetries})...`);
          await new Promise((resolve) => setTimeout(resolve, delay));
          continue;
        }

        providerManager.recordError(undefined, errMsg, false);
        return {
          success: false,
          isSimulated: false,
          mode: 'cloud_api',
          status: 'FAILED',
          recipient: recipientPhone,
          error: errMsg,
          attempts,
        };
      }
    }

    return {
      success: false,
      isSimulated: false,
      mode: 'cloud_api',
      status: 'FAILED',
      recipient: recipientPhone,
      error: 'Max retries exhausted',
      attempts,
    };
  }

  /**
   * Executes a simulated inbound message and returns full pipeline trace
   */
  public async simulateInbound(input: {
    from?: string;
    text?: string;
    mediaUrl?: string;
    imageData?: string;
  }): Promise<SimulationResult> {
    const sender = input.from || 'test_user_sim';
    const isImage = Boolean(input.mediaUrl || input.imageData);

    providerManager.recordInbound(sender, isImage ? 'image' : 'text');

    let scanResult: BotScanResult;
    if (isImage) {
      const media = input.mediaUrl || input.imageData || '';
      scanResult = await ScannerClient.scanImage(media, sender);
    } else {
      const text = input.text || '';
      scanResult = await ScannerClient.scanMessage(text, sender);
    }

    // Attempt delivery (will route through mock if simulated or report blocked if blocked)
    const deliveryResult = await this.sendMessage(sender, scanResult.formattedReply, {
      forceSimulate: config.mode !== 'cloud_api' || providerManager.getIsBlocked(),
    });

    return {
      sender,
      type: isImage ? 'image' : 'text',
      scanResult,
      formattedReply: scanResult.formattedReply,
      deliveryResult,
      providerStatus: providerManager.getStatus(config.mode),
    };
  }
}

export const whatsAppClient = WhatsAppClient.getInstance();
