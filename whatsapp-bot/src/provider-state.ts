/**
 * ScamShield WhatsApp Bot — Provider State & Health Manager
 *
 * Manages provider health status, Meta WhatsApp Cloud API restrictions,
 * error code tracking (including Meta error 131031 "Business account locked"),
 * simulation modes, and delivery diagnostics.
 */

export type ProviderHealthStatus = 'HEALTHY' | 'DEGRADED' | 'BLOCKED' | 'MOCK_MODE';

export interface ProviderErrorRecord {
  timestamp: string;
  code?: number;
  message: string;
  transient: boolean;
  httpStatus?: number;
}

export interface InteractionRecord {
  timestamp: string;
  recipient: string;
  type: 'INBOUND' | 'OUTBOUND' | 'SIMULATED';
  messageId?: string;
  success: boolean;
}

export interface ProviderStats {
  totalReceived: number;
  totalSent: number;
  totalSimulated: number;
  totalErrors: number;
  totalBlockedDrops: number;
  totalRetries: number;
}

export interface ProviderStatusSummary {
  status: ProviderHealthStatus;
  mode: 'demo' | 'mock' | 'cloud_api';
  isBlocked: boolean;
  lockDetails: {
    isLocked: boolean;
    code: number | null;
    reason: string | null;
    lockedAt: string | null;
  };
  lastError: ProviderErrorRecord | null;
  lastInteraction: InteractionRecord | null;
  stats: ProviderStats;
  uptimeSeconds: number;
  serverTime: string;
}

export class WhatsAppProviderManager {
  private static instance: WhatsAppProviderManager;

  private status: ProviderHealthStatus = 'HEALTHY';
  private isBlocked: boolean = false;
  private blockReason: string | null = null;
  private blockCode: number | null = null;
  private blockedAt: string | null = null;
  private lastError: ProviderErrorRecord | null = null;
  private lastInteraction: InteractionRecord | null = null;
  private startTime: number = Date.now();

  private stats: ProviderStats = {
    totalReceived: 0,
    totalSent: 0,
    totalSimulated: 0,
    totalErrors: 0,
    totalBlockedDrops: 0,
    totalRetries: 0,
  };

  private constructor() {}

  public static getInstance(): WhatsAppProviderManager {
    if (!WhatsAppProviderManager.instance) {
      WhatsAppProviderManager.instance = new WhatsAppProviderManager();
    }
    return WhatsAppProviderManager.instance;
  }

  /**
   * Resets all provider state (for testing or administrative reset)
   */
  public reset(): void {
    this.status = 'HEALTHY';
    this.isBlocked = false;
    this.blockReason = null;
    this.blockCode = null;
    this.blockedAt = null;
    this.lastError = null;
    this.lastInteraction = null;
    this.stats = {
      totalReceived: 0,
      totalSent: 0,
      totalSimulated: 0,
      totalErrors: 0,
      totalBlockedDrops: 0,
      totalRetries: 0,
    };
  }

  /**
   * Marks provider as permanently blocked due to external restriction (e.g. Meta Error 131031)
   */
  public markBlocked(code: number, reason: string): void {
    this.isBlocked = true;
    this.blockCode = code;
    this.blockReason = reason;
    this.blockedAt = new Date().toISOString();
    this.status = 'BLOCKED';

    this.lastError = {
      timestamp: this.blockedAt,
      code,
      message: reason,
      transient: false,
    };

    console.warn(`[WhatsAppProviderManager] PROVIDER BLOCKED: Code ${code} - ${reason}`);
  }

  /**
   * Records an error event
   */
  public recordError(code: number | undefined, message: string, transient: boolean, httpStatus?: number): void {
    this.stats.totalErrors += 1;
    this.lastError = {
      timestamp: new Date().toISOString(),
      code,
      message,
      transient,
      httpStatus,
    };

    if (!this.isBlocked) {
      this.status = transient ? 'DEGRADED' : 'DEGRADED';
    }
  }

  /**
   * Records a retry attempt for transient errors
   */
  public recordRetry(): void {
    this.stats.totalRetries += 1;
  }

  /**
   * Records a dropped message attempt due to blocked provider status
   */
  public recordBlockedDrop(recipient: string): void {
    this.stats.totalBlockedDrops += 1;
    this.lastInteraction = {
      timestamp: new Date().toISOString(),
      recipient,
      type: 'OUTBOUND',
      success: false,
    };
  }

  /**
   * Records a successful outbound or simulated delivery
   */
  public recordSuccess(recipient: string, messageId: string, isSimulated: boolean): void {
    if (isSimulated) {
      this.stats.totalSimulated += 1;
    } else {
      this.stats.totalSent += 1;
    }

    this.lastInteraction = {
      timestamp: new Date().toISOString(),
      recipient,
      type: isSimulated ? 'SIMULATED' : 'OUTBOUND',
      messageId,
      success: true,
    };

    if (!this.isBlocked) {
      this.status = 'HEALTHY';
    }
  }

  /**
   * Records an inbound message event
   */
  public recordInbound(sender: string, _type: string): void {
    this.stats.totalReceived += 1;
    this.lastInteraction = {
      timestamp: new Date().toISOString(),
      recipient: sender,
      type: 'INBOUND',
      success: true,
    };
  }

  /**
   * Gets current provider status
   */
  public getStatus(mode: 'demo' | 'mock' | 'cloud_api'): ProviderHealthStatus {
    if (this.isBlocked) return 'BLOCKED';
    if (mode === 'mock' || mode === 'demo') return 'MOCK_MODE';
    return this.status;
  }

  /**
   * Returns a complete diagnostic summary for health checks and admin dashboards
   */
  public getStatusSummary(mode: 'demo' | 'mock' | 'cloud_api'): ProviderStatusSummary {
    const effectiveStatus = this.getStatus(mode);

    return {
      status: effectiveStatus,
      mode,
      isBlocked: this.isBlocked,
      lockDetails: {
        isLocked: this.isBlocked,
        code: this.blockCode,
        reason: this.blockReason,
        lockedAt: this.blockedAt,
      },
      lastError: this.lastError,
      lastInteraction: this.lastInteraction,
      stats: { ...this.stats },
      uptimeSeconds: Math.floor((Date.now() - this.startTime) / 1000),
      serverTime: new Date().toISOString(),
    };
  }

  public getIsBlocked(): boolean {
    return this.isBlocked;
  }

  public getBlockReason(): string | null {
    return this.blockReason;
  }

  public getBlockCode(): number | null {
    return this.blockCode;
  }
}

export const providerManager = WhatsAppProviderManager.getInstance();
