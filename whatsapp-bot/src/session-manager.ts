/**
 * ScamShield WhatsApp Bot Session Manager
 *
 * Tracks conversation state per user (phone number):
 * - Current conversation state (IDLE, AWAITING_URL_CONSENT, AWAITING_REPORT)
 * - Last scan threat details (for contextual '1', '2', '3' replies)
 * - Pending URLs awaiting isolated investigation consent
 * - Automatic session expiry (TTL cleanup)
 */

export interface StoredScanResult {
  verdict: 'SAFE' | 'SUSPICIOUS' | 'HIGH' | 'CRITICAL';
  riskScore: number;
  category: string;
  summary: string;
  explanation: string;
  impersonatedEntity?: string;
  socialEngineeringTactics: string[];
  indicators: Array<{
    type: string;
    description: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH';
  }>;
  extractedUrls: string[];
  extractedPhones: string[];
  extractedUpiIds: string[];
  recommendedActions: string[];
  rawText: string;
  timestamp: number;
  isUnverifiedImage?: boolean;
}

export interface UserSession {
  userId: string;
  state: 'IDLE' | 'AWAITING_URL_CONSENT' | 'AWAITING_REPORT';
  lastScan?: StoredScanResult;
  pendingUrl?: string;
  lastUpdated: number;
}

export class SessionManager {
  private static sessions = new Map<string, UserSession>();
  private static readonly SESSION_TTL_MS = 2 * 60 * 60 * 1000; // 2 hours

  /**
   * Retrieves or creates a session for the specified user ID
   */
  static getSession(userId: string): UserSession {
    this.cleanExpiredSessions();
    const existing = this.sessions.get(userId);
    if (existing) {
      existing.lastUpdated = Date.now();
      return existing;
    }

    const newSession: UserSession = {
      userId,
      state: 'IDLE',
      lastUpdated: Date.now(),
    };
    this.sessions.set(userId, newSession);
    return newSession;
  }

  /**
   * Updates an existing user session with partial data
   */
  static updateSession(userId: string, partial: Partial<UserSession>): UserSession {
    const session = this.getSession(userId);
    Object.assign(session, partial, { lastUpdated: Date.now() });
    this.sessions.set(userId, session);
    return session;
  }

  /**
   * Clears state back to IDLE while optionally keeping the last scan context
   */
  static resetState(userId: string, keepLastScan = true): void {
    const session = this.getSession(userId);
    session.state = 'IDLE';
    session.pendingUrl = undefined;
    if (!keepLastScan) {
      session.lastScan = undefined;
    }
    session.lastUpdated = Date.now();
    this.sessions.set(userId, session);
  }

  /**
   * Cleans sessions that have exceeded the TTL
   */
  private static cleanExpiredSessions(): void {
    const now = Date.now();
    for (const [userId, session] of this.sessions.entries()) {
      if (now - session.lastUpdated > this.SESSION_TTL_MS) {
        this.sessions.delete(userId);
      }
    }
  }

  /**
   * Clears all sessions (for unit testing)
   */
  static clearAll(): void {
    this.sessions.clear();
  }
}
