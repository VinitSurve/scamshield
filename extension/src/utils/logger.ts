/**
 * Privacy-preserving, redacted logger
 */

const REDACT_PATTERNS = [
  /token=[^&\s]+/gi,
  /password=[^&\s]+/gi,
  /secret=[^&\s]+/gi,
  /auth=[^&\s]+/gi,
  /key=[^&\s]+/gi,
];

function sanitize(message: string): string {
  let cleaned = message;
  for (const pattern of REDACT_PATTERNS) {
    cleaned = cleaned.replace(pattern, '$1=[REDACTED]');
  }
  return cleaned;
}

export const logger = {
  debug: (...args: unknown[]) => {
    if ((import.meta as unknown as { env?: { DEV?: boolean } }).env?.DEV) {
      console.debug('[ScamShield]', ...args.map((a) => (typeof a === 'string' ? sanitize(a) : a)));
    }
  },
  info: (...args: unknown[]) => {
    console.info('[ScamShield]', ...args.map((a) => (typeof a === 'string' ? sanitize(a) : a)));
  },
  warn: (...args: unknown[]) => {
    console.warn('[ScamShield]', ...args.map((a) => (typeof a === 'string' ? sanitize(a) : a)));
  },
  error: (...args: unknown[]) => {
    console.error('[ScamShield]', ...args.map((a) => (typeof a === 'string' ? sanitize(a) : a)));
  },
};
