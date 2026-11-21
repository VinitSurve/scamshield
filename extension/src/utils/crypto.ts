/**
 * Cryptographic utilities using standard Web Crypto API (supported in MV3 Service Worker & Window)
 */

export async function sha256Hex(message: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(message.trim().toLowerCase());
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function get32BitPrefix(hash: string): string {
  // First 8 hex characters represent 32 bits (4 bytes * 8 bits)
  return hash.substring(0, 8).toLowerCase();
}

export function generateRandomId(prefix = 'id'): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `${prefix}_${hex}`;
}
