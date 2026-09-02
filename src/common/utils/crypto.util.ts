import * as crypto from 'crypto';

/**
 * Computes SHA-256 hash of string input
 */
export function cryptoHash(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}
