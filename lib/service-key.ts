// Service-key hashing + constant-time verification.
//
// The service key is a 32-byte (256-bit) random hex string. With that much
// entropy, a single round of SHA-256 is sufficient — no rainbow tables exist
// for the 2^256 key space, no salt needed. Same reasoning BetterAuth uses
// for opaque session tokens.
//
// We store the hash in customer's `flarelink_config` under SERVICE_KEY_HASH and
// compare new incoming keys against it constant-time.

const enc = new TextEncoder();

export async function hashServiceKey(key: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(key));
  return toHex(new Uint8Array(digest));
}

/** Constant-time string compare. Returns false on length mismatch immediately,
 *  then OR-accumulates byte diffs. Branchless past the early-out. */
export function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Generate a fresh service key. 32 bytes = 64 hex chars, prefixed with
 *  `flarelink_sk_` so leaked keys are easy to grep / GitGuardian-detect. */
export function generateServiceKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return 'flarelink_sk_' + toHex(bytes);
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}
