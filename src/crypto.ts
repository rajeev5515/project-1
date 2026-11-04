import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';

// ---------------------------------------------------------------- passwords
// scrypt with N=2^15, r=8, p=1 (OWASP minimum is N=2^17 for scrypt with p=1;
// we use 2^15 with maxmem raised so the free-tier host stays responsive, and
// accept that trade-off in THREATS.md). Format: scrypt$N$r$p$salt$hash
const SCRYPT_N = 1 << 15;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_MAXMEM = 64 * 1024 * 1024;

export function hashPassword(password: string): string {
  const salt = randomBytes(16);
  const hash = scryptSync(password.normalize('NFKC'), salt, 32, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
    maxmem: SCRYPT_MAXMEM,
  });
  return ['scrypt', SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.toString('base64'), hash.toString('base64')].join('$');
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split('$');
  if (parts.length !== 6 || parts[0] !== 'scrypt') return false;
  const [, n, r, p, saltB64, hashB64] = parts as [string, string, string, string, string, string];
  const expected = Buffer.from(hashB64, 'base64');
  const actual = scryptSync(password.normalize('NFKC'), Buffer.from(saltB64, 'base64'), expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
    maxmem: SCRYPT_MAXMEM,
  });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/**
 * A hash of a random password, computed once. Login for an unknown email
 * verifies against this so that "no such user" and "wrong password" take the
 * same time (no account enumeration by timing).
 */
export const DUMMY_PASSWORD_HASH = hashPassword(randomBytes(16).toString('hex'));

export function validatePasswordStrength(password: unknown): string | null {
  if (typeof password !== 'string') return 'Password is required';
  if (password.length < 12) return 'Password must be at least 12 characters';
  if (password.length > 256) return 'Password is too long';
  return null;
}

// ------------------------------------------------------------------ tokens
export function newToken(): string {
  return randomBytes(32).toString('base64url');
}

export function sha256Hex(data: string | Buffer): string {
  return createHash('sha256').update(data).digest('hex');
}

// --------------------------------------------------------- file encryption
// Envelope encryption: each file version gets a fresh random 256-bit data key
// (DEK). The file is encrypted with AES-256-GCM under the DEK; the DEK is
// itself encrypted ("wrapped") with the master key-encryption key (KEK) from
// the environment and stored in the database. Neither the blob on disk nor
// the database row alone is enough to read a file.
//
// Blob layout on disk: iv(12) | tag(16) | ciphertext
// Wrapped key layout (base64): iv(12) | tag(16) | encryptedDek(32)

function gcmEncrypt(key: Buffer, plaintext: Buffer, aad: Buffer): Buffer {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function gcmDecrypt(key: Buffer, blob: Buffer, aad: Buffer): Buffer {
  if (blob.length < 28) throw new Error('ciphertext too short');
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ct = blob.subarray(28);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

export interface EncryptedFile {
  blob: Buffer;
  wrappedKey: string;
}

/**
 * The storage key is bound in as additional authenticated data, so a blob
 * cannot be swapped for another version's blob on disk without decryption
 * failing.
 */
export function encryptFile(kek: Buffer, storageKey: string, plaintext: Buffer): EncryptedFile {
  const dek = randomBytes(32);
  const aad = Buffer.from(storageKey, 'utf8');
  const blob = gcmEncrypt(dek, plaintext, aad);
  const wrappedKey = gcmEncrypt(kek, dek, aad).toString('base64');
  dek.fill(0);
  return { blob, wrappedKey };
}

export function decryptFile(kek: Buffer, storageKey: string, wrappedKey: string, blob: Buffer): Buffer {
  const aad = Buffer.from(storageKey, 'utf8');
  const dek = gcmDecrypt(kek, Buffer.from(wrappedKey, 'base64'), aad);
  try {
    return gcmDecrypt(dek, blob, aad);
  } finally {
    dek.fill(0);
  }
}
