import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

// Passwords were removed in favour of emailed one-time codes (routes/auth.ts).
// The users.password_hash column is kept for schema compatibility and always
// holds '!', which no input can match.

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
