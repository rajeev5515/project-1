import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { decryptFile, encryptFile } from './crypto.ts';

/**
 * Encrypted blob store on the local filesystem.
 *
 * - Blobs live in <dataDir>/blobs, which is never mounted as a static route.
 *   The only way bytes leave this directory is BlobStore.read(), and the only
 *   callers of that are the download handlers, after authorizeDocument().
 * - Storage keys are 32 random hex characters generated here. They never come
 *   from user input and are never sent to clients, so there is no path
 *   traversal surface and nothing to guess.
 * - Blobs are AES-256-GCM encrypted with per-file keys (crypto.ts), so a copy
 *   of the disk or a backup is useless without TV_MASTER_KEY.
 */
const KEY_RE = /^[0-9a-f]{32}$/;

export class BlobStore {
  private readonly dir: string;
  private readonly kek: Buffer;

  constructor(dataDir: string, kek: Buffer) {
    this.dir = path.join(dataDir, 'blobs');
    this.kek = kek;
    fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 });
  }

  private pathFor(storageKey: string): string {
    if (!KEY_RE.test(storageKey)) throw new Error('invalid storage key');
    return path.join(this.dir, storageKey);
  }

  write(plaintext: Buffer): { storageKey: string; wrappedKey: string } {
    const storageKey = randomBytes(16).toString('hex');
    const { blob, wrappedKey } = encryptFile(this.kek, storageKey, plaintext);
    fs.writeFileSync(this.pathFor(storageKey), blob, { flag: 'wx', mode: 0o600 });
    return { storageKey, wrappedKey };
  }

  read(storageKey: string, wrappedKey: string): Buffer {
    const blob = fs.readFileSync(this.pathFor(storageKey));
    return decryptFile(this.kek, storageKey, wrappedKey, blob);
  }

  remove(storageKey: string): void {
    fs.rmSync(this.pathFor(storageKey), { force: true });
  }
}
