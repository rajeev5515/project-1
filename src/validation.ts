/**
 * Upload and input validation.
 *
 * Uploads are accepted only if BOTH the extension is on the allow-list AND the
 * file's leading bytes match that type. We never trust the client-supplied
 * Content-Type. Anything that could be rendered as active content by a
 * browser (HTML, SVG, XML, JS) is refused outright, and downloads are always
 * served as application/octet-stream attachments regardless (routes).
 */

export const CATEGORIES = ['HR', 'Legal', 'Finance', 'Engineering', 'Audit', 'Contracts', 'Other'] as const;
export type Category = (typeof CATEGORIES)[number];

interface FileType {
  ext: string[];
  mime: string;
  matches: (buf: Buffer) => boolean;
}

const startsWith = (buf: Buffer, sig: number[]) => buf.length >= sig.length && sig.every((b, i) => buf[i] === b);

function isZipOffice(buf: Buffer): boolean {
  // OOXML files are ZIP archives that contain [Content_Types].xml. We check the
  // local-file-header magic and that the name appears in the first entries.
  if (!startsWith(buf, [0x50, 0x4b, 0x03, 0x04])) return false;
  return buf.subarray(0, Math.min(buf.length, 4096)).includes('[Content_Types].xml');
}

function isPlainText(buf: Buffer): boolean {
  if (buf.includes(0)) return false;
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(buf);
  } catch {
    return false;
  }
  // Refuse text that a browser would sniff as markup, in case some client
  // ignores nosniff/attachment.
  const head = buf.subarray(0, 1024).toString('utf8').trimStart().toLowerCase();
  return !(head.startsWith('<') || head.includes('<script') || head.includes('<html') || head.includes('<svg'));
}

const TYPES: FileType[] = [
  { ext: ['pdf'], mime: 'application/pdf', matches: (b) => startsWith(b, [0x25, 0x50, 0x44, 0x46, 0x2d]) },
  { ext: ['png'], mime: 'image/png', matches: (b) => startsWith(b, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  { ext: ['jpg', 'jpeg'], mime: 'image/jpeg', matches: (b) => startsWith(b, [0xff, 0xd8, 0xff]) },
  {
    ext: ['docx'],
    mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    matches: isZipOffice,
  },
  {
    ext: ['xlsx'],
    mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    matches: isZipOffice,
  },
  {
    ext: ['pptx'],
    mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    matches: isZipOffice,
  },
  { ext: ['txt'], mime: 'text/plain', matches: isPlainText },
  { ext: ['csv'], mime: 'text/csv', matches: isPlainText },
];

export const ALLOWED_EXTENSIONS = TYPES.flatMap((t) => t.ext);

/**
 * Reduce a client-supplied filename to something safe to store and to put in
 * a Content-Disposition header: no directory parts, no control characters,
 * no quotes/backslashes, bounded length, NFC-normalised.
 */
export function sanitizeFilename(raw: string): string | null {
  let name = raw.normalize('NFC');
  name = name.split(/[\\/]/).pop() ?? '';
  // eslint-disable-next-line no-control-regex
  name = name.replace(/[\u0000-\u001f\u007f-\u009f"<>|:*?‪-‮⁦-⁩]/g, '');
  name = name.trim().replace(/^\.+/, '');
  if (name.length > 200) {
    const dot = name.lastIndexOf('.');
    const ext = dot > 0 ? name.slice(dot) : '';
    name = name.slice(0, 200 - ext.length) + ext;
  }
  if (!name || !name.includes('.')) return null;
  return name;
}

export type FileCheck = { ok: true; filename: string; mime: string } | { ok: false; error: string };

export function validateUpload(rawFilename: string, data: Buffer, maxBytes: number): FileCheck {
  const filename = sanitizeFilename(rawFilename);
  if (!filename) return { ok: false, error: 'Filename is missing or invalid' };
  if (data.length === 0) return { ok: false, error: 'File is empty' };
  if (data.length > maxBytes) return { ok: false, error: `File exceeds ${maxBytes} bytes` };
  const ext = filename.slice(filename.lastIndexOf('.') + 1).toLowerCase();
  const type = TYPES.find((t) => t.ext.includes(ext));
  if (!type) return { ok: false, error: `File type .${ext} is not allowed. Allowed: ${ALLOWED_EXTENSIONS.join(', ')}` };
  if (!type.matches(data)) return { ok: false, error: `File content does not match a .${ext} file` };
  return { ok: true, filename, mime: type.mime };
}

// ------------------------------------------------------------ field checks

export class ValidationError extends Error {}

export function requireString(value: unknown, field: string, { min = 1, max = 200 } = {}): string {
  if (typeof value !== 'string') throw new ValidationError(`${field} is required`);
  // eslint-disable-next-line no-control-regex
  const v = value.normalize('NFC').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').trim();
  if (v.length < min) throw new ValidationError(`${field} is required`);
  if (v.length > max) throw new ValidationError(`${field} must be at most ${max} characters`);
  return v;
}

export function optionalString(value: unknown, field: string, max = 2000): string {
  if (value === undefined || value === null || value === '') return '';
  return requireString(value, field, { min: 0, max });
}

export function requireCategory(value: unknown): Category {
  if (typeof value !== 'string' || !(CATEGORIES as readonly string[]).includes(value)) {
    throw new ValidationError(`category must be one of ${CATEGORIES.join(', ')}`);
  }
  return value as Category;
}

export function requireEmail(value: unknown): string {
  const v = requireString(value, 'email', { max: 254 }).toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) throw new ValidationError('email is invalid');
  return v;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function isUuid(v: unknown): v is string {
  return typeof v === 'string' && UUID_RE.test(v);
}

/** Only these keys may appear in a body; anything else is an error, not silently ignored. */
export function onlyKeys(body: unknown, allowed: string[]): Record<string, unknown> {
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    throw new ValidationError('Request body must be a JSON object');
  }
  const extra = Object.keys(body).filter((k) => !allowed.includes(k));
  if (extra.length) throw new ValidationError(`Unexpected field(s): ${extra.join(', ')}`);
  return body as Record<string, unknown>;
}

/** Parse an optional future expiry (ISO string or epoch ms). */
export function optionalExpiry(value: unknown): number | null {
  if (value === undefined || value === null || value === '') return null;
  const t = typeof value === 'number' ? value : typeof value === 'string' ? Date.parse(value) : NaN;
  if (!Number.isFinite(t)) throw new ValidationError('expiresAt is not a valid date');
  if (t <= Date.now()) throw new ValidationError('expiresAt must be in the future');
  if (t > Date.now() + 5 * 365 * 24 * 3600 * 1000) throw new ValidationError('expiresAt is too far in the future');
  return t;
}
