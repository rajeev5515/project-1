import { createHash } from 'node:crypto';
import path from 'node:path';

/**
 * All runtime configuration comes from the environment. In production the two
 * keys MUST be supplied; we refuse to start with the development defaults so a
 * mis-configured deploy fails loudly instead of running with known keys.
 */
export interface Config {
  env: 'production' | 'development' | 'test';
  port: number;
  dataDir: string;
  /** 32-byte key-encryption key: wraps the per-file data keys. */
  masterKey: Buffer;
  /** 32-byte HMAC key for the audit hash chain. Distinct from masterKey. */
  auditKey: Buffer;
  maxUploadBytes: number;
  sessionIdleMinutes: number;
  sessionAbsoluteHours: number;
  /** Public origin, e.g. https://trustvault.example.com. Used for Origin checks. */
  publicOrigin: string | null;
  trustProxy: boolean;
  anthropicApiKey: string | null;
  anthropicModel: string;
  /** Resend API key for sign-in codes. Without it, production cannot email codes. */
  resendApiKey: string | null;
  /** From address, e.g. "TrustVault <login@yourdomain.com>". Resend's sandbox only allows onboarding@resend.dev. */
  emailFrom: string;
  /** Emails that become admin when they sign up (lower-cased). */
  adminEmails: string[];
  /** If non-empty, only these email domains may sign up (e.g. ["acme.com"]). */
  signupDomains: string[];
  /** Sign-in codes that may be requested per email address / per IP in 15 minutes. */
  codeRequestsPerEmail: number;
  codeRequestsPerIp: number;
}

function deriveDevKey(label: string): Buffer {
  return createHash('sha256').update(`trustvault-dev-only:${label}`).digest();
}

function parseKey(name: string, value: string | undefined, env: Config['env']): Buffer {
  if (!value) {
    if (env === 'production') {
      throw new Error(`${name} must be set in production (64 hex chars = 32 bytes)`);
    }
    return deriveDevKey(name);
  }
  if (!/^[0-9a-fA-F]{64}$/.test(value)) {
    throw new Error(`${name} must be 64 hex characters (32 bytes)`);
  }
  return Buffer.from(value, 'hex');
}

function list(v: string | undefined): string[] {
  return (v ?? '')
    .split(',')
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean);
}

export function loadConfig(overrides: Partial<Config> = {}): Config {
  const rawEnv = process.env.NODE_ENV;
  const env: Config['env'] =
    rawEnv === 'production' ? 'production' : rawEnv === 'test' ? 'test' : 'development';
  const masterKey = parseKey('TV_MASTER_KEY', process.env.TV_MASTER_KEY, env);
  const auditKey = parseKey('TV_AUDIT_KEY', process.env.TV_AUDIT_KEY, env);
  if (masterKey.equals(auditKey)) {
    throw new Error('TV_MASTER_KEY and TV_AUDIT_KEY must be different keys');
  }
  const cfg: Config = {
    env,
    port: Number(process.env.PORT ?? 3000),
    dataDir: path.resolve(process.env.TV_DATA_DIR ?? './data'),
    masterKey,
    auditKey,
    maxUploadBytes: Number(process.env.TV_MAX_UPLOAD_BYTES ?? 20 * 1024 * 1024),
    sessionIdleMinutes: Number(process.env.TV_SESSION_IDLE_MINUTES ?? 30),
    sessionAbsoluteHours: Number(process.env.TV_SESSION_ABSOLUTE_HOURS ?? 8),
    publicOrigin: process.env.TV_PUBLIC_ORIGIN ?? null,
    trustProxy: process.env.TV_TRUST_PROXY === '1',
    anthropicApiKey: process.env.ANTHROPIC_API_KEY ?? null,
    anthropicModel: process.env.TV_AI_MODEL ?? 'claude-opus-5-5',
    resendApiKey: process.env.RESEND_API_KEY || null,
    emailFrom: process.env.TV_EMAIL_FROM || 'TrustVault <onboarding@resend.dev>',
    adminEmails: list(process.env.TV_ADMIN_EMAILS),
    signupDomains: list(process.env.TV_SIGNUP_DOMAINS),
    codeRequestsPerEmail: 5,
    codeRequestsPerIp: 30,
    ...overrides,
  };
  return cfg;
}
