import type { NextFunction, Request, Response } from 'express';
import { newToken, sha256Hex } from './crypto.ts';
import { HttpError, type AppContext, type Role, type SessionUser } from './context.ts';

export const SESSION_COOKIE = 'tv_session';
export const CSRF_HEADER = 'x-trustvault-csrf';

export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (k && !(k in out)) {
      try {
        out[k] = decodeURIComponent(v);
      } catch {
        // ignore malformed cookie values
      }
    }
  }
  return out;
}

/**
 * Sessions are opaque random tokens; the database stores only their SHA-256.
 * Because every request looks the session up (no self-contained JWTs),
 * revoking a session, deactivating a user or changing their role takes
 * effect on the next request, with no grace period.
 */
export function createSession(ctx: AppContext, userId: string, req: Request): { token: string; expiresAt: number } {
  const token = newToken();
  const now = Date.now();
  const expiresAt = now + ctx.config.sessionAbsoluteHours * 3600_000;
  ctx.db
    .prepare(
      `INSERT INTO sessions (token_hash, user_id, created_at, last_seen_at, expires_at, ip, user_agent)
       VALUES (?,?,?,?,?,?,?)`,
    )
    .run(sha256Hex(token), userId, now, now, expiresAt, req.ip ?? null, String(req.get('user-agent') ?? '').slice(0, 200));
  return { token, expiresAt };
}

export function setSessionCookie(ctx: AppContext, res: Response, token: string, expiresAt: number) {
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure: ctx.config.env === 'production',
    sameSite: 'strict',
    path: '/',
    expires: new Date(expiresAt),
  });
}

export function clearSessionCookie(ctx: AppContext, res: Response) {
  res.clearCookie(SESSION_COOKIE, {
    httpOnly: true,
    secure: ctx.config.env === 'production',
    sameSite: 'strict',
    path: '/',
  });
}

export function revokeSession(ctx: AppContext, tokenHash: string) {
  ctx.db.prepare('UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').run(Date.now(), tokenHash);
}

/** Revoke every live session of a user (optionally except one). Returns how many were revoked. */
export function revokeAllSessions(ctx: AppContext, userId: string, exceptHash?: string): number {
  const r = ctx.db
    .prepare('UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL AND token_hash IS NOT ?')
    .run(Date.now(), userId, exceptHash ?? null);
  return Number(r.changes);
}

interface SessionJoinRow {
  token_hash: string;
  last_seen_at: number;
  expires_at: number;
  revoked_at: number | null;
  id: string;
  email: string;
  name: string;
  role: Role;
  active: number;
  must_change_password: number;
}

/** Resolve the session cookie to a user, or leave req.user undefined. Never throws for bad cookies. */
export function sessionMiddleware(ctx: AppContext) {
  return (req: Request, _res: Response, next: NextFunction) => {
    const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
    if (!token || token.length > 128) return next();
    const tokenHash = sha256Hex(token);
    const row = ctx.db
      .prepare(
        `SELECT s.token_hash, s.last_seen_at, s.expires_at, s.revoked_at,
                u.id, u.email, u.name, u.role, u.active, u.must_change_password
         FROM sessions s JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ?`,
      )
      .get(tokenHash) as SessionJoinRow | undefined;
    const now = Date.now();
    const idleMs = ctx.config.sessionIdleMinutes * 60_000;
    if (
      !row ||
      row.revoked_at !== null ||
      row.expires_at <= now ||
      row.last_seen_at + idleMs <= now ||
      row.active !== 1
    ) {
      return next();
    }
    ctx.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').run(now, tokenHash);
    const user: SessionUser = {
      id: row.id,
      email: row.email,
      name: row.name,
      role: row.role,
      mustChangePassword: row.must_change_password === 1,
      sessionHash: tokenHash,
    };
    req.user = user;
    next();
  };
}

/** Paths a user with a temporary (admin-set) password may still call. */
const PASSWORD_CHANGE_ALLOWED = new Set(['/api/auth/me', '/api/auth/password', '/api/auth/logout']);

export function requireAuth(req: Request, _res: Response, next: NextFunction) {
  if (!req.user) return next(new HttpError(401, 'unauthenticated', 'Sign in required'));
  if (req.user.mustChangePassword && !PASSWORD_CHANGE_ALLOWED.has(req.baseUrl + req.path)) {
    return next(new HttpError(403, 'password_change_required', 'You must change your password first'));
  }
  next();
}

export function requireRole(...roles: Role[]) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (!req.user) return next(new HttpError(401, 'unauthenticated', 'Sign in required'));
    if (!roles.includes(req.user.role)) {
      return next(new HttpError(403, 'forbidden', 'Your role does not allow this'));
    }
    next();
  };
}

/**
 * CSRF defence for state-changing requests:
 *  1. The session cookie is SameSite=Strict, so cross-site requests carry no session.
 *  2. Every non-GET request must carry the custom header X-TrustVault-CSRF.
 *     A cross-origin page cannot add a custom header without a CORS preflight,
 *     and we never answer preflights, so the request cannot be forged.
 *  3. If the browser sends Origin / Sec-Fetch-Site, they must be same-origin.
 */
export function csrfMiddleware(ctx: AppContext) {
  return (req: Request, _res: Response, next: NextFunction) => {
    if (req.method === 'GET' || req.method === 'HEAD') return next();
    if (req.get(CSRF_HEADER) !== '1') {
      return next(new HttpError(403, 'csrf', 'Missing anti-forgery header'));
    }
    const site = req.get('sec-fetch-site');
    if (site && site !== 'same-origin' && site !== 'none') {
      return next(new HttpError(403, 'csrf', 'Cross-site request refused'));
    }
    const origin = req.get('origin');
    if (origin) {
      const expected = ctx.config.publicOrigin ?? `${req.protocol}://${req.get('host')}`;
      if (origin !== expected) return next(new HttpError(403, 'csrf', 'Cross-origin request refused'));
    }
    next();
  };
}

/**
 * Small fixed-window rate limiter kept in memory. Good enough for one
 * instance; a multi-instance deploy would need a shared store (THREATS.md).
 */
export class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly limit: number;
  private readonly windowMs: number;
  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }
  /** Returns true if this hit is allowed. */
  hit(key: string): boolean {
    const now = Date.now();
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      if (this.hits.size > 50_000) this.sweep(now);
      return true;
    }
    entry.count++;
    return entry.count <= this.limit;
  }
  private sweep(now: number) {
    for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
  }
}
