import { Router } from 'express';
import {
  clearSessionCookie,
  createSession,
  RateLimiter,
  requireAuth,
  revokeAllSessions,
  revokeSession,
  setSessionCookie,
} from '../auth.ts';
import { auditFor, HttpError, type AppContext } from '../context.ts';
import { DUMMY_PASSWORD_HASH, hashPassword, validatePasswordStrength, verifyPassword } from '../crypto.ts';
import { onlyKeys, requireString, ValidationError } from '../validation.ts';

const MAX_FAILED_LOGINS = 5;
const LOCKOUT_MS = 15 * 60_000;
/** One message for every failure, so the response does not reveal whether the account exists. */
const LOGIN_FAILED = 'Invalid email or password, or the account is temporarily locked';

interface UserAuthRow {
  id: string;
  email: string;
  name: string;
  role: string;
  password_hash: string;
  active: number;
  failed_logins: number;
  locked_until: number | null;
  must_change_password: number;
}

export function authRoutes(ctx: AppContext): Router {
  const r = Router();
  const ipLimiter = new RateLimiter(20, 15 * 60_000);

  r.post('/login', (req, res) => {
    const body = onlyKeys(req.body, ['email', 'password']);
    const email = typeof body.email === 'string' ? body.email.trim().toLowerCase().slice(0, 254) : '';
    const password = typeof body.password === 'string' ? body.password.slice(0, 256) : '';
    if (!ipLimiter.hit(req.ip ?? 'unknown')) {
      ctx.audit.record({ action: 'auth.login', outcome: 'denied', actorEmail: email, ip: req.ip, details: { reason: 'ip_rate_limited' } });
      throw new HttpError(429, 'rate_limited', 'Too many sign-in attempts. Try again later.');
    }
    const user = ctx.db.prepare('SELECT * FROM users WHERE email = ?').get(email) as UserAuthRow | undefined;
    // Always run one scrypt verification so response time does not reveal whether the email exists.
    const passwordOk = verifyPassword(password, user?.password_hash ?? DUMMY_PASSWORD_HASH);
    const now = Date.now();

    let reason: string | null = null;
    if (!user) reason = 'unknown_user';
    else if (user.active !== 1) reason = 'inactive';
    else if (user.locked_until !== null && user.locked_until > now) reason = 'locked';
    else if (!passwordOk) reason = 'bad_password';

    if (reason || !user) {
      if (user && reason === 'bad_password') {
        const failed = user.failed_logins + 1;
        const lock = failed >= MAX_FAILED_LOGINS ? now + LOCKOUT_MS : null;
        ctx.db
          .prepare('UPDATE users SET failed_logins = ?, locked_until = COALESCE(?, locked_until) WHERE id = ?')
          .run(lock ? 0 : failed, lock, user.id);
        if (lock) {
          ctx.audit.record({ action: 'auth.lockout', outcome: 'success', targetUserId: user.id, actorEmail: email, ip: req.ip, details: { until: lock } });
        }
      }
      ctx.audit.record({
        action: 'auth.login',
        outcome: 'denied',
        actorEmail: email,
        targetUserId: user?.id ?? null,
        ip: req.ip,
        details: { reason },
      });
      throw new HttpError(401, 'login_failed', LOGIN_FAILED);
    }

    ctx.db.prepare('UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?').run(user.id);
    const { token, expiresAt } = createSession(ctx, user.id, req);
    setSessionCookie(ctx, res, token, expiresAt);
    ctx.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, actorEmail: user.email, ip: req.ip });
    res.json({
      user: { id: user.id, email: user.email, name: user.name, role: user.role, mustChangePassword: user.must_change_password === 1 },
    });
  });

  r.post('/logout', requireAuth, (req, res) => {
    revokeSession(ctx, req.user!.sessionHash);
    clearSessionCookie(ctx, res);
    auditFor(ctx, req, { action: 'auth.logout', outcome: 'success' });
    res.json({ ok: true });
  });

  r.get('/me', requireAuth, (req, res) => {
    const u = req.user!;
    res.json({ user: { id: u.id, email: u.email, name: u.name, role: u.role, mustChangePassword: u.mustChangePassword } });
  });

  r.post('/password', requireAuth, (req, res) => {
    const body = onlyKeys(req.body, ['currentPassword', 'newPassword']);
    const current = requireString(body.currentPassword, 'currentPassword', { max: 256 });
    const problem = validatePasswordStrength(body.newPassword);
    if (problem) throw new ValidationError(problem);
    const newPassword = body.newPassword as string;
    const row = ctx.db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user!.id) as { password_hash: string };
    if (!verifyPassword(current, row.password_hash)) {
      auditFor(ctx, req, { action: 'auth.password_change', outcome: 'denied', targetUserId: req.user!.id, details: { reason: 'bad_current_password' } });
      throw new HttpError(403, 'bad_password', 'Current password is incorrect');
    }
    if (current === newPassword) throw new ValidationError('New password must differ from the current one');
    ctx.db.prepare('UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?').run(hashPassword(newPassword), req.user!.id);
    // Every other session for this user dies; this one survives.
    const revoked = revokeAllSessions(ctx, req.user!.id, req.user!.sessionHash);
    auditFor(ctx, req, { action: 'auth.password_change', outcome: 'success', targetUserId: req.user!.id, details: { otherSessionsRevoked: revoked } });
    res.json({ ok: true });
  });

  return r;
}
