import { createHmac, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { Router, type Request } from 'express';
import { clearSessionCookie, createSession, RateLimiter, requireAuth, revokeSession, setSessionCookie } from '../auth.ts';
import { auditFor, HttpError, type AppContext, type Role } from '../context.ts';
import { tx } from '../db.ts';
import { signInCodeMail } from '../mailer.ts';
import { onlyKeys, requireEmail, requireString, ValidationError } from '../validation.ts';

/**
 * Passwordless sign-in with a one-time code sent by email.
 *
 *   POST /auth/start   {email}        -> {challengeId}         (code emailed if the account exists)
 *   POST /auth/signup  {email, name}  -> {challengeId}         (code emailed; account created on verify)
 *   POST /auth/verify  {challengeId, code} -> session cookie
 *
 * Security properties (THREATS.md section D):
 *  - 6-digit code from a CSPRNG, stored only as HMAC(key, challengeId:code).
 *  - Valid for 10 minutes, single use, at most 5 wrong guesses per challenge,
 *    then the challenge is dead. At most 5 challenges per email per 15 min, so
 *    at most 25 guesses per 15 min against a 1-in-1,000,000 code.
 *  - The code is bound to its challenge id and its email: a code for one
 *    address can never sign in another.
 *  - No account enumeration: /start answers the same way for unknown emails
 *    (a decoy challenge is created and nothing is sent); /signup with an
 *    existing email sends that person a normal sign-in code instead of
 *    creating anything, so it cannot be used to take over an account.
 *  - Email is sent after the response, so timing does not reveal whether a
 *    message was sent.
 *  - Demo accounts (is_demo=1, seeded addresses that cannot receive mail) get
 *    the code shown in the response instead. That is only ever true for
 *    accounts the seed script created.
 */

const CODE_TTL_MS = 10 * 60_000;
const MAX_ATTEMPTS = 5;
const GENERIC_SENT = 'If that address can sign in, we have emailed it a 6-digit code.';
const BAD_CODE = 'That code is wrong or has expired. Request a new one.';

interface ChallengeRow {
  id: string;
  email: string;
  purpose: 'login' | 'signup';
  signup_name: string | null;
  code_hash: string;
  created_at: number;
  expires_at: number;
  attempts: number;
  consumed_at: number | null;
}

interface UserRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  active: number;
  is_demo: number;
}

export function authRoutes(ctx: AppContext): Router {
  const r = Router();
  const perEmail = new RateLimiter(ctx.config.codeRequestsPerEmail, 15 * 60_000);
  const perIpStart = new RateLimiter(ctx.config.codeRequestsPerIp, 15 * 60_000);
  const perIpVerifyFailures = new RateLimiter(50, 15 * 60_000);
  const otpKey = createHmac('sha256', ctx.config.masterKey).update('trustvault-otp-v1').digest();

  const hashCode = (challengeId: string, code: string) => createHmac('sha256', otpKey).update(`${challengeId}:${code}`).digest('hex');
  const newCode = () => String(randomInt(0, 1_000_000)).padStart(6, '0');
  const ip = (req: Request) => req.ip ?? 'unknown';

  function checkStartLimits(req: Request, email: string, action: string) {
    if (!perIpStart.hit(ip(req)) || !perEmail.hit(email)) {
      ctx.audit.record({ action, outcome: 'denied', actorEmail: email, ip: req.ip, details: { reason: 'rate_limited' } });
      throw new HttpError(429, 'rate_limited', 'Too many codes requested. Wait a few minutes and try again.');
    }
  }

  function createChallenge(req: Request, email: string, purpose: 'login' | 'signup', signupName: string | null) {
    const id = randomUUID();
    const code = newCode();
    const now = Date.now();
    ctx.db
      .prepare(
        `INSERT INTO login_challenges (id, email, purpose, signup_name, code_hash, created_at, expires_at, ip)
         VALUES (?,?,?,?,?,?,?,?)`,
      )
      .run(id, email, purpose, signupName, hashCode(id, code), now, now + CODE_TTL_MS, req.ip ?? null);
    return { id, code };
  }

  /** Fire-and-forget delivery so response timing never depends on whether mail is sent. */
  function deliver(req: Request, email: string, code: string, purpose: 'login' | 'signup', userId: string | null) {
    setImmediate(() => {
      ctx.mailer
        .send(signInCodeMail(email, code, purpose))
        .then(() => ctx.audit.record({ action: 'auth.code_sent', outcome: 'success', actorEmail: email, targetUserId: userId, ip: req.ip, details: { purpose } }))
        .catch((err: Error) => {
          console.error(JSON.stringify({ type: 'email_error', message: err.message }));
          ctx.audit.record({ action: 'auth.code_sent', outcome: 'failure', actorEmail: email, targetUserId: userId, ip: req.ip, details: { purpose, error: err.message.slice(0, 200) } });
        });
    });
  }

  function requireMailUnlessDemo(isDemo: boolean) {
    if (!isDemo && !ctx.mailer.configured) {
      throw new HttpError(503, 'email_unavailable', 'This server cannot send email yet, so only the demo accounts can sign in. Ask the administrator to configure email.');
    }
  }

  const findUser = (email: string) => ctx.db.prepare('SELECT id, email, name, role, active, is_demo FROM users WHERE email = ?').get(email) as UserRow | undefined;

  // ------------------------------------------------------------ start login
  r.post('/start', (req, res) => {
    const body = onlyKeys(req.body, ['email']);
    const email = requireEmail(body.email);
    checkStartLimits(req, email, 'auth.start');
    const user = findUser(email);
    const usable = !!user && user.active === 1;
    requireMailUnlessDemo(usable && user!.is_demo === 1);
    const { id, code } = createChallenge(req, email, 'login', null);
    ctx.audit.record({ action: 'auth.start', outcome: usable ? 'success' : 'denied', actorEmail: email, targetUserId: user?.id ?? null, ip: req.ip, details: usable ? {} : { reason: user ? 'inactive' : 'unknown_user' } });
    if (usable && user!.is_demo === 1) {
      return res.json({ challengeId: id, message: 'Demo account: this address cannot receive email, so the code is shown here.', demoCode: code });
    }
    if (usable) deliver(req, email, code, 'login', user!.id);
    // Unknown or inactive: the challenge exists but nobody receives its code.
    res.json({ challengeId: id, message: GENERIC_SENT });
  });

  // ----------------------------------------------------------------- signup
  r.post('/signup', (req, res) => {
    const body = onlyKeys(req.body, ['email', 'name']);
    const email = requireEmail(body.email);
    const name = requireString(body.name, 'name', { max: 100 });
    const domain = email.slice(email.lastIndexOf('@') + 1);
    if (ctx.config.signupDomains.length && !ctx.config.signupDomains.includes(domain)) {
      throw new ValidationError(`Sign-up is limited to ${ctx.config.signupDomains.map((d) => '@' + d).join(', ')} addresses`);
    }
    checkStartLimits(req, email, 'auth.signup');
    requireMailUnlessDemo(false);
    const existing = findUser(email);
    if (existing) {
      // Never create, rename or "reclaim" an existing account. The real owner
      // just gets a normal sign-in code; the response is identical.
      const { id, code } = createChallenge(req, email, 'login', null);
      ctx.audit.record({ action: 'auth.signup', outcome: 'denied', actorEmail: email, targetUserId: existing.id, ip: req.ip, details: { reason: 'exists' } });
      if (existing.active === 1 && existing.is_demo !== 1) deliver(req, email, code, 'login', existing.id);
      return res.json({ challengeId: id, message: GENERIC_SENT });
    }
    const { id, code } = createChallenge(req, email, 'signup', name);
    ctx.audit.record({ action: 'auth.signup', outcome: 'success', actorEmail: email, ip: req.ip, details: { stage: 'code_requested' } });
    deliver(req, email, code, 'signup', null);
    res.json({ challengeId: id, message: GENERIC_SENT });
  });

  // ----------------------------------------------------------------- verify
  r.post('/verify', (req, res) => {
    const body = onlyKeys(req.body, ['challengeId', 'code']);
    const challengeId = typeof body.challengeId === 'string' ? body.challengeId.slice(0, 64) : '';
    const code = typeof body.code === 'string' ? body.code.replace(/\s+/g, '') : '';
    if (perIpVerifyFailures.blocked(ip(req))) throw new HttpError(429, 'rate_limited', 'Too many wrong codes. Try again later.');

    const fail = (reason: string, email: string | null) => {
      perIpVerifyFailures.hit(ip(req));
      ctx.audit.record({ action: 'auth.verify', outcome: 'denied', actorEmail: email, ip: req.ip, details: { reason } });
      return new HttpError(401, 'bad_code', BAD_CODE);
    };

    const ch = ctx.db.prepare('SELECT * FROM login_challenges WHERE id = ?').get(challengeId) as ChallengeRow | undefined;
    if (!ch) throw fail('unknown_challenge', null);
    // "Already used" is decided once, atomically, by the UPDATE below (it also
    // covers two verifies racing), not by a separate pre-check here.
    if (ch.expires_at <= Date.now()) throw fail('expired', ch.email);
    if (ch.attempts >= MAX_ATTEMPTS) throw fail('too_many_attempts', ch.email);

    const expected = Buffer.from(ch.code_hash, 'hex');
    const actual = Buffer.from(hashCode(ch.id, /^\d{6}$/.test(code) ? code : 'invalid'), 'hex');
    if (!timingSafeEqual(expected, actual)) {
      ctx.db.prepare('UPDATE login_challenges SET attempts = attempts + 1 WHERE id = ?').run(ch.id);
      throw fail(ch.attempts + 1 >= MAX_ATTEMPTS ? 'wrong_code_challenge_dead' : 'wrong_code', ch.email);
    }

    // Correct code. Consume it and resolve the account in one transaction.
    const user = tx(ctx.db, () => {
      const consumed = ctx.db.prepare('UPDATE login_challenges SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL').run(Date.now(), ch.id);
      if (Number(consumed.changes) !== 1) return null; // lost a race with a concurrent verify
      let u = findUser(ch.email);
      if (ch.purpose === 'signup' && !u) {
        const id = randomUUID();
        const role: Role = ctx.config.adminEmails.includes(ch.email.toLowerCase()) ? 'admin' : 'owner';
        ctx.db
          .prepare("INSERT INTO users (id, email, name, role, password_hash, created_at, is_demo) VALUES (?,?,?,?,'!',?,0)")
          .run(id, ch.email.toLowerCase(), ch.signup_name ?? ch.email, role, Date.now());
        ctx.audit.record({ action: 'user.create', outcome: 'success', actorEmail: ch.email, targetUserId: id, ip: req.ip, details: { via: 'self_signup', role } });
        u = findUser(ch.email);
      }
      return u ?? null;
    });
    if (!user) throw fail('already_used', ch.email);
    if (user.active !== 1) throw fail('inactive', ch.email);

    const { token, expiresAt } = createSession(ctx, user.id, req);
    setSessionCookie(ctx, res, token, expiresAt);
    ctx.audit.record({ action: 'auth.login', outcome: 'success', actorId: user.id, actorEmail: user.email, ip: req.ip, details: { method: 'email_code' } });
    res.json({ user: { id: user.id, email: user.email, name: user.name, role: user.role, isDemo: user.is_demo === 1 } });
  });

  r.post('/logout', requireAuth, (req, res) => {
    revokeSession(ctx, req.user!.sessionHash);
    clearSessionCookie(ctx, res);
    auditFor(ctx, req, { action: 'auth.logout', outcome: 'success' });
    res.json({ ok: true });
  });

  r.get('/me', requireAuth, (req, res) => {
    const u = req.user!;
    res.json({ user: { id: u.id, email: u.email, name: u.name, role: u.role, isDemo: u.isDemo } });
  });

  /** Lets the sign-in page say whether real email delivery is available. */
  r.get('/config', (_req, res) => {
    res.json({ emailEnabled: ctx.mailer.configured, signupDomains: ctx.config.signupDomains });
  });

  return r;
}
