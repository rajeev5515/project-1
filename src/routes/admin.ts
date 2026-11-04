import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { requireAuth, requireRole, revokeAllSessions } from '../auth.ts';
import { auditFor, HttpError, type AppContext, type Role, type SessionUser } from '../context.ts';
import { tx } from '../db.ts';
import { isUuid, onlyKeys, requireEmail, requireString, ValidationError } from '../validation.ts';

const ROLES: Role[] = ['admin', 'owner', 'viewer'];

interface UserRow {
  id: string;
  email: string;
  name: string;
  role: Role;
  active: number;
  created_at: number;
  locked_until: number | null;
  is_demo: number;
}

const presentUser = (u: UserRow) => ({
  id: u.id,
  email: u.email,
  name: u.name,
  role: u.role,
  active: u.active === 1,
  createdAt: u.created_at,
  isDemo: u.is_demo === 1,
});

/**
 * Demo world wall (THREATS.md T60). The seeded demo accounts can be signed in
 * to by anyone on the internet, so a demo admin must never see or touch real
 * users or their documents' metadata. These SQL fragments restrict audit
 * queries to rows that involve the demo world. Real admins see everything.
 */
const DEMO_USERS = 'SELECT id FROM users WHERE is_demo = 1';
const DEMO_AUDIT_SCOPE = ` AND (actor_id IN (${DEMO_USERS}) OR target_user_id IN (${DEMO_USERS})
  OR document_id IN (SELECT d.id FROM documents d JOIN users u ON u.id = d.owner_id WHERE u.is_demo = 1))`;
const auditScope = (u: SessionUser) => (u.isDemo ? DEMO_AUDIT_SCOPE : '');

/** Directory lookup so owners can pick who to share with. Not available to viewers. */
export function userRoutes(ctx: AppContext): Router {
  const r = Router();
  r.use(requireAuth);
  r.get('/directory', requireRole('owner', 'admin'), (req, res) => {
    const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 100) : '';
    if (q.length < 2) return res.json({ users: [] });
    const like = `%${q.replace(/[\\%_]/g, (m) => '\\' + m)}%`;
    const rows = ctx.db
      .prepare(
        `SELECT id, name, email, role FROM users
         WHERE active = 1 AND id != ? AND is_demo = ? AND (name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\')
         ORDER BY name LIMIT 10`,
      )
      .all(req.user!.id, req.user!.isDemo ? 1 : 0, like, like);
    res.json({ users: rows });
  });
  return r;
}

export function adminRoutes(ctx: AppContext): Router {
  const r = Router();
  r.use(requireAuth, requireRole('admin'));

  /** A user the calling admin may manage. Demo admins only reach demo users. */
  const loadUser = (caller: SessionUser, id: unknown): UserRow => {
    const u = isUuid(id) ? (ctx.db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined) : undefined;
    if (!u || (caller.isDemo && u.is_demo !== 1)) throw new HttpError(404, 'not_found', 'User not found');
    return u;
  };

  const activeAdminCount = () => (ctx.db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND active = 1").get() as { n: number }).n;

  // ------------------------------------------------------------------ users
  r.get('/users', (req, res) => {
    const rows = ctx.db.prepare(`SELECT * FROM users ${req.user!.isDemo ? 'WHERE is_demo = 1' : ''} ORDER BY created_at`).all() as unknown as UserRow[];
    const docCounts = new Map(
      (ctx.db.prepare('SELECT owner_id, COUNT(*) AS n FROM documents WHERE deleted_at IS NULL GROUP BY owner_id').all() as { owner_id: string; n: number }[]).map(
        (x) => [x.owner_id, x.n],
      ),
    );
    res.json({ users: rows.map((u) => ({ ...presentUser(u), documentsOwned: docCounts.get(u.id) ?? 0 })) });
  });

  r.post('/users', (req, res) => {
    // A demo admin creating accounts could squat real people's addresses
    // inside the publicly-accessible demo world, so only real admins invite.
    if (req.user!.isDemo) throw new HttpError(403, 'forbidden', 'The demo administrator cannot create accounts');
    const body = onlyKeys(req.body, ['email', 'name', 'role']);
    const email = requireEmail(body.email);
    const name = requireString(body.name, 'name', { max: 100 });
    if (!ROLES.includes(body.role as Role)) throw new ValidationError('role must be admin, owner or viewer');
    if (ctx.db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) throw new HttpError(409, 'conflict', 'A user with that email already exists');
    const id = randomUUID();
    tx(ctx.db, () => {
      ctx.db
        .prepare("INSERT INTO users (id, email, name, role, password_hash, created_at, is_demo) VALUES (?,?,?,?,'!',?,0)")
        .run(id, email, name, body.role as Role, Date.now());
      auditFor(ctx, req, { action: 'user.create', outcome: 'success', targetUserId: id, details: { email, role: body.role } });
    });
    res.status(201).json({ user: presentUser(loadUser(req.user!, id)) });
  });

  r.patch('/users/:id', (req, res) => {
    const target = loadUser(req.user!, req.params.id);
    const body = onlyKeys(req.body, ['role', 'active', 'name']);
    const changes: Record<string, unknown> = {};
    let role = target.role;
    let active = target.active === 1;
    let name = target.name;
    if (body.role !== undefined) {
      if (!ROLES.includes(body.role as Role)) throw new ValidationError('role must be admin, owner or viewer');
      role = body.role as Role;
    }
    if (body.active !== undefined) {
      if (typeof body.active !== 'boolean') throw new ValidationError('active must be true or false');
      active = body.active;
    }
    if (body.name !== undefined) name = requireString(body.name, 'name', { max: 100 });
    if (target.id === req.user!.id && (role !== target.role || !active)) {
      throw new ValidationError('You cannot change your own role or deactivate yourself');
    }
    if (target.role === 'admin' && target.active === 1 && (role !== 'admin' || !active) && activeAdminCount() <= 1) {
      throw new ValidationError('Cannot remove the last active administrator');
    }
    if (role !== target.role) changes.role = { from: target.role, to: role };
    if (active !== (target.active === 1)) changes.active = { from: target.active === 1, to: active };
    if (name !== target.name) changes.name = { from: target.name, to: name };
    if (Object.keys(changes).length === 0) return res.json({ user: presentUser(target) });

    const revoked = tx(ctx.db, () => {
      ctx.db.prepare('UPDATE users SET role = ?, active = ?, name = ? WHERE id = ?').run(role, active ? 1 : 0, name, target.id);
      // Deactivation or any role change ends every session immediately. (Role
      // is re-read on each request anyway; this also forces a fresh sign-in.)
      const n = changes.active || changes.role ? revokeAllSessions(ctx, target.id) : 0;
      auditFor(ctx, req, {
        action: changes.active ? (active ? 'user.reactivate' : 'user.deactivate') : 'user.update',
        outcome: 'success',
        targetUserId: target.id,
        details: { changes, sessionsRevoked: n },
      });
      return n;
    });
    res.json({ user: presentUser(loadUser(req.user!, target.id)), sessionsRevoked: revoked });
  });

  r.post('/users/:id/revoke-sessions', (req, res) => {
    const target = loadUser(req.user!, req.params.id);
    const n = revokeAllSessions(ctx, target.id, target.id === req.user!.id ? req.user!.sessionHash : undefined);
    auditFor(ctx, req, { action: 'user.sessions_revoked', outcome: 'success', targetUserId: target.id, details: { sessionsRevoked: n } });
    res.json({ sessionsRevoked: n });
  });

  /**
   * Hand a leaver's documents to another owner. The admin does not gain
   * access themselves: the recipient must be a different, active user with
   * the owner role, and cannot be the acting admin.
   */
  r.post('/users/:id/transfer-documents', (req, res) => {
    const from = loadUser(req.user!, req.params.id);
    const body = onlyKeys(req.body, ['toUserId']);
    const to = loadUser(req.user!, body.toUserId);
    if (to.id === from.id) throw new ValidationError('Choose a different recipient');
    if (to.role !== 'owner' || to.active !== 1) throw new ValidationError('Recipient must be an active user with the owner role');
    if (to.is_demo !== from.is_demo) throw new ValidationError('Documents cannot move between demo and real accounts');
    const docs = ctx.db.prepare('SELECT id, title FROM documents WHERE owner_id = ?').all(from.id) as { id: string; title: string }[];
    tx(ctx.db, () => {
      for (const d of docs) {
        // The new owner's previous grant (if any) is superseded by ownership.
        ctx.db.prepare('DELETE FROM grants WHERE document_id = ? AND user_id = ?').run(d.id, to.id);
        ctx.db.prepare('UPDATE documents SET owner_id = ?, updated_at = ? WHERE id = ?').run(to.id, Date.now(), d.id);
        auditFor(ctx, req, { action: 'document.ownership_transfer', outcome: 'success', documentId: d.id, targetUserId: to.id, details: { from: from.id, to: to.id, title: d.title } });
      }
      auditFor(ctx, req, { action: 'user.documents_transferred', outcome: 'success', targetUserId: from.id, details: { to: to.id, count: docs.length } });
    });
    res.json({ transferred: docs.length });
  });

  // ------------------------------------------------------- permission review
  r.get('/grants', (req, res) => {
    const rows = ctx.db
      .prepare(
        `SELECT g.id, g.permission, g.created_at, g.expires_at, d.id AS document_id, d.title, d.category,
                o.email AS owner_email, u.email AS user_email, u.role AS user_role, u.active AS user_active
         FROM grants g JOIN documents d ON d.id = g.document_id
         JOIN users o ON o.id = d.owner_id JOIN users u ON u.id = g.user_id
         WHERE d.deleted_at IS NULL ${req.user!.isDemo ? 'AND o.is_demo = 1' : ''} ORDER BY g.created_at DESC LIMIT 1000`,
      )
      .all();
    res.json({ grants: rows });
  });

  // ------------------------------------------------------------------ audit
  r.get('/audit', (req, res) => {
    const q = req.query;
    const str = (v: unknown) => (typeof v === 'string' ? v.trim().slice(0, 200) : '');
    const where: string[] = [];
    const params: (string | number)[] = [];
    const actor = str(q.actor);
    if (actor) {
      where.push('(actor_email LIKE ? OR actor_id = ?)');
      params.push(`%${actor}%`, actor);
    }
    const action = str(q.action);
    if (action) {
      where.push('action LIKE ?');
      params.push(`${action}%`);
    }
    const outcome = str(q.outcome);
    if (outcome) {
      where.push('outcome = ?');
      params.push(outcome);
    }
    const documentId = str(q.documentId);
    if (documentId) {
      where.push('document_id = ?');
      params.push(documentId);
    }
    const before = Number(q.before);
    if (Number.isFinite(before) && before > 0) {
      where.push('seq < ?');
      params.push(before);
    }
    const from = str(q.from);
    if (from && Number.isFinite(Date.parse(from))) {
      where.push('ts >= ?');
      params.push(Date.parse(from));
    }
    const limit = Math.min(Math.max(Number(q.limit) || 100, 1), 500);
    const rows = ctx.db
      .prepare(`SELECT * FROM audit_log WHERE 1=1 ${where.map((w) => 'AND ' + w).join(' ')} ${auditScope(req.user!)} ORDER BY seq DESC LIMIT ${limit}`)
      .all(...params) as { details: string }[];
    res.json({ events: rows.map((e) => ({ ...e, details: JSON.parse(e.details) })) });
  });

  r.get('/audit/verify', (req, res) => {
    const seq = Number(req.query.seq);
    const hash = typeof req.query.hash === 'string' ? req.query.hash : '';
    const expected = Number.isInteger(seq) && seq > 0 && /^[0-9a-f]{64}$/.test(hash) ? { seq, hash } : undefined;
    const result = ctx.audit.verify(expected);
    auditFor(ctx, req, { action: 'audit.verify', outcome: result.ok ? 'success' : 'failure', details: { checked: result.checked, firstBadSeq: result.firstBadSeq, reason: result.reason } });
    res.json(result);
  });

  r.get('/alerts', (req, res) => res.json(computeAlerts(ctx, Date.now(), auditScope(req.user!))));

  r.get('/stats', (req, res) => {
    const one = (sql: string) => (ctx.db.prepare(sql).get() as { n: number }).n;
    const since = Date.now() - 24 * 3600_000;
    const demo = req.user!.isDemo;
    const docWorld = demo ? 'AND owner_id IN (SELECT id FROM users WHERE is_demo = 1)' : '';
    res.json({
      users: one(`SELECT COUNT(*) AS n FROM users WHERE active = 1 ${demo ? 'AND is_demo = 1' : ''}`),
      documents: one(`SELECT COUNT(*) AS n FROM documents WHERE deleted_at IS NULL ${docWorld}`),
      inTrash: one(`SELECT COUNT(*) AS n FROM documents WHERE deleted_at IS NOT NULL ${docWorld}`),
      grants: one(`SELECT COUNT(*) AS n FROM grants WHERE 1=1 ${demo ? 'AND user_id IN (SELECT id FROM users WHERE is_demo = 1)' : ''}`),
      auditEvents: one(`SELECT COUNT(*) AS n FROM audit_log WHERE 1=1 ${auditScope(req.user!)}`),
      last24h: ctx.db
        .prepare(`SELECT action, outcome, COUNT(*) AS n FROM audit_log WHERE ts >= ? ${auditScope(req.user!)} GROUP BY action, outcome ORDER BY n DESC`)
        .all(since),
    });
  });

  return r;
}

export interface Alert {
  severity: 'critical' | 'high' | 'medium' | 'info';
  kind: string;
  message: string;
  actor?: string | null;
  count?: number;
  lastSeen?: number;
}

/**
 * What an administrator should notice. Computed from the audit log on demand
 * (small data; a larger deploy would compute these incrementally).
 */
export function computeAlerts(ctx: AppContext, now = Date.now(), scope = ''): { alerts: Alert[]; generatedAt: number } {
  const alerts: Alert[] = [];
  const hour = now - 3600_000;
  const day = now - 24 * 3600_000;

  const verify = ctx.audit.verify();
  if (!verify.ok) {
    alerts.push({ severity: 'critical', kind: 'audit_tamper', message: `Audit chain broken at seq ${verify.firstBadSeq}: ${verify.reason}` });
  }

  const denied = ctx.db
    .prepare(
      `SELECT actor_email AS actor, COUNT(*) AS n, MAX(ts) AS last, COUNT(DISTINCT document_id) AS docs FROM audit_log
       WHERE outcome = 'denied' AND action LIKE 'document.%' AND ts >= ? ${scope} GROUP BY actor_id HAVING n >= 5 ORDER BY n DESC`,
    )
    .all(hour) as { actor: string; n: number; last: number; docs: number }[];
  for (const d of denied) {
    alerts.push({ severity: 'high', kind: 'access_probing', actor: d.actor, count: d.n, lastSeen: d.last, message: `${d.actor} was refused ${d.n} times in the last hour across ${d.docs} document id(s)` });
  }

  const failedLogins = ctx.db
    .prepare(
      `SELECT COALESCE(actor_email, '(blank)') AS actor, COUNT(*) AS n, MAX(ts) AS last FROM audit_log
       WHERE action = 'auth.verify' AND outcome = 'denied' AND ts >= ? ${scope} GROUP BY actor_email HAVING n >= 5 ORDER BY n DESC`,
    )
    .all(hour) as { actor: string; n: number; last: number }[];
  for (const f of failedLogins) {
    alerts.push({ severity: 'medium', kind: 'failed_logins', actor: f.actor, count: f.n, lastSeen: f.last, message: `${f.n} wrong sign-in codes for ${f.actor} in the last hour` });
  }
  const ipLogins = ctx.db
    .prepare(
      `SELECT ip AS actor, COUNT(DISTINCT actor_email) AS accounts, COUNT(*) AS n, MAX(ts) AS last FROM audit_log
       WHERE action = 'auth.verify' AND outcome = 'denied' AND ts >= ? ${scope} GROUP BY ip HAVING accounts >= 3`,
    )
    .all(hour) as { actor: string; accounts: number; n: number; last: number }[];
  for (const f of ipLogins) {
    alerts.push({ severity: 'high', kind: 'code_guessing', actor: f.actor, count: f.n, lastSeen: f.last, message: `IP ${f.actor} entered wrong codes for ${f.accounts} different accounts in the last hour` });
  }

  const bulk = ctx.db
    .prepare(
      `SELECT actor_email AS actor, COUNT(*) AS n, COUNT(DISTINCT document_id) AS docs, MAX(ts) AS last FROM audit_log
       WHERE action = 'document.download' AND outcome = 'success' AND ts >= ? ${scope} GROUP BY actor_id HAVING docs >= 10 OR n >= 30`,
    )
    .all(hour) as { actor: string; n: number; docs: number; last: number }[];
  for (const b of bulk) {
    alerts.push({ severity: 'high', kind: 'bulk_download', actor: b.actor, count: b.n, lastSeen: b.last, message: `${b.actor} downloaded ${b.docs} distinct documents (${b.n} downloads) in the last hour` });
  }

  const privileged = ctx.db
    .prepare(
      `SELECT action, actor_email AS actor, ts, target_user_id FROM audit_log
       WHERE action IN ('user.password_reset','user.deactivate','user.reactivate','user.update','user.create','user.documents_transferred') AND ts >= ? ${scope}
         AND COALESCE(actor_email, '') != 'seed'
       ORDER BY ts DESC LIMIT 50`,
    )
    .all(day) as { action: string; actor: string; ts: number; target_user_id: string }[];
  for (const p of privileged) {
    const target = ctx.db.prepare('SELECT email FROM users WHERE id = ?').get(p.target_user_id) as { email: string } | undefined;
    alerts.push({
      severity: p.action === 'user.documents_transferred' ? 'medium' : 'info',
      kind: 'privileged_change',
      actor: p.actor,
      lastSeen: p.ts,
      message: `${p.actor} performed ${p.action} on ${target?.email ?? p.target_user_id}`,
    });
  }

  const wideShare = ctx.db
    .prepare(
      `SELECT actor_email AS actor, COUNT(*) AS n, MAX(ts) AS last FROM audit_log
       WHERE action = 'grant.create' AND outcome = 'success' AND ts >= ? ${scope} GROUP BY actor_id HAVING n >= 15`,
    )
    .all(hour) as { actor: string; n: number; last: number }[];
  for (const w of wideShare) {
    alerts.push({ severity: 'medium', kind: 'mass_sharing', actor: w.actor, count: w.n, lastSeen: w.last, message: `${w.actor} created ${w.n} grants in the last hour` });
  }

  const order = { critical: 0, high: 1, medium: 2, info: 3 };
  alerts.sort((a, b) => order[a.severity] - order[b.severity] || (b.lastSeen ?? 0) - (a.lastSeen ?? 0));
  return { alerts, generatedAt: now };
}
