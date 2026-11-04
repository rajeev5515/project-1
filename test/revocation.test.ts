/**
 * Taking access away works immediately: the very next request fails.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, DOC, login, PASSWORD, startEnv, type TestEnv } from './helpers.ts';

let env: TestEnv;
before(async () => {
  env = await startEnv();
});
after(async () => env.close());

describe('T07 revoking a grant', () => {
  test('a live session loses the document on the next request', async () => {
    const owner = await login(env, 'olivia');
    const vera = await login(env, 'vera');
    const id = env.docs[DOC.veraSalary]!;
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 200);
    const grants = (await owner.get(`/api/documents/${id}/grants`)).json.grants;
    const g = grants.find((x: any) => x.user.id === env.ids.vera);
    assert.equal((await owner.del(`/api/documents/${id}/grants/${g.id}`)).status, 200);
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 404);
    assert.equal((await vera.get(`/api/documents/${id}`)).status, 404);
    assert.ok(!(await vera.get('/api/documents')).json.documents.some((d: any) => d.id === id));
    // Re-grant for later tests and check it works again immediately.
    assert.equal((await owner.post(`/api/documents/${id}/grants`, { userId: env.ids.vera, permission: 'read' })).status, 201);
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 200);
  });

  test('downgrading edit to read removes edit rights immediately', async () => {
    const owner = await login(env, 'olivia');
    const victor = await login(env, 'victor');
    const id = env.docs[DOC.handbook]!;
    assert.equal((await victor.patch(`/api/documents/${id}`, { description: 'v1' })).status, 200);
    assert.equal((await owner.post(`/api/documents/${id}/grants`, { userId: env.ids.victor, permission: 'read' })).status, 200);
    assert.equal((await victor.patch(`/api/documents/${id}`, { description: 'v2' })).status, 403);
    assert.equal((await victor.get(`/api/documents/${id}/download`)).status, 200);
    await owner.post(`/api/documents/${id}/grants`, { userId: env.ids.victor, permission: 'edit' });
  });
});

describe('T09 grant expiry', () => {
  test('an expired grant stops working without anyone acting', async () => {
    const owner = await login(env, 'oscar');
    const vera = await login(env, 'vera');
    const id = env.docs[DOC.memo]!;
    const expiresAt = Date.now() + 1500;
    assert.equal((await owner.post(`/api/documents/${id}/grants`, { userId: env.ids.vera, permission: 'read', expiresAt })).status, 201);
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 200);
    await new Promise((r) => setTimeout(r, 1700));
    assert.equal((await vera.get(`/api/documents/${id}/download`)).status, 404);
    assert.ok(!(await vera.get('/api/documents')).json.documents.some((d: any) => d.id === id));
  });

  test('expiry in the past is rejected', async () => {
    const owner = await login(env, 'oscar');
    const r = await owner.post(`/api/documents/${env.docs[DOC.memo]}/grants`, { userId: env.ids.victor, permission: 'read', expiresAt: Date.now() - 1000 });
    assert.equal(r.status, 400);
  });
});

describe('T08 sessions end when they should', () => {
  test('deactivating a user kills their live sessions at once', async () => {
    const admin = await login(env, 'admin');
    const pat1 = await login(env, 'pat');
    const pat2 = await login(env, 'pat');
    assert.equal((await pat1.get(`/api/documents/${env.docs[DOC.msa]}/download`)).status, 200);
    assert.equal((await admin.patch(`/api/admin/users/${env.ids.pat}`, { active: false })).status, 200);
    assert.equal((await pat1.get(`/api/documents/${env.docs[DOC.msa]}/download`)).status, 401);
    assert.equal((await pat2.get('/api/documents')).status, 401);
    // And they cannot sign back in.
    const again = new Client(env.base);
    assert.equal((await again.post('/api/auth/login', { email: 'pat@partner.example', password: PASSWORD })).status, 401);
    await admin.patch(`/api/admin/users/${env.ids.pat}`, { active: true });
  });

  test('inactive user check does not depend on session revocation alone', async () => {
    // Even if a session row were somehow left un-revoked, active=0 blocks it.
    const pat = await login(env, 'pat');
    env.ctx.db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(env.ids.pat);
    assert.equal((await pat.get('/api/documents')).status, 401);
    env.ctx.db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(env.ids.pat);
  });

  test('a role change takes effect immediately', async () => {
    const admin = await login(env, 'admin');
    const oscar = await login(env, 'oscar');
    await admin.patch(`/api/admin/users/${env.ids.oscar}`, { role: 'viewer' });
    assert.equal((await oscar.get('/api/documents')).status, 401, 'old session revoked');
    const oscar2 = await login(env, 'oscar');
    const r = await oscar2.upload('/api/documents', { title: 'x', category: 'Legal' }, { name: 'a.txt', data: 'hello' });
    assert.equal(r.status, 403, 'viewer role cannot upload');
    await admin.patch(`/api/admin/users/${env.ids.oscar}`, { role: 'owner' });
  });

  test('logout invalidates the token server-side, not just the cookie', async () => {
    const vera = await login(env, 'vera');
    const stolen = vera.cookie;
    await vera.post('/api/auth/logout');
    const attacker = new Client(env.base);
    attacker.cookie = stolen;
    assert.equal((await attacker.get('/api/documents')).status, 401);
  });

  test('changing password ends all other sessions', async () => {
    const a = await login(env, 'victor');
    const b = await login(env, 'victor');
    const r = await a.post('/api/auth/password', { currentPassword: PASSWORD, newPassword: 'Another-Password-456!' });
    assert.equal(r.status, 200);
    assert.equal((await b.get('/api/documents')).status, 401);
    assert.equal((await a.get('/api/documents')).status, 200);
    await a.post('/api/auth/password', { currentPassword: 'Another-Password-456!', newPassword: PASSWORD });
  });

  test('admin password reset ends sessions and forces a change', async () => {
    const admin = await login(env, 'admin');
    const vera = await login(env, 'vera');
    const r = await admin.post(`/api/admin/users/${env.ids.vera}/reset-password`);
    assert.equal(r.status, 200);
    assert.equal((await vera.get('/api/documents')).status, 401);
    const v2 = new Client(env.base);
    assert.equal((await v2.post('/api/auth/login', { email: 'vera@trustvault.demo', password: r.json.temporaryPassword })).status, 200);
    assert.equal((await v2.get('/api/documents')).status, 403, 'must change password before anything else');
    assert.equal((await v2.post('/api/auth/password', { currentPassword: r.json.temporaryPassword, newPassword: PASSWORD })).status, 200);
    assert.equal((await v2.get('/api/documents')).status, 200);
  });

  test('admin can revoke all sessions of a user', async () => {
    const admin = await login(env, 'admin');
    const vera = await login(env, 'vera');
    assert.equal((await admin.post(`/api/admin/users/${env.ids.vera}/revoke-sessions`)).json.sessionsRevoked >= 1, true);
    assert.equal((await vera.get('/api/documents')).status, 401);
  });

  test('idle timeout ends a session', async () => {
    const vera = await login(env, 'vera');
    // Age the session past the idle window.
    env.ctx.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE user_id = ?').run(Date.now() - 31 * 60_000, env.ids.vera);
    assert.equal((await vera.get('/api/documents')).status, 401);
  });

  test('absolute expiry ends a session even if active', async () => {
    const vera = await login(env, 'vera');
    env.ctx.db.prepare('UPDATE sessions SET expires_at = ? WHERE user_id = ?').run(Date.now() - 1, env.ids.vera);
    assert.equal((await vera.get('/api/documents')).status, 401);
  });
});

describe('T12 deleted documents', () => {
  test('soft-deleting removes access for grantees immediately; only the owner can restore', async () => {
    const owner = await login(env, 'oscar');
    const pat = await login(env, 'pat');
    const id = env.docs[DOC.msa]!;
    assert.equal((await pat.get(`/api/documents/${id}/download`)).status, 200);
    assert.equal((await owner.del(`/api/documents/${id}`)).status, 200);
    assert.equal((await pat.get(`/api/documents/${id}/download`)).status, 404);
    assert.equal((await pat.get(`/api/documents/${id}`)).status, 404);
    assert.equal((await owner.get(`/api/documents/${id}/download`)).status, 404, 'even the owner must restore first');
    assert.equal((await pat.post(`/api/documents/${id}/restore`)).status, 404);
    const olivia = await login(env, 'olivia');
    assert.equal((await olivia.post(`/api/documents/${id}/restore`)).status, 404);
    assert.ok((await owner.get('/api/documents/trash')).json.documents.some((d: any) => d.id === id));
    assert.equal((await owner.post(`/api/documents/${id}/restore`)).status, 200);
    assert.equal((await pat.get(`/api/documents/${id}/download`)).status, 200);
  });

  test('T28 purge destroys content but keeps the audit history; strangers cannot purge', async () => {
    const owner = await login(env, 'olivia');
    const up = await owner.upload('/api/documents', { title: 'Temp to purge', category: 'Other' }, { name: 't.txt', data: 'temporary' });
    const id = up.json.document.id;
    const oscar = await login(env, 'oscar');
    await owner.del(`/api/documents/${id}`);
    assert.equal((await oscar.del(`/api/documents/${id}/purge`)).status, 404);
    const keys = env.ctx.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').all(id) as any[];
    assert.equal((await owner.del(`/api/documents/${id}/purge`)).status, 200);
    assert.equal(env.ctx.db.prepare('SELECT 1 FROM documents WHERE id = ?').get(id), undefined);
    const fs = await import('node:fs');
    const path = await import('node:path');
    for (const k of keys) assert.equal(fs.existsSync(path.join(env.ctx.config.dataDir, 'blobs', k.storage_key)), false);
    const history = env.ctx.db.prepare('SELECT action, outcome FROM audit_log WHERE document_id = ? ORDER BY seq').all(id) as any[];
    const successes = history.filter((h: any) => h.outcome === 'success').map((h: any) => h.action);
    assert.deepEqual(successes, ['document.upload', 'document.delete', 'document.purge']);
  });
});

describe('T30 administration guard rails', () => {
  test('the last admin cannot be removed and admins cannot demote themselves', async () => {
    const admin = await login(env, 'admin');
    assert.equal((await admin.patch(`/api/admin/users/${env.ids.admin}`, { role: 'viewer' })).status, 400);
    assert.equal((await admin.patch(`/api/admin/users/${env.ids.admin}`, { active: false })).status, 400);
  });
});
