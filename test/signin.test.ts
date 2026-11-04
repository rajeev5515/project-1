/**
 * Email one-time-code sign-in, self sign-up, the demo-world wall, and preview.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, DOC, emailLogin, login, settle, signUp, startEnv, auditRows, type TestEnv } from './helpers.ts';

let env: TestEnv;
before(async () => {
  env = await startEnv({ adminEmails: ['boss@acme.test'] });
});
after(async () => env.close());

const start = (c: Client, email: string) => c.post('/api/auth/start', { email });
const verify = (c: Client, challengeId: string, code: string) => c.post('/api/auth/verify', { challengeId, code });

describe('T15 sign-up and sign-in by emailed code', () => {
  test('a new person signs up, gets a code by email, and becomes an owner who can upload', async () => {
    const c = await signUp(env, 'alice@acme.test', 'Alice Real');
    const me = await c.get('/api/auth/me');
    assert.equal(me.json.user.role, 'owner');
    assert.equal(me.json.user.isDemo, false);
    const up = await c.upload('/api/documents', { title: 'Alice plan', category: 'Other' }, { name: 'a.txt', data: 'alice' });
    assert.equal(up.status, 201);
    const mail = env.mail.sent.find((m) => m.to === 'alice@acme.test')!;
    assert.match(mail.text, /\b\d{6}\b/);
    assert.ok(!('demoCode' in (await new Client(env.base).post('/api/auth/start', { email: 'alice@acme.test' })).json), 'real accounts never get the code in the response');
  });

  test('an address listed in TV_ADMIN_EMAILS becomes admin on sign-up', async () => {
    const c = await signUp(env, 'boss@acme.test', 'Boss');
    assert.equal((await c.get('/api/auth/me')).json.user.role, 'admin');
  });

  test('signing in again sends a fresh code to the same inbox', async () => {
    const c = await emailLogin(env, 'alice@acme.test');
    assert.equal((await c.get('/api/auth/me')).json.user.email, 'alice@acme.test');
  });

  test('unknown and known emails get the same answer, and unknown ones are sent nothing', async () => {
    const c = new Client(env.base);
    const before = env.mail.sent.length;
    const a = await start(c, 'nobody-here@acme.test');
    const b = await start(c, 'alice@acme.test');
    await settle();
    assert.equal(a.status, b.status);
    assert.deepEqual(Object.keys(a.json).sort(), Object.keys(b.json).sort());
    assert.equal(a.json.message, b.json.message);
    assert.equal(env.mail.sent.length, before + 1, 'only the real account got an email');
    assert.equal(env.mail.sent.at(-1)!.to, 'alice@acme.test');
  });

  test('sign-up with an existing email cannot take the account over', async () => {
    const attacker = new Client(env.base);
    const r = await attacker.post('/api/auth/signup', { email: 'alice@acme.test', name: 'Mallory' });
    assert.equal(r.status, 200);
    await settle();
    // The code went to Alice's inbox, not to the attacker, and the account is unchanged.
    assert.equal(env.mail.sent.at(-1)!.to, 'alice@acme.test');
    const row = env.ctx.db.prepare("SELECT name, COUNT(*) OVER () AS n FROM users WHERE email = 'alice@acme.test'").get() as any;
    assert.equal(row.name, 'Alice Real');
    assert.equal(row.n, 1);
    // Guessing is all the attacker can do.
    assert.equal((await verify(attacker, r.json.challengeId, '123456')).status, 401);
  });

  test('a wrong code fails; five wrong codes kill the challenge even for the right code', async () => {
    const c = new Client(env.base);
    const s = await start(c, 'alice@acme.test');
    await settle();
    const right = env.mail.lastCodeFor('alice@acme.test')!;
    const wrong = right === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) assert.equal((await verify(c, s.json.challengeId, wrong)).status, 401);
    assert.equal((await verify(c, s.json.challengeId, right)).status, 401);
    assert.equal(auditRows(env, "action = 'auth.verify' AND json_extract(details,'$.reason') = 'too_many_attempts'").length >= 1, true);
  });

  test('a code works once', async () => {
    const c = new Client(env.base);
    const s = await start(c, 'alice@acme.test');
    await settle();
    const code = env.mail.lastCodeFor('alice@acme.test')!;
    assert.equal((await verify(c, s.json.challengeId, code)).status, 200);
    assert.equal((await verify(new Client(env.base), s.json.challengeId, code)).status, 401);
  });

  test('an expired code is refused', async () => {
    const c = new Client(env.base);
    const s = await start(c, 'alice@acme.test');
    await settle();
    const code = env.mail.lastCodeFor('alice@acme.test')!;
    env.ctx.db.prepare('UPDATE login_challenges SET expires_at = ? WHERE id = ?').run(Date.now() - 1, s.json.challengeId);
    assert.equal((await verify(c, s.json.challengeId, code)).status, 401);
  });

  test("a code for one address cannot sign in another (codes are bound to their challenge)", async () => {
    const c = new Client(env.base);
    const mine = await start(c, 'alice@acme.test');
    await settle();
    const aliceCode = env.mail.lastCodeFor('alice@acme.test')!;
    const theirs = await start(c, 'boss@acme.test');
    const r = await verify(c, theirs.json.challengeId, aliceCode);
    assert.equal(r.status, 401);
    assert.ok(mine.json.challengeId !== theirs.json.challengeId);
  });

  test('codes are stored hashed, never in plain text', async () => {
    const c = new Client(env.base);
    const s = await start(c, 'alice@acme.test');
    await settle();
    const code = env.mail.lastCodeFor('alice@acme.test')!;
    const row = env.ctx.db.prepare('SELECT code_hash FROM login_challenges WHERE id = ?').get(s.json.challengeId) as any;
    assert.ok(!row.code_hash.includes(code));
    assert.match(row.code_hash, /^[0-9a-f]{64}$/);
  });

  test('requesting codes for one address is rate limited (real limit: 5 per 15 minutes)', async () => {
    const fresh = await startEnv({ codeRequestsPerEmail: 5, codeRequestsPerIp: 30 });
    try {
      const c = new Client(fresh.base);
      let last = 0;
      for (let i = 0; i < 6; i++) last = (await start(c, 'vera@trustvault.demo')).status;
      assert.equal(last, 429);
    } finally {
      await fresh.close();
    }
  });

  test('a deactivated real user gets no code and cannot sign in', async () => {
    const id = (env.ctx.db.prepare("SELECT id FROM users WHERE email = 'alice@acme.test'").get() as any).id;
    env.ctx.db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(id);
    try {
      const before = env.mail.sent.length;
      await start(new Client(env.base), 'alice@acme.test');
      await settle();
      assert.equal(env.mail.sent.length, before);
    } finally {
      env.ctx.db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(id);
    }
  });

  test('without email configured, real accounts get a clear 503 and demo accounts still work', async () => {
    const { UnconfiguredMailer } = await import('../src/mailer.ts');
    const saved = env.ctx.mailer;
    env.ctx.mailer = new UnconfiguredMailer();
    try {
      assert.equal((await start(new Client(env.base), 'alice@acme.test')).status, 503);
      assert.equal((await start(new Client(env.base), 'nobody@acme.test')).status, 503, 'same answer for unknown addresses');
      assert.equal((await new Client(env.base).post('/api/auth/signup', { email: 'new@acme.test', name: 'N' })).status, 503);
      await login(env, 'vera');
    } finally {
      env.ctx.mailer = saved;
    }
  });
});

describe('T60 demo world wall: public demo accounts can never reach real people', () => {
  test('a real owner cannot share with a demo account, and a demo owner cannot share with a real one', async () => {
    const alice = await emailLogin(env, 'alice@acme.test');
    const up = await alice.upload('/api/documents', { title: 'Real secret', category: 'Legal' }, { name: 's.txt', data: 'real secret' });
    const realDoc = up.json.document.id;
    const r1 = await alice.post(`/api/documents/${realDoc}/grants`, { email: 'vera@trustvault.demo', permission: 'read' });
    assert.equal(r1.status, 400);
    const olivia = await login(env, 'olivia');
    const r2 = await olivia.post(`/api/documents/${env.docs[DOC.handbook]}/grants`, { email: 'alice@acme.test', permission: 'read' });
    assert.equal(r2.status, 400);
    assert.deepEqual(r1.json, r2.json, 'same message as "no such user"');
  });

  test('the directory only shows people in your own world', async () => {
    const olivia = await login(env, 'olivia');
    const d = await olivia.get('/api/users/directory?q=ac');
    assert.ok(d.json.users.every((u: any) => !u.email.endsWith('@acme.test')));
    const alice = await emailLogin(env, 'alice@acme.test');
    const d2 = await alice.get('/api/users/directory?q=tr');
    assert.ok(d2.json.users.every((u: any) => !u.email.endsWith('.demo')));
  });

  test('the demo admin cannot see, change, or move real users or their activity', async () => {
    const admin = await login(env, 'admin');
    const users = (await admin.get('/api/admin/users')).json.users;
    assert.ok(users.every((u: any) => u.isDemo), 'only demo users listed');
    const aliceId = (env.ctx.db.prepare("SELECT id FROM users WHERE email = 'alice@acme.test'").get() as any).id;
    assert.equal((await admin.patch(`/api/admin/users/${aliceId}`, { active: false })).status, 404);
    assert.equal((await admin.post(`/api/admin/users/${aliceId}/revoke-sessions`)).status, 404);
    assert.equal((await admin.post(`/api/admin/users/${aliceId}/transfer-documents`, { toUserId: env.ids.olivia })).status, 404);
    assert.equal((await admin.post('/api/admin/users', { email: 'x@acme.test', name: 'X', role: 'owner' })).status, 403);
    const audit = (await admin.get('/api/admin/audit?limit=500')).json.events;
    assert.ok(audit.every((e: any) => !(e.actor_email ?? '').endsWith('@acme.test')), 'no real-user activity');
    assert.ok(audit.every((e: any) => !JSON.stringify(e.details).includes('Real secret')));
    const grants = (await admin.get('/api/admin/grants')).json.grants;
    assert.ok(grants.every((g: any) => !g.owner_email.endsWith('@acme.test')));
    assert.equal((env.ctx.db.prepare("SELECT active FROM users WHERE id = ?").get(aliceId) as any).active, 1);
  });

  test('a real admin cannot move real documents into the demo world', async () => {
    const boss = await emailLogin(env, 'boss@acme.test');
    const aliceId = (env.ctx.db.prepare("SELECT id FROM users WHERE email = 'alice@acme.test'").get() as any).id;
    const r = await boss.post(`/api/admin/users/${aliceId}/transfer-documents`, { toUserId: env.ids.olivia });
    assert.equal(r.status, 400);
    assert.equal((env.ctx.db.prepare("SELECT COUNT(*) AS n FROM documents WHERE owner_id = ?").get(env.ids.olivia) as any).n >= 1, true);
    assert.equal((env.ctx.db.prepare("SELECT COUNT(*) AS n FROM documents d JOIN users u ON u.id = d.owner_id WHERE u.email='alice@acme.test'").get() as any).n >= 1, true);
  });

  test('real admins can invite real users, who then sign in by email', async () => {
    const boss = await emailLogin(env, 'boss@acme.test');
    const r = await boss.post('/api/admin/users', { email: 'carol@acme.test', name: 'Carol', role: 'viewer' });
    assert.equal(r.status, 201);
    assert.equal(r.json.user.isDemo, false);
    const carol = await emailLogin(env, 'carol@acme.test');
    assert.equal((await carol.get('/api/auth/me')).json.user.role, 'viewer');
  });
});

describe('T17b in-app preview', () => {
  test('reader can preview; it is audited as a preview, separately from downloads', async () => {
    const vera = await login(env, 'vera');
    const id = env.docs[DOC.veraSalary];
    const r = await vera.get(`/api/documents/${id}/preview`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('x-trustvault-mime'), 'application/pdf');
    assert.equal(r.headers.get('content-type'), 'application/octet-stream');
    assert.match(r.headers.get('content-disposition')!, /^attachment/);
    assert.ok(r.body.toString('latin1').startsWith('%PDF'));
    const row = auditRows(env, "action = 'document.preview' AND document_id = ?", id).at(-1);
    assert.equal(row.actor_id, env.ids.vera);
  });

  test('strangers cannot preview (404) and the refusal is audited', async () => {
    const victor = await login(env, 'victor');
    const id = env.docs[DOC.veraSalary];
    assert.equal((await victor.get(`/api/documents/${id}/preview`)).status, 404);
    assert.ok(auditRows(env, "action = 'document.preview' AND outcome = 'denied' AND actor_id = ?", env.ids.victor).length >= 1);
  });

  test('office files are not previewable', async () => {
    const olivia = await login(env, 'olivia');
    const docx = Buffer.concat([Buffer.from('PK\x03\x04'), Buffer.from('....[Content_Types].xml....')]);
    const up = await olivia.upload('/api/documents', { title: 'Word file', category: 'Other' }, { name: 'w.docx', data: docx });
    assert.equal(up.status, 201);
    assert.equal((await olivia.get(`/api/documents/${up.json.document.id}/preview`)).status, 415);
  });
});
