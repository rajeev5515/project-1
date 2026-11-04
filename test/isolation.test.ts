/**
 * One user cannot reach another user's documents, through any route.
 * Test names carry the THREATS.md id they cover.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client, DOC, login, PDF, startEnv, auditRows, type TestEnv } from './helpers.ts';

let env: TestEnv;
before(async () => {
  env = await startEnv();
});
after(async () => env.close());

/** Every route that takes a document id, with the method, as a stranger would call it. */
function allDocumentRoutes(docId: string, extra: { versionId?: string; grantId?: string; suggestionId?: string } = {}) {
  const v = extra.versionId ?? '00000000-0000-4000-8000-000000000000';
  const g = extra.grantId ?? '00000000-0000-4000-8000-000000000000';
  const s = extra.suggestionId ?? '00000000-0000-4000-8000-000000000000';
  return [
    ['GET', `/api/documents/${docId}`],
    ['GET', `/api/documents/${docId}/download`],
    ['GET', `/api/documents/${docId}/versions`],
    ['GET', `/api/documents/${docId}/versions/${v}/download`],
    ['PATCH', `/api/documents/${docId}`, { title: 'pwned' }],
    ['DELETE', `/api/documents/${docId}`],
    ['POST', `/api/documents/${docId}/restore`],
    ['DELETE', `/api/documents/${docId}/purge`],
    ['GET', `/api/documents/${docId}/grants`],
    ['POST', `/api/documents/${docId}/grants`, { email: 'oscar@trustvault.demo', permission: 'edit' }],
    ['DELETE', `/api/documents/${docId}/grants/${g}`],
    ['GET', `/api/documents/${docId}/activity`],
    ['POST', `/api/documents/${docId}/suggestions`],
    ['POST', `/api/documents/${docId}/suggestions/${s}/dismiss`],
  ] as const;
}

async function call(c: Client, [method, url, body]: readonly [string, string, unknown?]) {
  if (method === 'GET') return c.get(url);
  if (method === 'DELETE') return c.del(url);
  if (method === 'PATCH') return c.patch(url, body);
  return c.post(url, body ?? {});
}

describe('T01 IDOR: a stranger gets nothing from any document route', () => {
  for (const who of ['oscar', 'victor', 'pat', 'admin']) {
    test(`${who} cannot reach Vera's salary letter through any route`, async () => {
      const c = await login(env, who);
      const docId = env.docs[DOC.veraSalary]!;
      const version = env.ctx.db.prepare('SELECT current_version_id AS v FROM documents WHERE id = ?').get(docId) as { v: string };
      const grant = env.ctx.db.prepare('SELECT id FROM grants WHERE document_id = ?').get(docId) as { id: string };
      for (const route of allDocumentRoutes(docId, { versionId: version.v, grantId: grant.id })) {
        const r = await call(c, route);
        assert.equal(r.status, 404, `${who} ${route[0]} ${route[1]} returned ${r.status}`);
        assert.ok(!r.body.toString('latin1').includes('CONFIDENTIAL'), 'no file bytes in response');
        assert.ok(!JSON.stringify(r.json ?? {}).includes('Salary'), 'no title in response');
      }
      // Nothing changed as a side effect.
      const doc = env.ctx.db.prepare('SELECT title, deleted_at, owner_id FROM documents WHERE id = ?').get(docId) as any;
      assert.equal(doc.title, DOC.veraSalary);
      assert.equal(doc.deleted_at, null);
      assert.equal(doc.owner_id, env.ids.olivia);
      const grants = env.ctx.db.prepare('SELECT user_id FROM grants WHERE document_id = ?').all(docId) as any[];
      assert.deepEqual(grants.map((g) => g.user_id), [env.ids.vera]);
    });
  }

  test('a non-existent id and a forbidden id are indistinguishable', async () => {
    const c = await login(env, 'victor');
    const forbidden = await c.get(`/api/documents/${env.docs[DOC.veraSalary]}`);
    const missing = await c.get('/api/documents/11111111-1111-4111-8111-111111111111');
    assert.equal(forbidden.status, missing.status);
    assert.deepEqual(forbidden.json, missing.json);
  });

  test('malformed ids do not error or leak', async () => {
    const c = await login(env, 'victor');
    for (const id of ["' OR 1=1 --", '..%2F..%2Fetc%2Fpasswd', 'x'.repeat(500), '%00']) {
      const r = await c.get(`/api/documents/${encodeURIComponent(id)}/download`);
      assert.equal(r.status, 404);
    }
  });
});

describe('T23 unauthenticated callers get nothing', () => {
  test('every document route requires a session', async () => {
    const anon = new Client(env.base);
    for (const route of allDocumentRoutes(env.docs[DOC.veraSalary]!)) {
      const r = await call(anon, route);
      assert.equal(r.status, 401, `${route[0]} ${route[1]}`);
    }
    for (const url of ['/api/documents', '/api/documents/trash', '/api/users/directory?q=ve', '/api/admin/audit', '/api/admin/users']) {
      assert.equal((await anon.get(url)).status, 401, url);
    }
  });

  test('a forged or random session cookie is not a session', async () => {
    const c = new Client(env.base);
    c.cookie = 'tv_session=' + 'A'.repeat(43);
    assert.equal((await c.get('/api/documents')).status, 401);
  });
});

describe('T02 list and search only return documents the caller can reach', () => {
  test('viewer sees exactly their grants', async () => {
    const c = await login(env, 'vera');
    const r = await c.get('/api/documents');
    const titles = r.json.documents.map((d: any) => d.title).sort();
    assert.deepEqual(titles, [DOC.handbook, DOC.veraSalary].sort());
  });

  test('search by name, owner, category and date never widens the set', async () => {
    const c = await login(env, 'victor');
    const queries = ['q=Salary', 'owner=olivia', 'category=HR', 'from=2000-01-01&to=2999-01-01', 'q=%25', 'q=_', "q='", 'scope=all', 'owner=oscar', 'q=memo'];
    for (const qs of queries) {
      const r = await c.get(`/api/documents?${qs}`);
      assert.equal(r.status, 200, qs);
      for (const d of r.json.documents) {
        assert.ok([DOC.victorSalary, DOC.handbook].includes(d.title), `${qs} leaked ${d.title}`);
      }
    }
    const salary = await c.get('/api/documents?q=Salary');
    assert.deepEqual(salary.json.documents.map((d: any) => d.title), [DOC.victorSalary]);
  });

  test('search works on each field for an owner', async () => {
    const c = await login(env, 'oscar');
    assert.equal((await c.get('/api/documents?q=litigation')).json.documents.length, 1);
    assert.equal((await c.get('/api/documents?category=Contracts')).json.documents.length, 1);
    assert.equal((await c.get('/api/documents?owner=oscar')).json.documents.length, 2);
    assert.equal((await c.get('/api/documents?owner=olivia')).json.documents.length, 0);
    assert.equal((await c.get('/api/documents?to=2000-01-01')).json.documents.length, 0);
    assert.equal((await c.get('/api/documents?category=NotACategory')).status, 400);
  });

  test('admin role does not see documents in the list', async () => {
    const c = await login(env, 'admin');
    assert.equal((await c.get('/api/documents')).json.documents.length, 0);
  });
});

describe('T04 a read grant does not allow more than reading', () => {
  test('reader can view and download the current version', async () => {
    const c = await login(env, 'vera');
    const id = env.docs[DOC.veraSalary]!;
    const meta = await c.get(`/api/documents/${id}`);
    assert.equal(meta.status, 200);
    assert.equal(meta.json.document.access, 'read');
    const dl = await c.get(`/api/documents/${id}/download`);
    assert.equal(dl.status, 200);
    assert.ok(dl.body.toString('latin1').includes('CONFIDENTIAL Salary letter for Vera'));
  });

  test('reader cannot edit, version, delete, share, or see activity', async () => {
    const c = await login(env, 'vera');
    const id = env.docs[DOC.veraSalary]!;
    assert.equal((await c.patch(`/api/documents/${id}`, { title: 'changed' })).status, 403);
    assert.equal((await c.upload(`/api/documents/${id}/versions`, {}, { name: 'x.pdf', data: PDF })).status, 403);
    assert.equal((await c.get(`/api/documents/${id}/versions`)).status, 403);
    assert.equal((await c.del(`/api/documents/${id}`)).status, 403);
    assert.equal((await c.get(`/api/documents/${id}/grants`)).status, 403);
    assert.equal((await c.post(`/api/documents/${id}/grants`, { email: 'victor@trustvault.demo', permission: 'read' })).status, 403);
    assert.equal((await c.get(`/api/documents/${id}/activity`)).status, 403);
    assert.equal((await c.post(`/api/documents/${id}/suggestions`)).status, 403);
    const doc = env.ctx.db.prepare('SELECT title, deleted_at FROM documents WHERE id = ?').get(id) as any;
    assert.equal(doc.title, DOC.veraSalary);
    assert.equal(doc.deleted_at, null);
    assert.equal((env.ctx.db.prepare('SELECT COUNT(*) AS n FROM grants WHERE document_id = ?').get(id) as any).n, 1);
  });

  test('reader cannot download an older version even with its id', async () => {
    // Olivia uploads v2 of the handbook; Vera (read) must not fetch v1 by id.
    const owner = await login(env, 'olivia');
    const id = env.docs[DOC.handbook]!;
    const v1 = (env.ctx.db.prepare('SELECT id FROM document_versions WHERE document_id = ? AND version_no = 1').get(id) as any).id;
    const up = await owner.upload(`/api/documents/${id}/versions`, {}, { name: 'handbook.txt', data: 'Handbook v2\n' });
    assert.equal(up.status, 201);
    const vera = await login(env, 'vera');
    assert.equal((await vera.get(`/api/documents/${id}/versions/${v1}/download`)).status, 403);
    const cur = await vera.get(`/api/documents/${id}/download`);
    assert.equal(cur.body.toString(), 'Handbook v2\n');
  });
});

describe('T05 an edit grant allows editing but not sharing or deleting', () => {
  test('editor can change metadata and upload a version', async () => {
    const c = await login(env, 'victor');
    const id = env.docs[DOC.handbook]!;
    const r = await c.patch(`/api/documents/${id}`, { description: 'edited by victor' });
    assert.equal(r.status, 200);
    assert.equal(r.json.document.description, 'edited by victor');
    const up = await c.upload(`/api/documents/${id}/versions`, {}, { name: 'handbook.txt', data: 'Handbook v3 by Victor\n' });
    assert.equal(up.status, 201);
    assert.equal((await c.get(`/api/documents/${id}/versions`)).status, 200);
  });

  test('editor cannot re-share, revoke, delete, purge or see activity', async () => {
    const c = await login(env, 'victor');
    const id = env.docs[DOC.handbook]!;
    assert.equal((await c.post(`/api/documents/${id}/grants`, { email: 'pat@partner.example', permission: 'read' })).status, 403);
    const veraGrant = (env.ctx.db.prepare('SELECT id FROM grants WHERE document_id = ? AND user_id = ?').get(id, env.ids.vera) as any).id;
    assert.equal((await c.del(`/api/documents/${id}/grants/${veraGrant}`)).status, 403);
    assert.equal((await c.del(`/api/documents/${id}`)).status, 403);
    assert.equal((await c.get(`/api/documents/${id}/activity`)).status, 403);
    assert.equal((await c.get(`/api/documents/${id}/grants`)).status, 403);
    assert.ok(env.ctx.db.prepare('SELECT 1 FROM grants WHERE id = ?').get(veraGrant));
  });

  test('editor cannot change ownership or other protected fields (T13 mass assignment)', async () => {
    const c = await login(env, 'victor');
    const id = env.docs[DOC.handbook]!;
    for (const body of [{ owner_id: env.ids.victor }, { ownerId: env.ids.victor }, { deleted_at: 1 }, { title: 'ok', owner_id: env.ids.victor }]) {
      assert.equal((await c.patch(`/api/documents/${id}`, body)).status, 400);
    }
    assert.equal((env.ctx.db.prepare('SELECT owner_id FROM documents WHERE id = ?').get(id) as any).owner_id, env.ids.olivia);
  });
});

describe('T03 version ids are bound to their document', () => {
  test('edit access to one document does not unlock another document\'s version', async () => {
    // Victor can edit the handbook. Try to fetch the salary letter of Vera via its version id.
    const c = await login(env, 'victor');
    const handbook = env.docs[DOC.handbook]!;
    const foreignVersion = (env.ctx.db.prepare('SELECT current_version_id AS v FROM documents WHERE id = ?').get(env.docs[DOC.veraSalary]) as any).v;
    const r = await c.get(`/api/documents/${handbook}/versions/${foreignVersion}/download`);
    assert.equal(r.status, 404);
    assert.ok(!r.body.toString('latin1').includes('CONFIDENTIAL'));
  });
});

describe('T06 grant ids are bound to their document', () => {
  test('an owner cannot revoke a grant on someone else\'s document through their own', async () => {
    const oscar = await login(env, 'oscar');
    const ownDoc = env.docs[DOC.memo]!;
    const foreignGrant = (env.ctx.db.prepare('SELECT id FROM grants WHERE document_id = ?').get(env.docs[DOC.veraSalary]) as any).id;
    assert.equal((await oscar.del(`/api/documents/${ownDoc}/grants/${foreignGrant}`)).status, 404);
    assert.ok(env.ctx.db.prepare('SELECT 1 FROM grants WHERE id = ?').get(foreignGrant));
  });

  test('an owner cannot attach a suggestion from another document to a grant (T25)', async () => {
    const olivia = await login(env, 'olivia');
    const s = await olivia.post(`/api/documents/${env.docs[DOC.victorSalary]}/suggestions`);
    assert.equal(s.status, 200);
    const oscar = await login(env, 'oscar');
    const r = await oscar.post(`/api/documents/${env.docs[DOC.memo]}/grants`, { email: 'vera@trustvault.demo', permission: 'read', suggestionId: s.json.suggestionId });
    assert.equal(r.status, 400);
  });
});

describe('T11 role checks', () => {
  test('viewer cannot upload new documents', async () => {
    const c = await login(env, 'vera');
    const r = await c.upload('/api/documents', { title: 'x', category: 'HR' }, { name: 'x.pdf', data: PDF });
    assert.equal(r.status, 403);
  });

  test('admin cannot upload (admins do not own documents)', async () => {
    const c = await login(env, 'admin');
    assert.equal((await c.upload('/api/documents', { title: 'x', category: 'HR' }, { name: 'x.pdf', data: PDF })).status, 403);
  });

  test('non-admins cannot call any admin endpoint', async () => {
    for (const who of ['olivia', 'vera']) {
      const c = await login(env, who);
      for (const [m, u] of [
        ['GET', '/api/admin/users'],
        ['POST', '/api/admin/users'],
        ['PATCH', `/api/admin/users/${env.ids.vera}`],
        ['POST', `/api/admin/users/${env.ids.vera}/reset-password`],
        ['POST', `/api/admin/users/${env.ids.vera}/revoke-sessions`],
        ['POST', `/api/admin/users/${env.ids.oscar}/transfer-documents`],
        ['GET', '/api/admin/audit'],
        ['GET', '/api/admin/audit/verify'],
        ['GET', '/api/admin/alerts'],
        ['GET', '/api/admin/grants'],
        ['GET', '/api/admin/stats'],
      ] as const) {
        const r = m === 'GET' ? await c.get(u) : m === 'PATCH' ? await c.patch(u, { role: 'admin' }) : await c.post(u, { toUserId: env.ids[who] });
        assert.equal(r.status, 403, `${who} ${m} ${u}`);
      }
    }
    assert.equal((env.ctx.db.prepare('SELECT role FROM users WHERE id = ?').get(env.ids.vera) as any).role, 'viewer');
  });

  test('T27 viewers cannot enumerate the user directory', async () => {
    const c = await login(env, 'vera');
    assert.equal((await c.get('/api/users/directory?q=tr')).status, 403);
    const o = await login(env, 'olivia');
    const r = await o.get('/api/users/directory?q=vi');
    assert.equal(r.status, 200);
    assert.ok(r.json.users.every((u: any) => !('password_hash' in u)));
  });
});

describe('T10 administrators cannot read document content', () => {
  test('admin gets 404 on download and metadata of every document', async () => {
    const c = await login(env, 'admin');
    for (const id of Object.values(env.docs)) {
      assert.equal((await c.get(`/api/documents/${id}/download`)).status, 404);
      assert.equal((await c.get(`/api/documents/${id}`)).status, 404);
    }
  });

  test('T29 admin cannot transfer documents to themselves or a non-owner', async () => {
    const c = await login(env, 'admin');
    assert.equal((await c.post(`/api/admin/users/${env.ids.oscar}/transfer-documents`, { toUserId: env.ids.admin })).status, 400);
    assert.equal((await c.post(`/api/admin/users/${env.ids.oscar}/transfer-documents`, { toUserId: env.ids.vera })).status, 400);
    assert.equal((env.ctx.db.prepare('SELECT owner_id FROM documents WHERE id = ?').get(env.docs[DOC.memo]) as any).owner_id, env.ids.oscar);
  });
});

describe('T19 refused attempts are in the audit trail', () => {
  test('a stranger\'s download attempt is recorded as denied with who, what and when', async () => {
    const c = await login(env, 'pat');
    const id = env.docs[DOC.memo]!;
    const beforeCount = auditRows(env, "action = 'document.download' AND outcome = 'denied' AND document_id = ?", id).length;
    const t0 = Date.now();
    await c.get(`/api/documents/${id}/download`);
    const rows = auditRows(env, "action = 'document.download' AND outcome = 'denied' AND document_id = ?", id);
    assert.equal(rows.length, beforeCount + 1);
    const row = rows.at(-1);
    assert.equal(row.actor_id, env.ids.pat);
    assert.equal(row.actor_email, 'pat@partner.example');
    assert.ok(row.ts >= t0);
    assert.equal(JSON.parse(row.details).reason, 'no_access');
  });

  test('successful downloads are recorded with the version', async () => {
    const c = await login(env, 'pat');
    const id = env.docs[DOC.msa]!;
    await c.get(`/api/documents/${id}/download`);
    const row = auditRows(env, "action = 'document.download' AND outcome = 'success' AND document_id = ?", id).at(-1);
    assert.equal(row.actor_id, env.ids.pat);
    assert.ok(JSON.parse(row.details).versionId);
  });
});
