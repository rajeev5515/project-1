/**
 * Unit tests of the decision function itself, independent of HTTP. These
 * pin down rules that the HTTP layer also enforces elsewhere (e.g. inactive
 * users are rejected by the session middleware too), so that removing the
 * rule from authorizeDocument() is caught even though the HTTP tests would
 * still pass thanks to the other layer.
 */
import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { authorizeDocument, REQUIRED_LEVEL, type DocAction } from '../src/authz.ts';
import { DOC, startEnv, type TestEnv } from './helpers.ts';

let env: TestEnv;
before(async () => {
  env = await startEnv();
});
after(async () => env.close());

const ALL: DocAction[] = Object.keys(REQUIRED_LEVEL) as DocAction[];
const LIVE: DocAction[] = ALL.filter((a) => a !== 'restore' && a !== 'purge');

describe('authorizeDocument', () => {
  test('owner may do every live action', () => {
    for (const a of LIVE) assert.equal(authorizeDocument(env.ctx.db, env.ids.olivia, env.docs[DOC.handbook], a).allowed, true, a);
  });

  test('reader may only view, preview and download', () => {
    const allowed = LIVE.filter((a) => authorizeDocument(env.ctx.db, env.ids.vera, env.docs[DOC.handbook], a).allowed);
    assert.deepEqual(allowed.sort(), ['download', 'preview', 'view']);
  });

  test('editor may view, download, see versions, upload versions and edit metadata — nothing else', () => {
    const allowed = LIVE.filter((a) => authorizeDocument(env.ctx.db, env.ids.victor, env.docs[DOC.handbook], a).allowed);
    assert.deepEqual(allowed.sort(), ['download', 'download_version', 'list_versions', 'preview', 'update_metadata', 'upload_version', 'view']);
  });

  test('a user without a grant gets no_access for every action', () => {
    for (const a of ALL) {
      const r = authorizeDocument(env.ctx.db, env.ids.oscar, env.docs[DOC.veraSalary], a);
      assert.equal(r.allowed, false, a);
      assert.equal(r.allowed === false && r.reason, 'no_access', a);
    }
  });

  test('admin role confers nothing', () => {
    for (const a of ALL) assert.equal(authorizeDocument(env.ctx.db, env.ids.admin, env.docs[DOC.veraSalary], a).allowed, false, a);
  });

  test('an inactive user is refused even by their own document', () => {
    env.ctx.db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(env.ids.oscar);
    try {
      assert.equal(authorizeDocument(env.ctx.db, env.ids.oscar, env.docs[DOC.memo], 'view').allowed, false);
      assert.equal(authorizeDocument(env.ctx.db, env.ids.pat, env.docs[DOC.msa], 'view').allowed, true, 'others unaffected');
    } finally {
      env.ctx.db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(env.ids.oscar);
    }
  });

  test('an inactive grantee is refused', () => {
    env.ctx.db.prepare('UPDATE users SET active = 0 WHERE id = ?').run(env.ids.pat);
    try {
      assert.equal(authorizeDocument(env.ctx.db, env.ids.pat, env.docs[DOC.msa], 'download').allowed, false);
    } finally {
      env.ctx.db.prepare('UPDATE users SET active = 1 WHERE id = ?').run(env.ids.pat);
    }
  });

  test('an expired grant is no grant', () => {
    env.ctx.db.prepare('UPDATE grants SET expires_at = ? WHERE document_id = ? AND user_id = ?').run(Date.now() - 1, env.docs[DOC.msa], env.ids.pat);
    try {
      const r = authorizeDocument(env.ctx.db, env.ids.pat, env.docs[DOC.msa], 'view');
      assert.equal(r.allowed, false);
    } finally {
      env.ctx.db.prepare('UPDATE grants SET expires_at = NULL WHERE document_id = ? AND user_id = ?').run(env.docs[DOC.msa], env.ids.pat);
    }
  });

  test('a deleted document: owner may only restore/purge; grantees get nothing', () => {
    const id = env.docs[DOC.msa];
    env.ctx.db.prepare('UPDATE documents SET deleted_at = ? WHERE id = ?').run(Date.now(), id);
    try {
      for (const a of LIVE) assert.equal(authorizeDocument(env.ctx.db, env.ids.oscar, id, a).allowed, false, `owner ${a}`);
      assert.equal(authorizeDocument(env.ctx.db, env.ids.oscar, id, 'restore').allowed, true);
      assert.equal(authorizeDocument(env.ctx.db, env.ids.oscar, id, 'purge').allowed, true);
      for (const a of ALL) {
        const r = authorizeDocument(env.ctx.db, env.ids.pat, id, a);
        assert.equal(r.allowed, false, `grantee ${a}`);
        assert.equal(r.allowed === false && r.reason, 'deleted', `grantee ${a}`);
      }
    } finally {
      env.ctx.db.prepare('UPDATE documents SET deleted_at = NULL WHERE id = ?').run(id);
    }
  });

  test('restore/purge on a live document is refused', () => {
    assert.equal(authorizeDocument(env.ctx.db, env.ids.oscar, env.docs[DOC.msa], 'restore').allowed, false);
    assert.equal(authorizeDocument(env.ctx.db, env.ids.oscar, env.docs[DOC.msa], 'purge').allowed, false);
  });

  test('unknown document is not_found', () => {
    const r = authorizeDocument(env.ctx.db, env.ids.oscar, '11111111-1111-4111-8111-111111111111', 'view');
    assert.equal(r.allowed === false && r.reason, 'not_found');
  });
});
