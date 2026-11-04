/**
 * Mutation check for authorisation and audit code.
 *
 * The brief says: "We will take one authorisation check out of your code and
 * run your tests. If they still pass, they were not testing anything." This
 * script does exactly that, for every check we know about: it applies one
 * mutation at a time (removing or weakening a check), runs the test suite,
 * and expects it to FAIL. A mutation that survives (tests still pass) is a
 * hole in the tests and is reported.
 *
 *   npm run mutate                     # all mutations
 *   npm run mutate -- share            # only mutations whose id contains "share"
 *   npm run mutate -- --start bind-    # resume from the first id starting with "bind-"
 *
 * Mutations are applied to a throwaway copy of the repository in the OS temp
 * directory, never to the working tree, so a weakened check can never be
 * committed by accident.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import os from 'node:os';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'tv-mutate-'));
for (const entry of ['src', 'test', 'scripts', 'package.json', 'tsconfig.json']) {
  fs.cpSync(path.join(repo, entry), path.join(root, entry), { recursive: true });
}
fs.symlinkSync(path.join(repo, 'node_modules'), path.join(root, 'node_modules'));

interface Mutation {
  id: string;
  file: string;
  find: string;
  replace: string;
  why: string;
}

const M: Mutation[] = [
  // ---- the decision function
  { id: 'authz-no-access-null', file: 'src/authz.ts', find: "if (access === null) return { allowed: false, reason: 'no_access', access: null };", replace: '', why: 'no grant is treated as access' },
  { id: 'authz-rank', file: 'src/authz.ts', find: 'if (RANK[access] < RANK[REQUIRED_LEVEL[action]])', replace: 'if (false)', why: 'any grant allows any action' },
  { id: 'authz-deleted', file: 'src/authz.ts', find: "if (doc.deleted_at !== null && (access !== 'owner' || !isTrashAction))", replace: 'if (false)', why: 'deleted documents stay reachable' },
  { id: 'authz-deleted-grantee-trash', file: 'src/authz.ts', find: "(access !== 'owner' || !isTrashAction)", replace: '(!isTrashAction)', why: 'grantee learns a document is in the trash' },
  { id: 'authz-expiry', file: 'src/authz.ts', find: 'AND (g.expires_at IS NULL OR g.expires_at > :now)', replace: '', why: 'expired grants keep working' },
  { id: 'authz-grant-user', file: 'src/authz.ts', find: 'WHERE g.document_id = d.id AND g.user_id = :uid', replace: 'WHERE g.document_id = d.id', why: "anyone's grant counts as yours" },
  { id: 'authz-caller-active', file: 'src/authz.ts', find: 'JOIN users caller ON caller.id = :uid AND caller.active = 1\n       WHERE d.id = :docId', replace: 'JOIN users caller ON caller.id = :uid\n       WHERE d.id = :docId', why: 'deactivated users pass the decision function' },
  { id: 'level-download_version', file: 'src/authz.ts', find: "download_version: 'edit'", replace: "download_version: 'read'", why: 'readers fetch old versions' },
  { id: 'level-list_versions', file: 'src/authz.ts', find: "list_versions: 'edit'", replace: "list_versions: 'read'", why: 'readers list versions' },
  { id: 'level-upload_version', file: 'src/authz.ts', find: "upload_version: 'edit'", replace: "upload_version: 'read'", why: 'readers replace content' },
  { id: 'level-update_metadata', file: 'src/authz.ts', find: "update_metadata: 'edit'", replace: "update_metadata: 'read'", why: 'readers rename documents' },
  { id: 'level-delete', file: 'src/authz.ts', find: "delete: 'owner'", replace: "delete: 'edit'", why: 'editors delete' },
  { id: 'level-share', file: 'src/authz.ts', find: "share: 'owner'", replace: "share: 'edit'", why: 'editors re-share' },
  { id: 'level-view_activity', file: 'src/authz.ts', find: "view_activity: 'owner'", replace: "view_activity: 'edit'", why: 'editors read the access log' },
  { id: 'level-restore', file: 'src/authz.ts', find: "restore: 'owner'", replace: "restore: 'read'", why: 'grantees restore' },
  // ---- route gate and bindings
  { id: 'gate-allowed', file: 'src/routes/documents.ts', find: 'if (!result.allowed) {', replace: 'if (false && !result.allowed) {', why: 'gate lets everyone through' },
  { id: 'gate-deny-audit', file: 'src/routes/documents.ts', find: "        action: `document.${action}`,\n        outcome: 'denied',", replace: "        action: `document.${action}`,\n        outcome: 'success',", why: 'refusals not recorded as refusals' },
  { id: 'gate-404', file: 'src/routes/documents.ts', find: "if (result.reason === 'insufficient') {", replace: 'if (true) {', why: 'existence leaks via 403 vs 404' },
  { id: 'route-patch-level', file: 'src/routes/documents.ts', find: "gate(req, 'update_metadata')", replace: "gate(req, 'view')", why: 'PATCH only needs read' },
  { id: 'route-grant-level', file: 'src/routes/documents.ts', find: "  r.post('/:id/grants', (req, res) => {\n    const { doc } = gate(req, 'share');", replace: "  r.post('/:id/grants', (req, res) => {\n    const { doc } = gate(req, 'view');", why: 'readers grant access' },
  { id: 'route-revoke-level', file: 'src/routes/documents.ts', find: "  r.delete('/:id/grants/:grantId', (req, res) => {\n    const { doc } = gate(req, 'share');", replace: "  r.delete('/:id/grants/:grantId', (req, res) => {\n    const { doc } = gate(req, 'view');", why: 'readers revoke access' },
  { id: 'route-delete-level', file: 'src/routes/documents.ts', find: "gate(req, 'delete')", replace: "gate(req, 'view')", why: 'readers delete' },
  { id: 'control-noop', file: 'src/app.ts', find: "message: 'Something went wrong'", replace: "message: 'Something went wrong.'", why: 'CONTROL: cosmetic change; tests must still pass (proves the harness does not fail everything)' },
  { id: 'route-version-download-level', file: 'src/routes/documents.ts', find: "gate(req, 'download_version')", replace: "gate(req, 'download')", why: 'readers download old versions' },
  { id: 'route-activity-level', file: 'src/routes/documents.ts', find: "gate(req, 'view_activity')", replace: "gate(req, 'view')", why: 'readers see the access log' },
  { id: 'route-suggest-level', file: 'src/routes/documents.ts', find: "  r.post('/:id/suggestions', async (req, res) => {\n    const { doc } = gate(req, 'share');", replace: "  r.post('/:id/suggestions', async (req, res) => {\n    const { doc } = gate(req, 'view');", why: 'readers trigger suggestions' },
  { id: 'bind-version', file: 'src/routes/documents.ts', find: "SELECT * FROM document_versions WHERE id = ? AND document_id = ?').get(req.params.versionId, doc.id)", replace: "SELECT * FROM document_versions WHERE id = ? AND ? IS NOT NULL').get(req.params.versionId, doc.id)", why: 'version id from another document accepted' },
  { id: 'bind-grant', file: 'src/routes/documents.ts', find: "SELECT * FROM grants WHERE id = ? AND document_id = ?').get(req.params.grantId, doc.id)", replace: "SELECT * FROM grants WHERE id = ? AND ? IS NOT NULL').get(req.params.grantId, doc.id)", why: 'grant on another document revoked' },
  { id: 'bind-suggestion', file: 'src/routes/documents.ts', find: "SELECT id, suggestions FROM ai_suggestions WHERE id = ? AND document_id = ?').get(body.suggestionId, doc.id)", replace: "SELECT id, suggestions FROM ai_suggestions WHERE id = ? AND ? IS NOT NULL').get(body.suggestionId, doc.id)", why: 'suggestion from another document accepted' },
  { id: 'list-filter', file: 'src/routes/documents.ts', find: 'WHERE a.access IS NOT NULL', replace: 'WHERE 1=1', why: 'search returns everything' },
  { id: 'mass-assignment', file: 'src/routes/documents.ts', find: "onlyKeys(req.body, ['title', 'category', 'description'])", replace: '(req.body as Record<string, unknown>)', why: 'unknown fields silently accepted' },
  { id: 'upload-role', file: 'src/routes/documents.ts', find: "r.post('/', requireRole('owner'), async", replace: "r.post('/', async", why: 'viewers/admins upload' },
  { id: 'download-octet', file: 'src/routes/documents.ts', find: "res.setHeader('Content-Type', 'application/octet-stream');", replace: "res.setHeader('Content-Type', v.mime_type);", why: 'downloads may render inline' },
  { id: 'download-attachment', file: 'src/routes/documents.ts', find: "`attachment; filename=", replace: '`inline; filename=', why: 'downloads render inline' },
  // ---- roles, sessions, CSRF
  { id: 'admin-role', file: 'src/routes/admin.ts', find: "r.use(requireAuth, requireRole('admin'));", replace: 'r.use(requireAuth);', why: 'anyone uses admin endpoints' },
  { id: 'directory-role', file: 'src/routes/admin.ts', find: "r.get('/directory', requireRole('owner', 'admin'),", replace: "r.get('/directory',", why: 'viewers enumerate users' },
  { id: 'transfer-recipient', file: 'src/routes/admin.ts', find: "if (to.role !== 'owner' || to.active !== 1)", replace: 'if (to.active !== 1)', why: 'admin transfers documents to self' },
  { id: 'deactivate-revoke', file: 'src/routes/admin.ts', find: 'const n = changes.active || changes.role ? revokeAllSessions(ctx, target.id) : 0;', replace: 'const n = 0;', why: 'role change keeps old sessions' },
  { id: 'last-admin', file: 'src/routes/admin.ts', find: "if (target.id === req.user!.id && (role !== target.role || !active))", replace: 'if (false)', why: 'admin locks everyone out' },
  { id: 'session-revoked', file: 'src/auth.ts', find: 'row.revoked_at !== null ||', replace: '', why: 'logged-out tokens still work' },
  { id: 'session-idle', file: 'src/auth.ts', find: 'row.last_seen_at + idleMs <= now ||', replace: '', why: 'no idle timeout' },
  { id: 'session-expiry', file: 'src/auth.ts', find: 'row.expires_at <= now ||', replace: '', why: 'no absolute expiry' },
  { id: 'session-active', file: 'src/auth.ts', find: "row.active !== 1\n    ) {", replace: 'false\n    ) {', why: 'deactivated users keep sessions (authz still blocks docs)' },
  { id: 'csrf-header', file: 'src/auth.ts', find: "if (req.get(CSRF_HEADER) !== '1') {", replace: 'if (false) {', why: 'no anti-forgery header required' },
  { id: 'csrf-origin', file: 'src/auth.ts', find: 'if (origin !== expected)', replace: 'if (false)', why: 'cross-origin requests accepted' },
  // ---- email-code sign-in
  { id: 'otp-attempts', file: 'src/routes/auth.ts', find: 'if (ch.attempts >= MAX_ATTEMPTS)', replace: 'if (false)', why: 'unlimited guesses per code' },
  { id: 'otp-expiry', file: 'src/routes/auth.ts', find: 'if (ch.expires_at <= Date.now())', replace: 'if (false)', why: 'codes never expire' },
  { id: 'otp-single-use', file: 'src/routes/auth.ts', find: 'WHERE id = ? AND consumed_at IS NULL', replace: 'WHERE id = ?', why: 'a code can be replayed' },
  { id: 'otp-compare', file: 'src/routes/auth.ts', find: 'if (!timingSafeEqual(expected, actual)) {', replace: 'if (false) {', why: 'any code is accepted' },
  { id: 'otp-demo-only-display', file: 'src/routes/auth.ts', find: 'if (usable && user!.is_demo === 1) {', replace: 'if (usable) {', why: 'real accounts get their code in the HTTP response' },
  { id: 'otp-inactive', file: 'src/routes/auth.ts', find: "if (user.active !== 1) throw fail('inactive', ch.email);", replace: '', why: 'deactivated users sign in with a code issued earlier' },
  { id: 'otp-rate-email', file: 'src/routes/auth.ts', find: 'if (!perIpStart.hit(ip(req)) || !perEmail.hit(email)) {', replace: 'if (!perIpStart.hit(ip(req))) {', why: 'unlimited codes per address' },
  // ---- demo world wall
  { id: 'world-grant', file: 'src/routes/documents.ts', find: ' || (target.is_demo === 1) !== req.user!.isDemo', replace: '', why: 'real documents shared into the public demo world' },
  { id: 'world-directory', file: 'src/routes/admin.ts', find: 'AND is_demo = ? AND', replace: 'AND ? IS NOT NULL AND', why: 'directory shows the other world' },
  { id: 'world-admin-users', file: 'src/routes/admin.ts', find: '|| (caller.isDemo && u.is_demo !== 1)', replace: '', why: 'demo admin manages real users' },
  { id: 'world-admin-list', file: 'src/routes/admin.ts', find: "${req.user!.isDemo ? 'WHERE is_demo = 1' : ''}", replace: '', why: 'demo admin lists real users' },
  { id: 'world-admin-audit', file: 'src/routes/admin.ts', find: "(u.isDemo ? DEMO_AUDIT_SCOPE : '')", replace: "('')", why: 'demo admin reads real activity' },
  { id: 'world-admin-grants', file: 'src/routes/admin.ts', find: "${req.user!.isDemo ? 'AND o.is_demo = 1' : ''}", replace: '', why: 'demo admin sees real grants' },
  { id: 'world-transfer', file: 'src/routes/admin.ts', find: "    if (to.is_demo !== from.is_demo) throw new ValidationError('Documents cannot move between demo and real accounts');\n", replace: '', why: 'real documents moved into the demo world' },
  { id: 'world-demo-invite', file: 'src/routes/admin.ts', find: "if (req.user!.isDemo) throw new HttpError(403, 'forbidden', 'The demo administrator cannot create accounts');", replace: '', why: 'demo admin squats real addresses' },
  // ---- preview
  { id: 'preview-types', file: 'src/routes/documents.ts', find: 'if (!PREVIEWABLE.has(v.mime_type))', replace: 'if (false)', why: 'office files previewed' },
  { id: 'preview-audit', file: 'src/routes/documents.ts', find: "      action: 'document.preview',\n      outcome: 'success',", replace: "      action: 'document.download',\n      outcome: 'success',", why: 'previews indistinguishable from downloads in the record' },
  // ---- audit
  { id: 'audit-trigger-update', file: 'src/db.ts', find: "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log\nBEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;", replace: '', why: 'audit rows editable' },
  { id: 'audit-verify-hash', file: 'src/audit.ts', find: "if (a.length !== b.length || !timingSafeEqual(a, b)) return fail('row content does not match its hash');", replace: '', why: 'edited rows verify' },
  { id: 'audit-verify-truncation', file: 'src/audit.ts', find: 'if (head.seq < expectedHead.seq) {', replace: 'if (false) {', why: 'truncation not detected' },
  { id: 'audit-sink', file: 'src/audit.ts', find: 'this.sink({ seq, hash, ts: base.ts });', replace: '', why: 'head never leaves the database' },
  // ---- uploads and AI
  { id: 'upload-magic', file: 'src/validation.ts', find: 'if (!type.matches(data))', replace: 'if (false)', why: 'content not checked against extension' },
  { id: 'upload-path-strip', file: 'src/validation.ts', find: "name = name.split(/[\\\\/]/).pop() ?? '';", replace: '', why: 'path components kept in filename' },
  { id: 'ai-candidates', file: 'src/suggest.ts', find: 'WHERE d.owner_id = :ownerId', replace: 'WHERE 1=1', why: "suggestions drawn from other owners' sharing" },
  { id: 'ai-personal-docs', file: 'src/suggest.ts', find: 'AND (SELECT COUNT(*) FROM grants g2 WHERE g2.document_id = d.id) >= 2', replace: '', why: 'personal documents count as evidence (suggests Victor for Vera\'s salary letter)' },
  { id: 'ai-personal-target', file: 'src/suggest.ts', find: 'if (grantees === 1) {', replace: 'if (false) {', why: "suggests more people for a document that is personal to one person" },
  { id: 'ai-read-only', file: 'src/suggest.ts', find: "the machine never does.\n      permission: 'read' as const,", replace: "the machine never does.\n      permission: c.editCount > 0 ? ('edit' as const) : ('read' as const),", why: 'suggestions propose edit access' },
];

/**
 * The checks that decide who reaches a document, and whether that is on record.
 * `--important` runs only these (plus the control): about 30 minutes instead of 70.
 */
const IMPORTANT = new Set([
  'control-noop',
  'authz-no-access-null', 'authz-rank', 'authz-deleted', 'authz-expiry', 'authz-grant-user', 'authz-caller-active',
  'level-download_version', 'level-upload_version', 'level-update_metadata', 'level-delete', 'level-share',
  'gate-allowed', 'gate-deny-audit', 'gate-404',
  'route-patch-level', 'route-grant-level', 'route-revoke-level', 'route-delete-level', 'route-version-download-level', 'route-activity-level',
  'bind-version', 'bind-grant', 'bind-suggestion', 'list-filter',
  'upload-role', 'admin-role', 'directory-role', 'transfer-recipient',
  'deactivate-revoke', 'session-revoked', 'session-active',
  'otp-attempts', 'otp-expiry', 'otp-single-use', 'otp-compare', 'otp-demo-only-display', 'otp-inactive', 'otp-rate-email',
  'world-grant', 'world-directory', 'world-admin-users', 'world-admin-list', 'world-admin-audit', 'world-admin-grants', 'world-transfer', 'world-demo-invite',
  'preview-types', 'preview-audit',
  'csrf-header', 'csrf-origin',
  'audit-trigger-update', 'audit-verify-hash', 'audit-verify-truncation',
  'download-attachment', 'ai-candidates', 'ai-personal-docs', 'ai-personal-target', 'ai-read-only',
]);

const CONTROL_IDS = new Set(['control-noop']); // expected to survive: proves the harness is not just failing everything

function runTests(): { passed: boolean; summary: string } {
  const r = spawnSync(process.execPath, ['--disable-warning=ExperimentalWarning', '--test', '--test-concurrency=1', ...fs.readdirSync(path.join(root, 'test')).filter((f) => f.endsWith('.test.ts')).map((f) => path.join('test', f))], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, NODE_ENV: 'test' },
    timeout: 300_000,
  });
  const out = (r.stdout ?? '') + (r.stderr ?? '');
  const fail = /# fail (\d+)/.exec(out)?.[1] ?? '?';
  const pass = /# pass (\d+)/.exec(out)?.[1] ?? '?';
  return { passed: r.status === 0, summary: `pass ${pass}, fail ${fail}` };
}

const args = process.argv.slice(2);
const startIdx = args.indexOf('--start');
const start = startIdx >= 0 ? args[startIdx + 1] : undefined;
const filter = args.find((a, i) => !a.startsWith('--') && (startIdx < 0 || i !== startIdx + 1));
const important = args.includes('--important');
let selected = M.filter((m) => (!filter || m.id.includes(filter)) && (!important || IMPORTANT.has(m.id)));
for (const id of IMPORTANT) if (!M.some((m) => m.id === id)) throw new Error(`IMPORTANT lists unknown mutation ${id}`);
if (start) {
  const at = selected.findIndex((m) => m.id.startsWith(start));
  selected = at >= 0 ? selected.slice(at) : [];
}
const cleanup = () => fs.rmSync(root, { recursive: true, force: true });
process.on('SIGINT', () => {
  cleanup();
  process.exit(130);
});
process.on('exit', cleanup);
console.log(`Working copy: ${root}`);

console.log(`Baseline: running tests on unmodified code...`);
const baseline = runTests();
if (!baseline.passed) {
  console.error(`Baseline is not green (${baseline.summary}). Fix tests first.`);
  process.exit(2);
}
console.log(`Baseline green (${baseline.summary}).\n`);

const survivors: Mutation[] = [];
let killed = 0;
for (const m of selected) {
  const file = path.join(root, m.file);
  const src = fs.readFileSync(file, 'utf8');
  const count = src.split(m.find).length - 1;
  if (count !== 1) {
    console.log(`?? ${m.id}: pattern found ${count} times in ${m.file} — mutation is stale, update it`);
    survivors.push(m);
    continue;
  }
  fs.writeFileSync(file, src.replace(m.find, m.replace));
  try {
    const r = runTests();
    const expectSurvive = CONTROL_IDS.has(m.id);
    if (r.passed === expectSurvive) {
      killed++;
      console.log(`${expectSurvive ? 'ok (control survived)' : 'KILLED'}  ${m.id.padEnd(30)} ${r.summary}  — ${m.why}`);
    } else {
      survivors.push(m);
      console.log(`SURVIVED ${m.id.padEnd(30)} ${r.summary}  — ${m.why}`);
    }
  } finally {
    fs.writeFileSync(file, src);
  }
}
console.log(`\n${killed}/${selected.length} mutations behaved as expected.`);
if (survivors.length) {
  console.log('Not caught by the tests:');
  for (const s of survivors) console.log(`  - ${s.id} (${s.file}): ${s.why}`);
  process.exit(1);
}
