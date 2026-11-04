/**
 * Seed demo data. Idempotent: does nothing if any user exists.
 *   npm run seed
 * Demo accounts sign in with a one-time code that is SHOWN ON SCREEN (they
 * cannot receive email). They are flagged is_demo=1 and live in a separate
 * "demo world" that can never see or share with real accounts.
 */
import { randomUUID } from 'node:crypto';
import { createContext } from '../src/app.ts';
import type { AppContext, Role } from '../src/context.ts';
import { sha256Hex } from '../src/crypto.ts';
import { tx } from '../src/db.ts';

export const DEMO_USERS: { email: string; name: string; role: Role }[] = [
  { email: 'admin@trustvault.demo', name: 'Ada Admin', role: 'admin' },
  { email: 'olivia@trustvault.demo', name: 'Olivia Owner (HR)', role: 'owner' },
  { email: 'oscar@trustvault.demo', name: 'Oscar Owner (Legal)', role: 'owner' },
  { email: 'vera@trustvault.demo', name: 'Vera Viewer', role: 'viewer' },
  { email: 'victor@trustvault.demo', name: 'Victor Viewer', role: 'viewer' },
  { email: 'pat@partner.example', name: 'Pat Partner (external)', role: 'viewer' },
];

function pdf(text: string): Buffer {
  // A minimal but valid one-page PDF with the given text.
  const safe = text.replace(/[()\\]/g, '');
  const stream = `BT /F1 14 Tf 72 720 Td (${safe}) Tj ET`;
  const objs = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let out = '%PDF-1.4\n';
  const offsets: number[] = [];
  objs.forEach((o, i) => {
    offsets.push(out.length);
    out += `${i + 1} 0 obj\n${o}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, '0')} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out, 'latin1');
}

/**
 * Mark the seeded addresses as demo accounts. Runs on every start so that a
 * database seeded by an earlier version (before is_demo existed) is upgraded.
 */
export function ensureDemoFlags(ctx: AppContext): number {
  const stmt = ctx.db.prepare('UPDATE users SET is_demo = 1 WHERE email = ? AND is_demo = 0');
  let n = 0;
  for (const u of DEMO_USERS) n += Number(stmt.run(u.email).changes);
  return n;
}

export function seed(ctx: AppContext): boolean {
  const count = (ctx.db.prepare('SELECT COUNT(*) AS n FROM users').get() as { n: number }).n;
  if (count > 0) return false;
  const ids: Record<string, string> = {};
  const now = Date.now();
  tx(ctx.db, () => {
    for (const u of DEMO_USERS) {
      const id = randomUUID();
      ids[u.email] = id;
      ctx.db
        .prepare("INSERT INTO users (id, email, name, role, password_hash, created_at, is_demo) VALUES (?,?,?,?,'!',?,1)")
        .run(id, u.email, u.name, u.role, now);
      ctx.audit.record({ action: 'user.create', outcome: 'success', actorEmail: 'seed', targetUserId: id, details: { email: u.email, role: u.role, seeded: true } });
    }
    const docs: { owner: string; title: string; category: string; description: string; filename: string; body: Buffer; grants: [string, 'read' | 'edit'][] }[] = [
      {
        owner: 'olivia@trustvault.demo',
        title: 'Salary letter - Vera Viewer 2026',
        category: 'HR',
        description: 'Annual compensation letter. Only Vera should see this.',
        filename: 'salary-vera-2026.pdf',
        body: pdf('CONFIDENTIAL Salary letter for Vera Viewer 2026'),
        grants: [['vera@trustvault.demo', 'read']],
      },
      {
        owner: 'olivia@trustvault.demo',
        title: 'Salary letter - Victor Viewer 2026',
        category: 'HR',
        description: 'Annual compensation letter. Only Victor should see this.',
        filename: 'salary-victor-2026.pdf',
        body: pdf('CONFIDENTIAL Salary letter for Victor Viewer 2026'),
        grants: [['victor@trustvault.demo', 'read']],
      },
      {
        owner: 'olivia@trustvault.demo',
        title: 'HR policy handbook',
        category: 'HR',
        description: 'Internal policies. Shared with both viewers.',
        filename: 'handbook.txt',
        body: Buffer.from('TrustVault demo HR handbook.\nSection 1: Be excellent to each other.\n'),
        grants: [
          ['vera@trustvault.demo', 'read'],
          ['victor@trustvault.demo', 'edit'],
        ],
      },
      {
        owner: 'oscar@trustvault.demo',
        title: 'Master services agreement - Partner Co',
        category: 'Contracts',
        description: 'Contract with the external partner. Pat may read it.',
        filename: 'msa-partner.pdf',
        body: pdf('Master services agreement between TrustVault Demo and Partner Co'),
        grants: [['pat@partner.example', 'read']],
      },
      {
        owner: 'oscar@trustvault.demo',
        title: 'Board litigation memo',
        category: 'Legal',
        description: 'Privileged. Not shared with anyone.',
        filename: 'litigation-memo.pdf',
        body: pdf('PRIVILEGED litigation memo - do not distribute'),
        grants: [],
      },
    ];
    for (const d of docs) {
      const docId = randomUUID();
      const versionId = randomUUID();
      const { storageKey, wrappedKey } = ctx.blobs.write(d.body);
      const ownerId = ids[d.owner]!;
      ctx.db
        .prepare('INSERT INTO documents (id, owner_id, title, category, description, current_version_id, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)')
        .run(docId, ownerId, d.title, d.category, d.description, versionId, now, now);
      const mime = d.filename.endsWith('.pdf') ? 'application/pdf' : 'text/plain';
      ctx.db
        .prepare(
          `INSERT INTO document_versions (id, document_id, version_no, filename, mime_type, size_bytes, sha256, storage_key, wrapped_key, uploaded_by, created_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
        )
        .run(versionId, docId, 1, d.filename, mime, d.body.length, sha256Hex(d.body), storageKey, wrappedKey, ownerId, now);
      ctx.audit.record({ action: 'document.upload', outcome: 'success', actorId: ownerId, actorEmail: d.owner, documentId: docId, details: { title: d.title, seeded: true } });
      for (const [email, permission] of d.grants) {
        const gid = randomUUID();
        ctx.db
          .prepare('INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at) VALUES (?,?,?,?,?,?)')
          .run(gid, docId, ids[email]!, permission, ownerId, now);
        ctx.audit.record({ action: 'grant.create', outcome: 'success', actorId: ownerId, actorEmail: d.owner, documentId: docId, targetUserId: ids[email]!, details: { grantId: gid, permission, seeded: true } });
      }
    }
  });
  return true;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const ctx = createContext();
  const done = seed(ctx);
  ensureDemoFlags(ctx);
  console.log(done ? 'Seeded demo data.' : 'Users already exist; nothing to do.');
}
