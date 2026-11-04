import { randomUUID } from 'node:crypto';
import { Router, type Request, type Response } from 'express';
import { requireAuth, requireRole } from '../auth.ts';
import {
  ACCESSIBLE_DOCUMENTS_SQL,
  allowedActions,
  authorizeDocument,
  type AccessLevel,
  type DocAction,
  type DocumentRow,
} from '../authz.ts';
import { auditFor, HttpError, type AppContext } from '../context.ts';
import { sha256Hex } from '../crypto.ts';
import { tx } from '../db.ts';
import { suggestRecipients } from '../suggest.ts';
import { parseUpload } from '../upload.ts';
import {
  CATEGORIES,
  isUuid,
  onlyKeys,
  optionalExpiry,
  optionalString,
  requireCategory,
  requireString,
  validateUpload,
  ValidationError,
} from '../validation.ts';

/** Types the web client can render safely itself. Office files are download-only. */
const PREVIEWABLE = new Set(['application/pdf', 'image/png', 'image/jpeg', 'text/plain', 'text/csv']);

interface VersionRow {
  id: string;
  document_id: string;
  version_no: number;
  filename: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
  storage_key: string;
  wrapped_key: string;
  uploaded_by: string;
  created_at: number;
}

interface GrantRow {
  id: string;
  document_id: string;
  user_id: string;
  permission: 'read' | 'edit';
  granted_by: string;
  created_at: number;
  expires_at: number | null;
}

export function documentRoutes(ctx: AppContext): Router {
  const r = Router();
  r.use(requireAuth);

  /**
   * The single gate every document route goes through.
   *
   * Calls authorizeDocument() and, if refused, writes an access.denied audit
   * row and throws. A caller who has no access at all gets 404, identical to
   * a document that does not exist, so ids cannot be probed. A caller who can
   * see the document but lacks the level for this action gets 403.
   */
  function gate(req: Request, action: DocAction): { doc: DocumentRow; access: AccessLevel } {
    const id = req.params.id;
    if (!isUuid(id)) throw new HttpError(404, 'not_found', 'Document not found');
    const result = authorizeDocument(ctx.db, req.user!.id, id, action);
    if (!result.allowed) {
      auditFor(ctx, req, {
        action: `document.${action}`,
        outcome: 'denied',
        documentId: id,
        details: { reason: result.reason, path: req.originalUrl.slice(0, 200), method: req.method },
      });
      if (result.reason === 'insufficient') {
        throw new HttpError(403, 'forbidden', 'Your access to this document does not allow this');
      }
      throw new HttpError(404, 'not_found', 'Document not found');
    }
    return { doc: result.doc, access: result.access };
  }

  const currentVersion = (doc: DocumentRow) =>
    doc.current_version_id
      ? (ctx.db.prepare('SELECT * FROM document_versions WHERE id = ? AND document_id = ?').get(doc.current_version_id, doc.id) as
          | VersionRow
          | undefined)
      : undefined;

  const ownerOf = (doc: DocumentRow) =>
    ctx.db.prepare('SELECT id, name, email FROM users WHERE id = ?').get(doc.owner_id) as { id: string; name: string; email: string };

  function present(doc: DocumentRow, access: AccessLevel) {
    const v = currentVersion(doc);
    return {
      id: doc.id,
      title: doc.title,
      category: doc.category,
      description: doc.description,
      owner: ownerOf(doc),
      createdAt: doc.created_at,
      updatedAt: doc.updated_at,
      access,
      allowedActions: allowedActions(access),
      currentVersion: v
        ? { id: v.id, versionNo: v.version_no, filename: v.filename, mimeType: v.mime_type, sizeBytes: v.size_bytes, sha256: v.sha256, createdAt: v.created_at }
        : null,
    };
  }

  /** Send decrypted bytes as a download that no browser will render inline. */
  function sendFile(res: Response, v: VersionRow) {
    const data = ctx.blobs.read(v.storage_key, v.wrapped_key);
    if (sha256Hex(data) !== v.sha256) throw new Error(`integrity check failed for version ${v.id}`);
    const ascii = v.filename.replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(v.filename)}`);
    res.setHeader('Content-Security-Policy', "default-src 'none'; sandbox");
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-store, private');
    res.setHeader('Content-Length', String(data.length));
    res.end(data);
  }

  // ------------------------------------------------------------ list/search
  r.get('/', (req, res) => {
    const q = req.query;
    const str = (v: unknown, max = 200) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
    const like = (s: string) => `%${s.replace(/[\\%_]/g, (m) => '\\' + m)}%`;
    const where: string[] = [];
    const params: Record<string, string | number> = { uid: req.user!.id, now: Date.now() };

    const text = str(q.q);
    if (text) {
      where.push(`(a.title LIKE :text ESCAPE '\\' OR a.description LIKE :text ESCAPE '\\')`);
      params.text = like(text);
    }
    const owner = str(q.owner);
    if (owner) {
      where.push(`(o.name LIKE :owner ESCAPE '\\' OR o.email LIKE :owner ESCAPE '\\')`);
      params.owner = like(owner);
    }
    const category = str(q.category);
    if (category) {
      if (!(CATEGORIES as readonly string[]).includes(category)) throw new ValidationError('Unknown category');
      where.push('a.category = :category');
      params.category = category;
    }
    const dateParam = (v: string, name: string, endOfDay: boolean) => {
      const t = Date.parse(endOfDay && /^\d{4}-\d{2}-\d{2}$/.test(v) ? `${v}T23:59:59.999Z` : v);
      if (!Number.isFinite(t)) throw new ValidationError(`${name} is not a valid date`);
      return t;
    };
    const from = str(q.from, 40);
    if (from) {
      where.push('a.updated_at >= :from');
      params.from = dateParam(from, 'from', false);
    }
    const to = str(q.to, 40);
    if (to) {
      where.push('a.updated_at <= :to');
      params.to = dateParam(to, 'to', true);
    }
    const scope = str(q.scope, 10) || 'all';
    if (scope === 'mine') where.push("a.access = 'owner'");
    else if (scope === 'shared') where.push("a.access IN ('read','edit')");
    else if (scope !== 'all') throw new ValidationError('scope must be all, mine or shared');

    const limit = Math.min(Math.max(Number(q.limit) || 50, 1), 200);
    const offset = Math.max(Number(q.offset) || 0, 0);
    params.limit = limit;
    params.offset = offset;

    // ACCESSIBLE_DOCUMENTS_SQL is the same access rule as authorizeDocument();
    // `access IS NOT NULL` is what removes documents the caller cannot reach.
    const rows = ctx.db
      .prepare(
        `SELECT a.*, o.name AS owner_name, o.email AS owner_email, cv.mime_type AS mime_type, cv.filename AS filename
         FROM (${ACCESSIBLE_DOCUMENTS_SQL}) a
         JOIN users o ON o.id = a.owner_id
         LEFT JOIN document_versions cv ON cv.id = a.current_version_id AND cv.document_id = a.id
         WHERE a.access IS NOT NULL ${where.map((w) => 'AND ' + w).join(' ')}
         ORDER BY a.updated_at DESC LIMIT :limit OFFSET :offset`,
      )
      .all(params) as unknown as (DocumentRow & { access: AccessLevel; owner_name: string; owner_email: string; mime_type: string | null; filename: string | null })[];

    res.json({
      documents: rows.map((d) => ({
        id: d.id,
        title: d.title,
        category: d.category,
        owner: { id: d.owner_id, name: d.owner_name, email: d.owner_email },
        updatedAt: d.updated_at,
        createdAt: d.created_at,
        access: d.access,
        mimeType: d.mime_type,
        filename: d.filename,
      })),
      limit,
      offset,
    });
  });

  r.get('/categories', (_req, res) => res.json({ categories: CATEGORIES }));

  // ------------------------------------------------------------- upload new
  // Only the 'owner' role creates documents. Admins do not own documents
  // (separation of duties) and viewers only receive.
  r.post('/', requireRole('owner'), async (req, res) => {
    const { fields, file } = await parseUpload(req, ctx.config.maxUploadBytes);
    const title = requireString(fields.title, 'title', { max: 200 });
    const category = requireCategory(fields.category);
    const description = optionalString(fields.description, 'description', 2000);
    if (!file) throw new ValidationError('A file is required');
    const check = validateUpload(file.filename, file.data, ctx.config.maxUploadBytes);
    if (!check.ok) {
      auditFor(ctx, req, { action: 'document.upload', outcome: 'failure', details: { reason: check.error, filename: file.filename.slice(0, 200) } });
      throw new ValidationError(check.error);
    }
    const { storageKey, wrappedKey } = ctx.blobs.write(file.data);
    const docId = randomUUID();
    const versionId = randomUUID();
    const now = Date.now();
    try {
      tx(ctx.db, () => {
        ctx.db
          .prepare(
            `INSERT INTO documents (id, owner_id, title, category, description, current_version_id, created_at, updated_at)
             VALUES (?,?,?,?,?,?,?,?)`,
          )
          .run(docId, req.user!.id, title, category, description, versionId, now, now);
        ctx.db
          .prepare(
            `INSERT INTO document_versions (id, document_id, version_no, filename, mime_type, size_bytes, sha256, storage_key, wrapped_key, uploaded_by, created_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          )
          .run(versionId, docId, 1, check.filename, check.mime, file.data.length, sha256Hex(file.data), storageKey, wrappedKey, req.user!.id, now);
        auditFor(ctx, req, {
          action: 'document.upload',
          outcome: 'success',
          documentId: docId,
          details: { title, category, filename: check.filename, sizeBytes: file.data.length, sha256: sha256Hex(file.data), versionId },
        });
      });
    } catch (err) {
      ctx.blobs.remove(storageKey);
      throw err;
    }
    const created = authorizeDocument(ctx.db, req.user!.id, docId, 'view');
    if (!created.allowed) throw new Error('created document is not visible to its owner');
    res.status(201).json({ document: present(created.doc, created.access) });
  });

  // ------------------------------------------------------------------ trash
  r.get('/trash', requireRole('owner'), (req, res) => {
    const rows = ctx.db
      .prepare('SELECT id, title, category, deleted_at FROM documents WHERE owner_id = ? AND deleted_at IS NOT NULL ORDER BY deleted_at DESC')
      .all(req.user!.id) as { id: string; title: string; category: string; deleted_at: number }[];
    res.json({ documents: rows.map((d) => ({ id: d.id, title: d.title, category: d.category, deletedAt: d.deleted_at })) });
  });

  // ---------------------------------------------------------------- one doc
  r.get('/:id', (req, res) => {
    const { doc, access } = gate(req, 'view');
    auditFor(ctx, req, { action: 'document.view', outcome: 'success', documentId: doc.id });
    res.json({ document: present(doc, access) });
  });

  r.get('/:id/download', (req, res) => {
    const { doc } = gate(req, 'download');
    const v = currentVersion(doc);
    if (!v) throw new HttpError(404, 'not_found', 'Document has no content');
    auditFor(ctx, req, {
      action: 'document.download',
      outcome: 'success',
      documentId: doc.id,
      details: { versionId: v.id, versionNo: v.version_no, sha256: v.sha256 },
    });
    sendFile(res, v);
  });

  /**
   * In-app preview of the current version. Same rule as download (read
   * access), audited separately so the owner can tell "opened in the browser"
   * from "saved a copy". The bytes are still sent as an opaque attachment; the
   * client renders them itself (images via <img>, text via textContent, PDF via
   * pdf.js with scripting disabled), so nothing in the file runs on our origin.
   */
  r.get('/:id/preview', (req, res) => {
    const { doc } = gate(req, 'preview');
    const v = currentVersion(doc);
    if (!v) throw new HttpError(404, 'not_found', 'Document has no content');
    if (!PREVIEWABLE.has(v.mime_type)) throw new HttpError(415, 'not_previewable', 'This file type cannot be previewed; download it instead');
    auditFor(ctx, req, {
      action: 'document.preview',
      outcome: 'success',
      documentId: doc.id,
      details: { versionId: v.id, versionNo: v.version_no, sha256: v.sha256 },
    });
    res.setHeader('X-TrustVault-Mime', v.mime_type);
    sendFile(res, v);
  });

  r.get('/:id/versions', (req, res) => {
    const { doc } = gate(req, 'list_versions');
    const rows = ctx.db
      .prepare(
        `SELECT v.id, v.version_no, v.filename, v.mime_type, v.size_bytes, v.sha256, v.created_at, u.name AS uploaded_by_name
         FROM document_versions v JOIN users u ON u.id = v.uploaded_by
         WHERE v.document_id = ? ORDER BY v.version_no DESC`,
      )
      .all(doc.id) as { id: string; version_no: number; filename: string; mime_type: string; size_bytes: number; sha256: string; created_at: number; uploaded_by_name: string }[];
    res.json({
      versions: rows.map((v) => ({
        id: v.id,
        versionNo: v.version_no,
        filename: v.filename,
        mimeType: v.mime_type,
        sizeBytes: v.size_bytes,
        sha256: v.sha256,
        createdAt: v.created_at,
        uploadedBy: v.uploaded_by_name,
        current: v.id === doc.current_version_id,
      })),
    });
  });

  r.get('/:id/versions/:versionId/download', (req, res) => {
    const { doc } = gate(req, 'download_version');
    // The version must belong to THIS document. Without the document_id
    // condition, edit access to one document would unlock every version id.
    const v = isUuid(req.params.versionId)
      ? (ctx.db.prepare('SELECT * FROM document_versions WHERE id = ? AND document_id = ?').get(req.params.versionId, doc.id) as VersionRow | undefined)
      : undefined;
    if (!v) {
      auditFor(ctx, req, { action: 'document.download_version', outcome: 'denied', documentId: doc.id, details: { reason: 'version_not_in_document', versionId: String(req.params.versionId).slice(0, 64) } });
      throw new HttpError(404, 'not_found', 'Version not found');
    }
    auditFor(ctx, req, { action: 'document.download', outcome: 'success', documentId: doc.id, details: { versionId: v.id, versionNo: v.version_no, sha256: v.sha256 } });
    sendFile(res, v);
  });

  r.post('/:id/versions', async (req, res) => {
    // Checked before reading the body (no work for unauthorised callers) ...
    gate(req, 'upload_version');
    const { file } = await parseUpload(req, ctx.config.maxUploadBytes);
    if (!file) throw new ValidationError('A file is required');
    const check = validateUpload(file.filename, file.data, ctx.config.maxUploadBytes);
    if (!check.ok) {
      auditFor(ctx, req, { action: 'document.upload_version', outcome: 'failure', documentId: req.params.id as string, details: { reason: check.error } });
      throw new ValidationError(check.error);
    }
    const { storageKey, wrappedKey } = ctx.blobs.write(file.data);
    try {
      const result = tx(ctx.db, () => {
        // ... and checked again inside the transaction, because the upload may
        // have taken seconds and access could have been revoked meanwhile.
        const { doc } = gate(req, 'upload_version');
        const next = (ctx.db.prepare('SELECT MAX(version_no) AS n FROM document_versions WHERE document_id = ?').get(doc.id) as { n: number }).n + 1;
        const versionId = randomUUID();
        const now = Date.now();
        ctx.db
          .prepare(
            `INSERT INTO document_versions (id, document_id, version_no, filename, mime_type, size_bytes, sha256, storage_key, wrapped_key, uploaded_by, created_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          )
          .run(versionId, doc.id, next, check.filename, check.mime, file.data.length, sha256Hex(file.data), storageKey, wrappedKey, req.user!.id, now);
        ctx.db.prepare('UPDATE documents SET current_version_id = ?, updated_at = ? WHERE id = ?').run(versionId, now, doc.id);
        auditFor(ctx, req, {
          action: 'document.upload_version',
          outcome: 'success',
          documentId: doc.id,
          details: { versionId, versionNo: next, filename: check.filename, sizeBytes: file.data.length, sha256: sha256Hex(file.data) },
        });
        return { versionId, versionNo: next };
      });
      res.status(201).json({ version: result });
    } catch (err) {
      ctx.blobs.remove(storageKey);
      throw err;
    }
  });

  r.patch('/:id', (req, res) => {
    const { doc, access } = gate(req, 'update_metadata');
    // Explicit allow-list: owner_id, deleted_at etc. can never be set from a request body.
    const body = onlyKeys(req.body, ['title', 'category', 'description']);
    const changes: Record<string, { from: string; to: string }> = {};
    const next = { title: doc.title, category: doc.category, description: doc.description };
    if (body.title !== undefined) next.title = requireString(body.title, 'title', { max: 200 });
    if (body.category !== undefined) next.category = requireCategory(body.category);
    if (body.description !== undefined) next.description = optionalString(body.description, 'description', 2000);
    for (const k of ['title', 'category', 'description'] as const) {
      if (next[k] !== doc[k]) changes[k] = { from: doc[k], to: next[k] };
    }
    if (Object.keys(changes).length === 0) return res.json({ document: present(doc, access) });
    tx(ctx.db, () => {
      ctx.db
        .prepare('UPDATE documents SET title = ?, category = ?, description = ?, updated_at = ? WHERE id = ?')
        .run(next.title, next.category, next.description, Date.now(), doc.id);
      auditFor(ctx, req, { action: 'document.update_metadata', outcome: 'success', documentId: doc.id, details: { changes } });
    });
    const after = gate(req, 'view');
    res.json({ document: present(after.doc, after.access) });
  });

  r.delete('/:id', (req, res) => {
    const { doc } = gate(req, 'delete');
    tx(ctx.db, () => {
      ctx.db.prepare('UPDATE documents SET deleted_at = ?, deleted_by = ? WHERE id = ?').run(Date.now(), req.user!.id, doc.id);
      auditFor(ctx, req, { action: 'document.delete', outcome: 'success', documentId: doc.id, details: { title: doc.title, recoverable: true } });
    });
    res.json({ ok: true });
  });

  r.post('/:id/restore', (req, res) => {
    const { doc } = gate(req, 'restore');
    tx(ctx.db, () => {
      ctx.db.prepare('UPDATE documents SET deleted_at = NULL, deleted_by = NULL, updated_at = ? WHERE id = ?').run(Date.now(), doc.id);
      auditFor(ctx, req, { action: 'document.restore', outcome: 'success', documentId: doc.id, details: { title: doc.title } });
    });
    res.json({ ok: true });
  });

  r.delete('/:id/purge', (req, res) => {
    const { doc } = gate(req, 'purge');
    const versions = ctx.db.prepare('SELECT storage_key FROM document_versions WHERE document_id = ?').all(doc.id) as { storage_key: string }[];
    const grantCount = tx(ctx.db, () => {
      const g = ctx.db.prepare('DELETE FROM grants WHERE document_id = ?').run(doc.id);
      ctx.db.prepare('DELETE FROM ai_suggestions WHERE document_id = ?').run(doc.id);
      ctx.db.prepare('UPDATE documents SET current_version_id = NULL WHERE id = ?').run(doc.id);
      ctx.db.prepare('DELETE FROM document_versions WHERE document_id = ?').run(doc.id);
      ctx.db.prepare('DELETE FROM documents WHERE id = ?').run(doc.id);
      // The audit rows about this document stay: purge removes content, never history.
      auditFor(ctx, req, {
        action: 'document.purge',
        outcome: 'success',
        documentId: doc.id,
        details: { title: doc.title, versionsDestroyed: versions.length, grantsRemoved: Number(g.changes) },
      });
      return Number(g.changes);
    });
    for (const v of versions) ctx.blobs.remove(v.storage_key);
    res.json({ ok: true, versionsDestroyed: versions.length, grantsRemoved: grantCount });
  });

  // ----------------------------------------------------------------- grants
  r.get('/:id/grants', (req, res) => {
    const { doc } = gate(req, 'share');
    const rows = ctx.db
      .prepare(
        `SELECT g.*, u.name, u.email, u.role, u.active, gb.name AS granted_by_name
         FROM grants g JOIN users u ON u.id = g.user_id JOIN users gb ON gb.id = g.granted_by
         WHERE g.document_id = ? ORDER BY g.created_at`,
      )
      .all(doc.id) as unknown as (GrantRow & { name: string; email: string; role: string; active: number; granted_by_name: string })[];
    const now = Date.now();
    res.json({
      grants: rows.map((g) => ({
        id: g.id,
        user: { id: g.user_id, name: g.name, email: g.email, role: g.role, active: g.active === 1 },
        permission: g.permission,
        grantedBy: g.granted_by_name,
        createdAt: g.created_at,
        expiresAt: g.expires_at,
        expired: g.expires_at !== null && g.expires_at <= now,
      })),
    });
  });

  r.post('/:id/grants', (req, res) => {
    const { doc } = gate(req, 'share');
    const body = onlyKeys(req.body, ['userId', 'email', 'permission', 'expiresAt', 'suggestionId']);
    const permission = body.permission;
    if (permission !== 'read' && permission !== 'edit') throw new ValidationError('permission must be read or edit');
    const expiresAt = optionalExpiry(body.expiresAt);
    let target: { id: string; email: string; name: string; active: number; is_demo: number } | undefined;
    if (isUuid(body.userId)) {
      target = ctx.db.prepare('SELECT id, email, name, active, is_demo FROM users WHERE id = ?').get(body.userId) as typeof target;
    } else if (typeof body.email === 'string') {
      target = ctx.db.prepare('SELECT id, email, name, active, is_demo FROM users WHERE email = ?').get(body.email.trim().toLowerCase()) as typeof target;
    } else {
      throw new ValidationError('userId or email is required');
    }
    // Demo accounts can be signed in to by anyone, so real documents must never
    // be shared into the demo world (and demo users cannot reach real people).
    // Same message as "no such user", so this cannot be used to probe the other world.
    if (!target || target.active !== 1 || (target.is_demo === 1) !== req.user!.isDemo) {
      throw new ValidationError('No active user with that id or email');
    }
    if (target.id === doc.owner_id) throw new ValidationError('The owner already has full access');

    let suggestionId: string | null = null;
    if (body.suggestionId !== undefined) {
      const s = isUuid(body.suggestionId)
        ? (ctx.db.prepare('SELECT id, suggestions FROM ai_suggestions WHERE id = ? AND document_id = ?').get(body.suggestionId, doc.id) as
            | { id: string; suggestions: string }
            | undefined)
        : undefined;
      if (!s) throw new ValidationError('suggestionId does not belong to this document');
      suggestionId = s.id;
    }

    const existing = ctx.db.prepare('SELECT * FROM grants WHERE document_id = ? AND user_id = ?').get(doc.id, target.id) as GrantRow | undefined;
    const now = Date.now();
    const result = tx(ctx.db, () => {
      if (existing) {
        ctx.db.prepare('UPDATE grants SET permission = ?, expires_at = ?, granted_by = ?, created_at = ? WHERE id = ?').run(permission, expiresAt, req.user!.id, now, existing.id);
        auditFor(ctx, req, {
          action: 'grant.update',
          outcome: 'success',
          documentId: doc.id,
          targetUserId: target.id,
          details: { grantId: existing.id, from: { permission: existing.permission, expiresAt: existing.expires_at }, to: { permission, expiresAt }, suggestionId },
        });
        return { id: existing.id, created: false };
      }
      const id = randomUUID();
      ctx.db
        .prepare('INSERT INTO grants (id, document_id, user_id, permission, granted_by, created_at, expires_at) VALUES (?,?,?,?,?,?,?)')
        .run(id, doc.id, target.id, permission, req.user!.id, now, expiresAt);
      auditFor(ctx, req, {
        action: 'grant.create',
        outcome: 'success',
        documentId: doc.id,
        targetUserId: target.id,
        details: { grantId: id, permission, expiresAt, targetEmail: target.email, suggestionId },
      });
      if (suggestionId) {
        auditFor(ctx, req, { action: 'ai.suggestion.accepted', outcome: 'success', documentId: doc.id, targetUserId: target.id, details: { suggestionId, grantId: id, permission } });
      }
      return { id, created: true };
    });
    res.status(result.created ? 201 : 200).json({ grant: { id: result.id, userId: target.id, permission, expiresAt } });
  });

  r.delete('/:id/grants/:grantId', (req, res) => {
    const { doc } = gate(req, 'share');
    // The grant must belong to this document; otherwise owning any document
    // would let you revoke grants on everyone else's.
    const grant = isUuid(req.params.grantId)
      ? (ctx.db.prepare('SELECT * FROM grants WHERE id = ? AND document_id = ?').get(req.params.grantId, doc.id) as GrantRow | undefined)
      : undefined;
    if (!grant) {
      auditFor(ctx, req, { action: 'grant.revoke', outcome: 'denied', documentId: doc.id, details: { reason: 'grant_not_in_document', grantId: String(req.params.grantId).slice(0, 64) } });
      throw new HttpError(404, 'not_found', 'Grant not found');
    }
    tx(ctx.db, () => {
      ctx.db.prepare('DELETE FROM grants WHERE id = ?').run(grant.id);
      auditFor(ctx, req, {
        action: 'grant.revoke',
        outcome: 'success',
        documentId: doc.id,
        targetUserId: grant.user_id,
        details: { grantId: grant.id, permission: grant.permission },
      });
    });
    res.json({ ok: true });
  });

  // --------------------------------------------------------------- activity
  r.get('/:id/activity', (req, res) => {
    const { doc } = gate(req, 'view_activity');
    const rows = ctx.db
      .prepare('SELECT seq, ts, actor_email, action, outcome, target_user_id, details FROM audit_log WHERE document_id = ? ORDER BY seq DESC LIMIT 500')
      .all(doc.id) as { seq: number; ts: number; actor_email: string | null; action: string; outcome: string; target_user_id: string | null; details: string }[];
    res.json({ events: rows.map((e) => ({ ...e, details: JSON.parse(e.details) })) });
  });

  // ------------------------------------------------------------ AI suggest
  r.post('/:id/suggestions', async (req, res) => {
    const { doc } = gate(req, 'share');
    const result = await suggestRecipients(ctx, doc);
    // Re-check after the (possibly slow) external call: ownership may have changed.
    gate(req, 'share');
    const id = randomUUID();
    tx(ctx.db, () => {
      ctx.db
        .prepare('INSERT INTO ai_suggestions (id, document_id, requested_by, source, suggestions, created_at) VALUES (?,?,?,?,?,?)')
        .run(id, doc.id, req.user!.id, result.source, JSON.stringify(result.suggestions), Date.now());
      auditFor(ctx, req, {
        action: 'ai.suggestion.generated',
        outcome: 'success',
        documentId: doc.id,
        details: {
          suggestionId: id,
          source: result.source,
          suggested: result.suggestions.map((s) => ({ userId: s.userId, permission: s.permission })),
          note: result.note ?? null,
        },
      });
    });
    res.json({ suggestionId: id, source: result.source, note: result.note ?? null, suggestions: result.suggestions, appliesAutomatically: false });
  });

  r.post('/:id/suggestions/:suggestionId/dismiss', (req, res) => {
    const { doc } = gate(req, 'share');
    const body = onlyKeys(req.body ?? {}, ['userId']);
    const s = isUuid(req.params.suggestionId)
      ? ctx.db.prepare('SELECT id FROM ai_suggestions WHERE id = ? AND document_id = ?').get(req.params.suggestionId, doc.id)
      : undefined;
    if (!s) throw new HttpError(404, 'not_found', 'Suggestion not found');
    auditFor(ctx, req, {
      action: 'ai.suggestion.dismissed',
      outcome: 'success',
      documentId: doc.id,
      targetUserId: isUuid(body.userId) ? body.userId : null,
      details: { suggestionId: req.params.suggestionId },
    });
    res.json({ ok: true });
  });

  return r;
}
