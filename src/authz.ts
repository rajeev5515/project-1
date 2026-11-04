import type { DB } from './db.ts';

/**
 * THE authorisation decision for documents. Every route that touches a
 * document calls authorizeDocument() (single document) or uses
 * ACCESSIBLE_DOCUMENTS_SQL (lists/search). Both are built from the same SQL
 * so the list view and the single-document view cannot disagree.
 *
 * Model (see docs/PERMISSIONS.md):
 *   - Every document has exactly one owner. The owner holds 'owner' access.
 *   - Anyone else needs an explicit, unexpired grant naming them:
 *       read : view metadata, download the CURRENT version.
 *       edit : read + upload a new version, change title/category/description,
 *              see version history and download old versions.
 *   - Only the owner can share, revoke, delete, restore, or see the
 *     per-document activity log. Editors cannot re-share (no chains).
 *   - Administrators get NO document access from their role. They manage
 *     users and read the audit trail; they cannot open a document unless
 *     someone grants it to them like anyone else.
 *   - A soft-deleted document is unreachable to everyone except its owner,
 *     and only for the 'restore'/'purge'/'view-trash' actions.
 *   - Inactive users never reach this function (auth middleware rejects
 *     them), but we check active=1 here too so the rule holds for any caller.
 *
 * Nothing here is cached. Every request re-reads grants, so revoking a grant
 * or deactivating a user takes effect on the very next request.
 */

export type AccessLevel = 'read' | 'edit' | 'owner';

export type DocAction =
  | 'view' // metadata
  | 'download' // current version
  | 'download_version' // any older version
  | 'list_versions'
  | 'upload_version'
  | 'update_metadata'
  | 'delete'
  | 'share' // create/change/revoke grants, AI suggestions
  | 'view_activity'
  | 'restore'
  | 'purge';

const RANK: Record<AccessLevel, number> = { read: 1, edit: 2, owner: 3 };

/** Minimum access level each action requires. */
export const REQUIRED_LEVEL: Record<DocAction, AccessLevel> = {
  view: 'read',
  download: 'read',
  download_version: 'edit',
  list_versions: 'edit',
  upload_version: 'edit',
  update_metadata: 'edit',
  delete: 'owner',
  share: 'owner',
  view_activity: 'owner',
  restore: 'owner',
  purge: 'owner',
};

/** Actions that apply to documents in the trash. Everything else requires a live document. */
const TRASH_ACTIONS: ReadonlySet<DocAction> = new Set(['restore', 'purge']);

/**
 * Computes the caller's access level for every document. Parameters:
 * :uid = caller's user id, :now = current epoch ms.
 * Rows with access IS NULL are documents the caller cannot reach.
 */
export const ACCESS_LEVEL_SQL = `
  CASE
    WHEN d.owner_id = :uid THEN 'owner'
    ELSE (SELECT g.permission FROM grants g
           WHERE g.document_id = d.id AND g.user_id = :uid
             AND (g.expires_at IS NULL OR g.expires_at > :now))
  END`;

/** Live (not deleted) documents the caller can reach, with their level as `access`. */
export const ACCESSIBLE_DOCUMENTS_SQL = `
  SELECT d.*, ${ACCESS_LEVEL_SQL} AS access
  FROM documents d
  JOIN users caller ON caller.id = :uid AND caller.active = 1
  WHERE d.deleted_at IS NULL`;

export interface DocumentRow {
  id: string;
  owner_id: string;
  title: string;
  category: string;
  description: string;
  current_version_id: string | null;
  created_at: number;
  updated_at: number;
  deleted_at: number | null;
  deleted_by: string | null;
}

export interface AuthorizedDocument {
  doc: DocumentRow;
  access: AccessLevel;
}

export type AuthzResult =
  | { allowed: true; doc: DocumentRow; access: AccessLevel }
  | { allowed: false; reason: 'not_found' | 'no_access' | 'insufficient' | 'deleted'; access: AccessLevel | null };

export function accessLevelFor(db: DB, userId: string, documentId: string): { doc: DocumentRow; access: AccessLevel | null } | null {
  const row = db
    .prepare(
      `SELECT d.*, ${ACCESS_LEVEL_SQL} AS access
       FROM documents d
       JOIN users caller ON caller.id = :uid AND caller.active = 1
       WHERE d.id = :docId`,
    )
    .get({ uid: userId, now: Date.now(), docId: documentId }) as (DocumentRow & { access: AccessLevel | null }) | undefined;
  if (!row) return null;
  const { access, ...doc } = row;
  return { doc, access };
}

export function authorizeDocument(db: DB, userId: string, documentId: string, action: DocAction): AuthzResult {
  const found = accessLevelFor(db, userId, documentId);
  if (!found) return { allowed: false, reason: 'not_found', access: null };
  const { doc, access } = found;
  if (access === null) return { allowed: false, reason: 'no_access', access: null };
  const isTrashAction = TRASH_ACTIONS.has(action);
  if (doc.deleted_at !== null && !isTrashAction) return { allowed: false, reason: 'deleted', access };
  if (doc.deleted_at === null && isTrashAction) return { allowed: false, reason: 'not_found', access };
  if (RANK[access] < RANK[REQUIRED_LEVEL[action]]) return { allowed: false, reason: 'insufficient', access };
  return { allowed: true, doc, access };
}

/** Actions the caller may perform, for the UI. The UI is a convenience; the server re-checks every call. */
export function allowedActions(access: AccessLevel): DocAction[] {
  return (Object.keys(REQUIRED_LEVEL) as DocAction[]).filter(
    (a) => !TRASH_ACTIONS.has(a) && RANK[access] >= RANK[REQUIRED_LEVEL[a]],
  );
}
