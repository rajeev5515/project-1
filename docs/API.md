# TrustVault HTTP API

Base path `/api`. JSON in and out, except uploads (multipart) and downloads
(bytes).

**Common rules**

* Authentication is the `tv_session` cookie set by `POST /api/auth/login`
  (HttpOnly, SameSite=Strict, Secure in production). There are no bearer
  tokens.
* **Every non-GET request must send `X-TrustVault-CSRF: 1`.** Without it the
  answer is `403 csrf`. If `Origin` or `Sec-Fetch-Site` is present, it must be
  same-origin.
* Errors are `{"error": "<code>", "message": "<text>"}`.
* `401 unauthenticated`: no valid session. `403 forbidden`: your role, or your
  access to this document, does not allow it. `404 not_found`: the document
  does not exist **or you have no access to it**. These two cases are
  deliberately indistinguishable.
* Unknown body fields are rejected with `400 validation` (no mass
  assignment).
* All responses are `Cache-Control: no-store`.
* "Access" below means the caller's level on *that document* (`read`, `edit`
  or `owner`; see PERMISSIONS.md). "Role" means the account type.

## Auth

| Method & path | Who may call | Body / query | Notes |
|---|---|---|---|
| `POST /auth/login` | anyone | `{email, password}` | Same 401 for every failure. 5 failures lock the account for 15 minutes. 20 failures per IP per 15 minutes gives 429. Audited. |
| `POST /auth/logout` | signed in | — | Revokes this session on the server. |
| `GET /auth/me` | signed in | — | `{user:{id,email,name,role,mustChangePassword}}` |
| `POST /auth/password` | signed in (allowed even while `mustChangePassword`) | `{currentPassword, newPassword}` | At least 12 characters. Ends all your *other* sessions. |

While `mustChangePassword` is true, every other endpoint returns
`403 password_change_required`.

## Documents

| Method & path | Who may call | Body / query | Notes |
|---|---|---|---|
| `GET /documents` | signed in | `q, owner, category, from, to (YYYY-MM-DD or ISO), scope=all\|mine\|shared, limit≤200, offset` | Only documents you can reach. `q` matches title and description; `owner` matches owner name or email; dates filter on last update. |
| `GET /documents/categories` | signed in | — | The fixed category list. |
| `POST /documents` | **role owner** | multipart: `file`, `title`, `category`, `description?` | Validated by extension *and* content. 20 MB maximum. 201 → `{document}`. |
| `GET /documents/trash` | **role owner** | — | Your own deleted documents. |
| `GET /documents/:id` | access ≥ read | — | Metadata, your access, `allowedActions`, current version. Audited as `document.view`. |
| `GET /documents/:id/download` | access ≥ read | — | Current version, as an `application/octet-stream` attachment. Audited. |
| `GET /documents/:id/versions` | access ≥ edit | — | Version history. |
| `GET /documents/:id/versions/:versionId/download` | access ≥ edit | — | The version must belong to `:id`. Audited. |
| `POST /documents/:id/versions` | access ≥ edit | multipart: `file` | Becomes the current version. Access is checked before reading the body and again before saving. |
| `PATCH /documents/:id` | access ≥ edit | `{title?, category?, description?}` | Anything else is rejected. Changes are audited with before and after values. |
| `DELETE /documents/:id` | access = owner | — | Moves it to the trash. All grantees lose access immediately. |
| `POST /documents/:id/restore` | access = owner, document in trash | — | |
| `DELETE /documents/:id/purge` | access = owner, document in trash | — | Destroys every version (blob and data key) and every grant. The audit history is kept. |

## Sharing

| Method & path | Who may call | Body | Notes |
|---|---|---|---|
| `GET /documents/:id/grants` | access = owner | — | |
| `POST /documents/:id/grants` | access = owner | `{userId \| email, permission: read\|edit, expiresAt?, suggestionId?}` | Creates or updates the single grant for that person. The target must be an active user and not the owner. 201 when created, 200 when updated. Audited as `grant.create` or `grant.update` (with old and new values). With `suggestionId` (which must belong to this document), also audited as `ai.suggestion.accepted`. |
| `DELETE /documents/:id/grants/:grantId` | access = owner | — | The grant must belong to `:id`. Takes effect on the next request. Audited as `grant.revoke`. |
| `GET /documents/:id/activity` | access = owner | — | The last 500 audit events for this document, including refused attempts. |
| `POST /documents/:id/suggestions` | access = owner | — | Returns `{suggestionId, source, suggestions[], appliesAutomatically:false}`. **Creates no grants.** Audited as `ai.suggestion.generated`. |
| `POST /documents/:id/suggestions/:sid/dismiss` | access = owner | `{userId?}` | Audited as `ai.suggestion.dismissed`. |
| `GET /users/directory?q=` | **role owner or admin** | `q` at least 2 characters | Up to 10 active users `{id,name,email,role}`, so owners can pick who to share with. |

## Administration (all require role admin)

| Method & path | Body / query | Notes |
|---|---|---|
| `GET /admin/users` | — | All users, with the number of documents each owns. |
| `POST /admin/users` | `{email, name, role, password}` | The new user must change the password at first sign-in. |
| `PATCH /admin/users/:id` | `{role?, active?, name?}` | Deactivation and role changes end all of that user's sessions. You cannot change your own role or deactivate yourself, and the last admin cannot be removed. |
| `POST /admin/users/:id/reset-password` | — | Returns `{temporaryPassword}` once. Ends sessions and forces a change. Raises an alert. |
| `POST /admin/users/:id/revoke-sessions` | — | |
| `POST /admin/users/:id/transfer-documents` | `{toUserId}` | The recipient must be an active owner other than the source user. Admins cannot receive. |
| `GET /admin/grants` | — | Every current grant: document title, owner, grantee, level and expiry. No content. |
| `GET /admin/audit` | `actor, action (prefix), outcome, documentId, from, before (seq), limit≤500` | Newest first. |
| `GET /admin/audit/verify` | `seq?, hash?` | Walks the HMAC chain. With an externally recorded head, also detects truncation. |
| `GET /admin/alerts` | — | Audit chain broken, access probing, failed sign-ins, password spraying, bulk downloads, mass sharing, privileged changes. |
| `GET /admin/stats` | — | Counts, and actions in the last 24 hours. |

## Other

| Path | Who | Notes |
|---|---|---|
| `GET /healthz` | anyone | `{"ok":true}` |
| `GET /` and static files | anyone | The UI shell only. It contains no data. |
