# Permission model

## In one paragraph

Every document has exactly one owner. Nobody else can reach it unless the
owner has granted *them, by name,* `read` or `edit` on *that document*,
optionally until a date. There are no folders, groups, inheritance, public
links or admin override. The server works out the caller's access from the
database on every request, so a grant that is revoked, has expired, or belongs
to a deactivated user stops working on the next request.

## Roles (what your account type lets you do)

| Role | Can | Cannot |
|---|---|---|
| **admin** | Invite and deactivate users, change roles, end sessions, transfer a leaver's documents to another owner, read the full audit trail, verify the audit chain, see alerts and every current grant (metadata only). | Open, download or change any document, unless an owner grants it to them like anyone else. Upload or own documents. Change their own role or deactivate themselves. Remove the last admin. |
| **owner** | Upload documents (and so become their owner). Everything on their own documents. Search the user directory to share. **Everyone who signs up gets this role.** | Anything on other people's documents without a grant. |
| **viewer** | Use documents shared with them, at the level granted. This is the role for external people too. | Upload. Search the user directory. |

## Accounts and sign-in

Anyone can create an account with their email. They get a 6-digit code by
email, valid for 10 minutes and usable once, and they become an **owner**.
Addresses in `TV_ADMIN_EMAILS` become **admin** instead. Admins can also
invite people with any role. There are no passwords.

**Demo world.** The seeded demo accounts show their code on screen, so anyone
can use them. They form a separate world: demo and real accounts can never
share with, find, or administer each other, and a demo admin's audit, alerts
and grant review only show demo activity.

## Access levels (what you can do to one document)

| Action | read | edit | owner |
|---|:-:|:-:|:-:|
| See it in lists and search, view metadata | ✓ | ✓ | ✓ |
| Preview it in the app (PDF, image, text) | ✓ | ✓ | ✓ |
| Download the current version | ✓ | ✓ | ✓ |
| See version history, download old versions | | ✓ | ✓ |
| Upload a new version, change title/category/description | | ✓ | ✓ |
| Share, change or revoke grants; ask for AI suggestions | | | ✓ |
| See who accessed it (activity, including refusals) | | | ✓ |
| Delete (to trash), restore, purge | | | ✓ |

Defined in one table, `REQUIRED_LEVEL` in `src/authz.ts`.

### Why these choices

* **Editors cannot share.** If they could, access would spread in chains the
  owner never sees. The owner stays the single point who decides.
* **Readers do not get old versions.** If v1 of a salary letter had the wrong
  figure, the reader is entitled to the current letter, not its history.
* **Admins get no content.** Separation of duties: the person who manages
  accounts is not automatically a reader of HR or legal documents. Sign-in codes only
  go to a person's own inbox, so an admin cannot impersonate anyone (THREATS.md T41).
* **No folders.** Folder inheritance is what turns "see one file" into "see
  forty". Per-document grants are more work to set up, which is the point.
* **External partners are viewer accounts, not links.** A link is a bearer
  token; an account is a named person who can be revoked and audited.

## Special states

* **Trash:** a soft-deleted document is unreachable to everyone, its owner
  included, except for restore and purge. A former grantee gets 404, exactly
  as for an id that never existed. Restoring brings the grants back.
* **Expired grant:** counts as no grant. Nothing has to run for expiry to
  take effect.
* **Deactivated user:** all sessions end, and they fail every check. Their
  grants are kept, so they come back if the user is reactivated.
* **Leaver:** deactivate them, then use *Transfer documents* to move
  ownership to another owner. The recipient must hold the owner role, so an
  admin cannot transfer documents to themselves.

## How it is enforced

```
request ─► sessionMiddleware      (cookie → session row → active user, or nothing)
        ─► csrfMiddleware         (non-GET needs X-TrustVault-CSRF + same origin)
        ─► requireAuth / requireRole
        ─► route handler ─► gate(req, action)
                               └► authorizeDocument(db, user, docId, action)
                                    ├ ACCESS_LEVEL_SQL → 'owner' | 'edit' | 'read' | null
                                    ├ deleted?  → refuse unless owner + restore/purge
                                    └ level ≥ REQUIRED_LEVEL[action]?
                               refused → audit 'denied' → 404 (or 403 if some access)
```

List and search use `ACCESSIBLE_DOCUMENTS_SQL`, built from the same
`ACCESS_LEVEL_SQL`, so they cannot disagree with the single-document check.
