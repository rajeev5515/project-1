# TrustVault — write-up

## What I built

A document-sharing service built around three promises: only people who were
granted a document can reach it; you can prove afterwards who did, including
the attempts that were refused; and taking access away works on the very next
request.

* **Accounts and roles:** admin, owner, viewer. External partners are viewer
  accounts.
* **Documents:** upload (validated by content, not just name), version
  history, edit metadata, soft delete to a trash, restore, and purge (crypto
  shredding).
* **Sharing:** per document, per named person, `read` or `edit`, with an
  optional expiry. Only the owner shares.
* **Search** by title or description, owner, category and date range, plus
  "mine / shared with me". Every search goes through the same access rule as
  single-document requests.
* **Audit:** every view, download, upload, change, deletion, permission change,
  sign-in and refusal. Append-only triggers, an HMAC hash chain, and the
  chain head mirrored to stdout for the platform log. Verified at startup,
  hourly, on demand and offline.
* **Admin console:** users (create, role, deactivate, reset password, end
  sessions, transfer a leaver's documents), audit search, current-grant
  review, permission-change history, chain status, and alerts.
* **Owner view:** the full activity of each of their documents, including who
  was refused.
* **AI sharing suggestions.** Claude ranks candidates when an API key is set;
  otherwise a heuristic is used. It never grants. The owner confirms, and
  the suggestion, acceptance and dismissal are each audited.
* **Tests:** 93 tests. A mutation script removes each of 55 authorisation and
  audit checks in turn and confirms the suite fails.

## My permission model, in my own words

A document belongs to one person. That person decides, name by name, who may
read it and who may also edit it, and for how long. Editing never includes
sharing, so access cannot spread without the owner. There are no folders and
no groups, because inheritance is how "I gave them one file" becomes "they can
see forty". An administrator runs the accounts and reads the audit trail, but
gets no access to content from their role. If they want to read a salary
letter, they have to go through a password reset, which is audited, raises an
alert, and locks the real user out in a way they will notice. The server
works out access from the database on every request: a grant revoked a
millisecond ago is gone, an expired grant is gone, a deactivated person is
gone. The only credential ever issued is an opaque session cookie, and it
carries no permissions.

The decision is `authorizeDocument()` in `src/authz.ts`, called through
`gate()` in `src/routes/documents.ts`. For a download, it happens on the line
`const { doc } = gate(req, 'download');` in the `/:id/download` handler.
Remove the `if (!result.allowed)` block in `gate()` and every document leaks to
every signed-in user; 7 test files fail.

## What I deliberately did not build

* **Public share links.** A link is a bearer token, and bearer tokens leak.
  External people get accounts.
* **Folders, groups and inheritance.** See above. Groups would be the next
  feature.
* **Signed or expiring download URLs, or JWT sessions.** Each would add a
  window after revocation.
* **MFA and SSO.** The biggest gap. SSO would also remove admin password
  resets, which is the main accepted risk (THREATS T41).
* **Malware scanning, watermarking, DRM, retention and legal hold.**
* **Multi-instance or high availability.** SQLite and an in-memory rate
  limiter tie it to one instance.

## How I used AI, and where it was wrong

The whole codebase was written with an AI coding agent (Claude Code). The
entries in PROMPTS.md are the cases where its output was wrong and was caught.
In short:

1. It wanted a second, "defence in depth" access filter on search, which
   would have made each check individually untestable.
2. The per-IP login limiter counted successful logins, which would lock out an
   office behind one NAT address.
3. **Authorisation:** a former grantee calling `restore` on a trashed
   document got 403 instead of 404, which confirms the document exists.
4. The multipart parser hung forever on malformed input, because busboy emits
   `error` instead of `close`.
5. Mutation testing: see PROMPTS.md for which checks the first version of
   the tests did not actually cover.

The pattern I took from this: the AI writes plausible authorisation code
quickly, and its own tests pass. The bugs only showed up when the tests were
written from the attacker's side ("every route × every stranger") and when
checks were deleted to see whether anything noticed. CLAUDE.md holds the rules
I now give it up front.

## What is unfinished

* **No live deployment and no demo video yet.** I could not deploy from the
  build environment (no hosting credentials there). `render.yaml`, `fly.toml`
  and the Dockerfile are ready; the README has the steps.
* Audit tail-truncation detection relies on an operator comparing against
  the platform log. Shipping heads to WORM storage automatically is not
  built.
* No key rotation for `TV_MASTER_KEY` or `TV_AUDIT_KEY`.
* The rate limiter is in memory.
* Alerts are computed on request, not pushed (no email or Slack).
* The UI is functional, not polished.
