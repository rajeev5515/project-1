# Instructions for AI assistants working on TrustVault

This file is reused context: it is loaded at the start of every AI coding
session on this repository. It holds the rules that the AI got wrong, or would
plausibly get wrong, in a security-critical codebase.

## Non-negotiables

1. **Authorisation lives in one place.** Document access is decided only by
   `authorizeDocument()` / `ACCESS_LEVEL_SQL` in `src/authz.ts`, and called
   from routes only through `gate(req, action)`. Do not write a second
   "who can see this" query anywhere (search included). Do not add a
   "defence in depth" duplicate check: a duplicate means removing either check
   leaves the tests green, so neither is really tested.
2. **New document route?** Add the action to `DocAction` / `REQUIRED_LEVEL`.
   Call `gate()` before touching the body or the database. Bind every child id
   (version, grant, suggestion) to the document with `AND document_id = ?`.
   Add the route to `allDocumentRoutes()` in `test/isolation.test.ts`, and a
   mutation to `scripts/mutation-check.ts`.
3. **Refuse with 404** when the caller has no access at all. Use 403 only
   when they can already see the document. Never let the status code reveal
   that a document exists, or that it is in the trash.
4. **Every state change writes its audit row inside the same `tx()`.** Every
   refusal writes a `denied` row. There is never an UPDATE or DELETE on
   `audit_log`.
5. **No caching of permissions, no JWTs, no signed URLs.** Revocation must
   take effect on the next request.
6. **AI may suggest, never grant.** Model output is filtered to the
   server-built candidate list. Granting is always a separate request made by
   the owner.
7. **No `innerHTML`** in `public/`. Build DOM with `h()` (textContent only).
8. **Bodies go through `onlyKeys()`.** Unknown fields are a 400.

## Before saying something is done

* `npm test` and `npm run typecheck` pass.
* For an authz or audit change: `npm run mutate -- <id>` kills the
  relevant mutant.
* Update THREATS.md if the change affects a threat, and add a PROMPTS.md
  entry if the AI got something wrong along the way.

## Review prompt (reused)

> Review this diff as an attacker with a valid low-privilege account. For each
> new or changed route, list: which `gate()` action it uses, whether every id
> in the URL or body is bound to the gated document, what is written to the
> audit trail on success AND on refusal, and whether the status code differs
> between "does not exist" and "not yours". Then name one test that would fail
> if the check were deleted. If you cannot name one, say so.
