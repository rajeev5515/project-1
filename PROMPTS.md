# PROMPTS.md — how AI was used to build TrustVault

This file is written as the work happens. Each entry says what the tool was
asked, what it produced, what was wrong with it, and what was done instead,
with the commit that fixed it. Dates are real commit dates.

The tool used was Claude Code (an AI coding agent) running against this
repository. The "reusable context" section at the end holds the instructions
reused across sessions.

---

## Entry 1 — 2026-11-04 — Initial build brief and architecture

**Asked:** The full challenge brief (three non-negotiables: server decides every
access, provable record including refusals, revocation is immediate), and to
pick a stack that could be defended in an interview.

**Produced:** A plan for Node 22 + TypeScript (run with native type
stripping, no build step) + Express 5 + SQLite (`node:sqlite`) + a vanilla JS
front end with a strict CSP. Key choices: opaque server-side sessions instead
of JWTs (so revocation is a database write), one authorisation function shared
by single-document routes and the search query, envelope-encrypted blobs, an
HMAC-chained append-only audit table.

**What was wrong / what I changed:** The first sketch of the search endpoint
filtered results with its own `owner_id = ? OR EXISTS(grant)` SQL, separate
from the single-document check. That gives two definitions of "who can see
this", and they drift: a later change to grant expiry would have to be made in
two places, and forgetting one is a leak through search. Changed so that
`src/authz.ts` exports `ACCESS_LEVEL_SQL`, used by both `authorizeDocument()`
and the list query. A second suggestion was to filter the search results in
JavaScript *as well* "for defence in depth"; rejected, because a redundant
check means removing either one leaves the tests green, which is exactly the
mutation test the brief describes. One rule, tested, beats two rules where
neither is.

Commit: [8211876](https://github.com/rajeev5515/project-1/commit/8211876) (`src/authz.ts`, list query in `src/routes/documents.ts`).

---

## Entry 2 — 2026-11-04 — Login rate limiting (authentication)

**Asked:** Add brute-force protection to `POST /api/auth/login`: per-account
lockout and a per-IP limit.

**Produced:** A per-account lockout (5 failures → 15 minutes) and a fixed-window
`RateLimiter` per IP that called `hit()` at the top of the handler, before the
password was checked.

**What was wrong:** `hit()` before the check counts **every** attempt,
including successful ones. Twenty people signing in from one office NAT
address within 15 minutes would get `429` for everyone after that, and that
is the normal case for a company. It showed up when the isolation test suite,
which logs in 20+ times from 127.0.0.1, started failing with 429 on valid
credentials. The generated code had no test for "valid logins are not
limited". It only had the abstract "limit is 20".

**What I did instead:** Added `RateLimiter.blocked()` (a check that does not
count) and call `hit()` only on failures. Successful sign-ins never consume
the budget. Test: `security › T15 › many failures from one IP are rate
limited`, which also asserts that a blocked IP is refused even with valid
credentials while the window lasts.

Commit: [93abc84](https://github.com/rajeev5515/project-1/commit/93abc84)

---

## Entry 3 — 2026-11-04 — Deleted documents leaked their existence (authorisation)

**Asked:** Add soft delete with a trash, restore and purge, owner-only, and
make deleted documents unreachable for grantees.

**Produced:** In `authorizeDocument()`:

```ts
const isTrashAction = TRASH_ACTIONS.has(action);
if (doc.deleted_at !== null && !isTrashAction) return { allowed: false, reason: 'deleted', access };
...
if (RANK[access] < RANK[REQUIRED_LEVEL[action]]) return { allowed: false, reason: 'insufficient', access };
```

It looked right, and the AI's own happy-path test (owner deletes, grantee gets
404 on download) passed.

**What was wrong:** For `restore` and `purge` the deleted check is skipped, so
a **former grantee** falls through to the level check and gets
`insufficient`, which `gate()` maps to **403**. For an id that does not exist
the answer is 404. So anyone who was ever granted a document could tell
whether it was sitting in the owner's trash or had been purged: an existence
oracle on exactly the documents someone tried to take away from them. Caught
by the test `revocation › T12 › …only the owner can restore`, which I wrote
from the attacker's side (a former grantee calls every trash route) rather
than the owner's.

**What I did instead:** For a deleted document, anyone who is not the owner
gets `deleted` (→ 404) on **every** action. The owner gets only restore and
purge. Added `authz.test › a deleted document…`, which asserts the *reason*
(`deleted`) for the grantee on every action, and a mutation
(`authz-deleted-grantee-trash`) that reintroduces the bug and must be caught.

Commit: [0b440d4](https://github.com/rajeev5515/project-1/commit/0b440d4)

---

## Entry 4 — 2026-11-04 — Upload parser hung on malformed input

**Asked:** A multipart upload parser with busboy: one file, a size limit,
refuse rather than truncate oversized files.

**Produced:** `parseUpload()` that resolved or rejected only in busboy's
`close` handler, and mapped `error` to "remember the failure".

**What was wrong:** On malformed input (here, a NUL byte in a filename from
my path-traversal test) busboy emits `error` and **never** `close`. The
promise never settled, so the request hung, holding its memory, until the
client gave up. Anyone could tie up server connections by sending a broken
multipart body. Found because the security suite hung for 120 seconds instead
of failing; I bisected it to that test with a 5-second watchdog script.

**What I did instead:** A single `settle()` called from `error`, `close` and
`req.on('aborted')`. It unpipes and drains the request, and rejects with 400.
Added `security › T16 › malformed multipart is refused promptly instead of
hanging the request`, which sends both a NUL filename and a body with a
boundary but no parts, and asserts a 400 in under 5 seconds. The sanitiser is
now unit-tested separately (`sanitizeFilename strips control characters…`),
because busboy rejects most control characters before our code sees them,
which the original test had assumed it would not.

Commit: [d1ddd1a](https://github.com/rajeev5515/project-1/commit/d1ddd1a)

---

## Entry 5 — 2026-11-04 — The AI sharing suggestion recommended exactly the wrong person (access control)

**Asked:** "Suggest who should see a document: rank people the owner already
shares with, prefer the same category. Never grant automatically. Fall back
to a heuristic when there is no API key."

**Produced:** `src/suggest.ts`, with a candidate query of "users this owner
has granted other documents to, ranked by same-category count", and a
`stop_reason === 'refusal'` branch that returned an empty list. The tests it
wrote checked the boundary properly (no grant is created, the suggestion and
the decision are audited, ids outside the candidate list are dropped), and
they passed.

**What was wrong:** When I opened the UI in a browser (Playwright screenshot)
on *Vera's salary letter*, the top suggestion was **Victor**: "You have shared
2 other documents in this category with them". One of those two was
Victor's *own* salary letter. The heuristic took "Olivia shares HR documents
with Victor" as evidence that Victor should see Vera's pay. That is the most
damaging suggestion it could have made for this document, phrased with
confidence. The rule "the machine never widens access" held, because the
owner still has to click Confirm, but a suggestion like this one trains
people to click Confirm on bad advice. Separately, the refusal branch
returned `[]`, which the UI shows as "No suggestions": a model refusal
silently turned into "nobody needs access".

**What I did instead:**
* Only documents shared with **two or more** people count as evidence of
  working together. A single-recipient document (salary letter, personal
  contract) is personal and says nothing about anyone else.
* The reason text now says "team document" and tells the owner to check that
  this document is not personal to someone else.
* Any `stop_reason` other than `end_turn` falls back to the heuristic,
  with a note shown to the owner.
* Test `security › T22e … Victor is not suggested for Vera's salary letter…`,
  and mutation `ai-personal-docs`, which removes the rule and is killed by
  that test.

The lesson for the interview: the boundary tests passed and were correct.
The failure was in the *quality* of the advice, and it only showed up by
looking at real data in the real UI.

Commit: [8b7e2f7](https://github.com/rajeev5515/project-1/commit/8b7e2f7)
