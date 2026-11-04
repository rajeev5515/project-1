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

Commit: see `git log --grep "core backend"`.
