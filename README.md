# TrustVault

Confidential document sharing where **the wrong person cannot reach a
document**, and where you can **prove who reached it**, including the
attempts that were refused.

* Per-document grants (`read` / `edit`) to named people, optionally
  time-limited. Every request is checked on the server; nothing is cached, so
  revocation takes effect on the next request.
* Files are encrypted at rest (AES-256-GCM, a fresh key per version, wrapped by
  a master key) and are only ever served as attachments after the check.
* A tamper-evident audit trail: append-only in the database, HMAC hash-chained,
  with the chain head mirrored to the platform log stream.
* An admin console with alerts (access probing, password spraying, bulk
  downloads, privileged changes, broken audit chain).
* Optional AI suggestions of who to share with. They never grant anything on
  their own; the owner confirms, and both steps are audited.

| Document | What is in it |
|---|---|
| [THREATS.md](THREATS.md) | 50+ threats: what stops each one, what was accepted, and which test covers it |
| [PROMPTS.md](PROMPTS.md) | How AI was used, and where it was wrong |
| [WRITEUP.md](WRITEUP.md) | What was built, what wasn't, and what is unfinished |
| [docs/PERMISSIONS.md](docs/PERMISSIONS.md) | Roles, access levels, and where the decision is made |
| [docs/API.md](docs/API.md) | Every endpoint and who may call it |
| [docs/schema.sql](docs/schema.sql) | Database schema (applied automatically at startup) |
| [docs/mutation-results.txt](docs/mutation-results.txt) | Results of removing each authorisation check and re-running the tests |

## Live demo

**URL:** _not deployed yet. See "Deploy" below. Fill this in after the first
deploy._

Seeded accounts (created automatically when `TV_AUTO_SEED=1`):

| Role | Email | Password | What they have |
|---|---|---|---|
| admin | `admin@trustvault.demo` | `Admin-Demo-2026!` | User management and audit. **No document access.** |
| owner | `olivia@trustvault.demo` | `Owner-Demo-2026!` | Owns 2 salary letters and the HR handbook |
| owner | `oscar@trustvault.demo` | `Owner-Demo-2026!` | Owns a partner contract and an unshared litigation memo |
| viewer | `vera@trustvault.demo` | `Viewer-Demo-2026!` | Read: her own salary letter and the handbook |
| viewer | `victor@trustvault.demo` | `Viewer-Demo-2026!` | Read: his own salary letter. Edit: the handbook |
| viewer (external) | `pat@partner.example` | `Viewer-Demo-2026!` | Read: the partner contract only |

Things to try:

* Sign in as Vera, then open Victor's salary letter by id. You get 404, and
  Olivia's activity log shows the refusal.
* As Olivia, revoke Vera's grant while Vera has the document open. Vera's
  next click fails.
* As admin, open *Admin → Alerts*, then *Audit*. Try to download any document
  as admin.

## Run locally

Requires **Node.js 22.18 or later**. It runs TypeScript directly; there is no
build step.

```bash
git clone <this repo> && cd trustvault
npm ci
npm run seed        # creates ./data with demo users and documents
npm start           # http://localhost:3000
```

In development, fixed keys derived from a constant are used. Never use them in
production. With `NODE_ENV=production` the server refuses to start without
real keys.

## Tests

```bash
npm test            # 93 tests: isolation, revocation, audit, uploads, CSRF, sessions, AI boundary
npm run typecheck
npm run mutate      # removes each authorisation/audit check in turn; the suite must fail for each
npm run verify-audit [-- <seq> <hash>]   # offline chain verification
```

Test names carry the THREATS.md id they cover, for example `T07`.

## Configuration

| Variable | Required | Meaning |
|---|---|---|
| `NODE_ENV` | | `production` enables Secure cookies and HSTS, and requires real keys |
| `TV_MASTER_KEY` | prod | 64 hex characters. Wraps every file's data key. Losing it means losing every file. |
| `TV_AUDIT_KEY` | prod | 64 hex characters, different from the master key. Signs the audit chain. |
| `TV_DATA_DIR` | | Database and blobs. Default `./data`. Must be persistent storage. |
| `TV_PUBLIC_ORIGIN` | recommended | For example `https://trustvault.example.com`. Used for the Origin check. |
| `TV_TRUST_PROXY` | | `1` only when behind exactly one trusted proxy (Render, Fly). Without it, client IPs come from the socket. |
| `TV_AUTO_SEED` | | `1` seeds demo data on first start (an empty database only). |
| `TV_SEED_PASSWORD` | | Overrides every demo password. |
| `ANTHROPIC_API_KEY` | | Enables Claude-ranked sharing suggestions. Without it, a local heuristic is used. |
| `TV_AI_MODEL` | | Default `claude-opus-5-5`. |
| `PORT` | | Default 3000. |

Generate keys with `openssl rand -hex 32` (run it twice).

## Deploy

Any host that runs a Docker image with **one instance and a persistent disk**
will work. Why a single instance: the database is SQLite and the rate limiter
is in memory (see THREATS.md T15b and T52).

**Render.** Push the repository, then *New → Blueprint* and pick
`render.yaml`. Set `TV_MASTER_KEY`, `TV_AUDIT_KEY` and `TV_PUBLIC_ORIGIN` when
prompted.

**Fly.io**

```bash
fly launch --no-deploy --copy-config
fly volumes create trustvault_data --size 1
fly secrets set TV_MASTER_KEY=$(openssl rand -hex 32) TV_AUDIT_KEY=$(openssl rand -hex 32) TV_PUBLIC_ORIGIN=https://<app>.fly.dev
fly deploy
```

**Plain Docker**

```bash
docker build -t trustvault .
docker run -d -p 8080:8080 -v trustvault-data:/data \
  -e TV_MASTER_KEY=$(openssl rand -hex 32) -e TV_AUDIT_KEY=$(openssl rand -hex 32) \
  -e TV_PUBLIC_ORIGIN=http://localhost:8080 -e TV_AUTO_SEED=1 trustvault
```

(Over plain HTTP on localhost, browsers drop the Secure cookie. For a local
Docker test, also set `-e NODE_ENV=development` and pass the keys.)

**Operating it**

* Keep the two keys in the platform's secret store, and back them up
  separately from the data. A data backup without the keys cannot be read.
* The platform log keeps one line per audit append:
  `{"type":"audit_head","seq":…,"hash":…}`. To check that nobody removed recent
  entries, take the latest one and run `npm run verify-audit -- <seq> <hash>`,
  or open `/api/admin/audit/verify?seq=…&hash=…`.
* The chain is verified at startup and every hour. A failure appears as a
  critical alert in *Admin → Alerts* and as `{"type":"audit_verify","ok":false}`
  in the log.

## Layout

```
src/
  authz.ts          the authorisation decision (read this first)
  routes/documents.ts  gate() + every document route
  routes/admin.ts   admin, directory, alerts
  routes/auth.ts    login, logout, password change
  auth.ts           sessions, CSRF, role checks, rate limiter
  audit.ts          hash-chained audit log
  crypto.ts         scrypt, tokens, envelope encryption
  storage.ts        encrypted blob store
  validation.ts     upload and input validation
  suggest.ts        AI / heuristic sharing suggestions
  db.ts             schema
public/             UI (vanilla JS, no innerHTML, CSP script-src 'self')
test/               node:test suites
scripts/            seed, mutation check, audit verify
```

## Stack, and why

Node 22 + TypeScript (native type stripping) + Express 5 + SQLite
(`node:sqlite`), and plain JavaScript in the browser.

* **Few moving parts I can explain line by line.** There are three runtime
  dependencies. Every security property is in code in this repository, not in
  framework configuration.
* **SQLite** makes the audit append and the action it records one
  transaction. Writes are serialised, so the hash chain cannot fork. The cost
  is one instance only; Postgres (with row-level security as a second layer)
  is the next step.
* **No front-end framework**, so the CSP can be strict (`script-src 'self'`,
  no inline code) and the rule "never `innerHTML`" can be checked with
  `grep`.
