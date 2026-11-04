# TrustVault

Confidential document sharing where **the wrong person cannot reach a
document**, and where you can **prove who reached it**, including the
attempts that were refused.

* **Sign up and sign in with your email.** There are no passwords: a
  6-digit one-time code is emailed (through Resend), valid for 10 minutes and
  usable once.
* **Upload your own files** by drag and drop (PDF, images, Word, Excel,
  PowerPoint, text, CSV; up to 20 MB). The type is checked from the content.
  Files are encrypted at rest (AES-256-GCM, a fresh key per version).
* **Read files in the app.** PDFs, images and text open in a viewer that can't
  run anything in the file. Download is always available.
* **Share per document, per person**: *Can view* or *Can edit* (edit = new
  versions and details), optionally until a date. Revoking works on the
  person's very next click.
* **Prove who reached it:** every view, preview, download, change, permission
  change and *refused attempt* is in an append-only, HMAC hash-chained audit
  trail. Owners see it per document; admins see everything, with alerts.
* **AI sharing suggestions** that never grant anything on their own.
* React + Tailwind UI with dark mode and a phone layout.

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

**URL:** https://project-1-kxxnvq.fly.dev

**Real accounts:** click *Create account*, enter your name and email, then
type the code from your inbox. You become an **owner**: you can upload and
share. (Admins are the addresses listed in `TV_ADMIN_EMAILS`.)

**Demo accounts** (seeded with `TV_AUTO_SEED=1`) are one click on the sign-in
page. They can't receive email, so **their code is shown on screen**. They
live in a separate demo world that can never see, share with or administer
real accounts (THREATS T60).

| Role | Email | What they have |
|---|---|---|
| admin | `admin@trustvault.demo` | User management and audit of the demo world. **No document access.** |
| owner | `olivia@trustvault.demo` | Owns 2 salary letters and the HR handbook |
| owner | `oscar@trustvault.demo` | Owns a partner contract and an unshared litigation memo |
| viewer | `vera@trustvault.demo` | Can view: her own salary letter and the handbook |
| viewer | `victor@trustvault.demo` | Can view: his own salary letter. Can edit: the handbook |
| viewer (external) | `pat@partner.example` | Can view: the partner contract only |

Things to try:

* Create your own account with your email, upload a file, and share it.
  Notice that you can't share with the demo accounts, and they can't see you.
* Sign in as Vera, then open Victor's salary letter by its URL. You get 404,
  and Olivia's *Activity* tab shows the refusal.
* As Olivia, revoke Vera's grant while Vera has the document open. Vera's
  next click fails.
* As admin, open *Admin → Alerts*, then *Audit*. Try to download any document
  as admin.

## Run locally

Requires **Node.js 22.18 or later**. The server runs TypeScript directly; the
React UI in `web/` is built once with Vite.

```bash
git clone <this repo> && cd trustvault
npm ci
npm run build       # builds the React UI into web/dist
npm run seed        # creates ./data with demo users and documents
npm start           # http://localhost:3000
```

Without `RESEND_API_KEY`, development prints sign-in codes to the server log
(`{"type":"dev_mail",...}`). Production never does this. For UI work, run
`npm start` and `npm run dev:web` (Vite on :5173, proxying /api).

In development, fixed keys derived from a constant are used. Never use them in
production. With `NODE_ENV=production` the server refuses to start without
real keys.

## Tests

```bash
npm test            # 111 tests: isolation, revocation, sign-in codes, demo wall, preview, audit, uploads, CSRF, AI boundary
npm run typecheck
npm run mutate      # removes each authorisation/audit check in turn; the suite must fail for each
npm run mutate -- --important   # only the 41 checks that decide access or evidence (~30 min)
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
| `RESEND_API_KEY` | prod, for real users | Resend API key, used to email sign-in codes. Without it, only demo accounts can sign in. |
| `TV_EMAIL_FROM` | with Resend | Sender, e.g. `TrustVault <login@yourdomain.com>`. Default `onboarding@resend.dev`, Resend's test sender, which **only delivers to your own Resend account's address** until you verify a domain. |
| `TV_ADMIN_EMAILS` | | Comma-separated addresses that become **admin** when they sign up. |
| `TV_SIGNUP_DOMAINS` | | Comma-separated domains allowed to sign up, e.g. `acme.com`. Empty means anyone. |
| `TV_AUTO_SEED` | | `1` seeds demo data on first start (an empty database only). |
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
fly secrets set RESEND_API_KEY=re_xxx TV_EMAIL_FROM='TrustVault <login@yourdomain.com>' TV_ADMIN_EMAILS=you@yourdomain.com
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
  routes/auth.ts    email-code sign-up / sign-in, logout
  auth.ts           sessions, CSRF, role checks, rate limiter
  audit.ts          hash-chained audit log
  crypto.ts         tokens, envelope encryption
  mailer.ts         Resend / dev-log / test mailers
  storage.ts        encrypted blob store
  validation.ts     upload and input validation
  suggest.ts        AI / heuristic sharing suggestions
  db.ts             schema
web/                React + Tailwind UI (Vite), built to web/dist and served by the server
test/               node:test suites
scripts/            seed, mutation check, audit verify
```

## Stack, and why

**Server:** Node 22 + TypeScript (native type stripping) + Express 5 + SQLite
(`node:sqlite`). **UI:** React 19 + Tailwind 4 + Vite, with pdf.js for previews.

* **Every security decision is on the server**, in code in this repository:
  `src/authz.ts` for access, `src/routes/auth.ts` for sign-in, `src/audit.ts`
  for evidence. The React app only hides buttons; removing that code changes
  nothing about what a user can reach.
* **SQLite** makes the audit append and the action it records one
  transaction. Writes are serialised, so the hash chain cannot fork. The cost
  is one instance only; Postgres (with row-level security as a second layer)
  is the next step.
* **The CSP stays strict with React:** `script-src 'self'`, no inline code, no
  `dangerouslySetInnerHTML` anywhere (checkable with `grep`). The only
  additions are `img-src blob:` for image previews and `worker-src 'self'`
  for the bundled pdf.js worker.
