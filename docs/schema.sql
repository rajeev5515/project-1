-- TrustVault schema (generated from src/db.ts; the app applies it, plus additive migrations, at startup)
CREATE TABLE IF NOT EXISTS users (
  id              TEXT PRIMARY KEY,
  email           TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name            TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  password_hash   TEXT NOT NULL,
  active          INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  failed_logins   INTEGER NOT NULL DEFAULT 0,
  locked_until    INTEGER,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash    TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id),
  created_at    INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  revoked_at    INTEGER,
  ip            TEXT,
  user_agent    TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS documents (
  id                 TEXT PRIMARY KEY,
  owner_id           TEXT NOT NULL REFERENCES users(id),
  title              TEXT NOT NULL,
  category           TEXT NOT NULL,
  description        TEXT NOT NULL DEFAULT '',
  current_version_id TEXT,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL,
  deleted_at         INTEGER,
  deleted_by         TEXT REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);

CREATE TABLE IF NOT EXISTS document_versions (
  id           TEXT PRIMARY KEY,
  document_id  TEXT NOT NULL REFERENCES documents(id),
  version_no   INTEGER NOT NULL,
  filename     TEXT NOT NULL,
  mime_type    TEXT NOT NULL,
  size_bytes   INTEGER NOT NULL,
  sha256       TEXT NOT NULL,
  storage_key  TEXT NOT NULL UNIQUE,
  wrapped_key  TEXT NOT NULL,
  uploaded_by  TEXT NOT NULL REFERENCES users(id),
  created_at   INTEGER NOT NULL,
  UNIQUE (document_id, version_no)
);

CREATE TABLE IF NOT EXISTS grants (
  id          TEXT PRIMARY KEY,
  document_id TEXT NOT NULL REFERENCES documents(id),
  user_id     TEXT NOT NULL REFERENCES users(id),
  permission  TEXT NOT NULL CHECK (permission IN ('read','edit')),
  granted_by  TEXT NOT NULL REFERENCES users(id),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER,
  UNIQUE (document_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);

CREATE TABLE IF NOT EXISTS ai_suggestions (
  id           TEXT PRIMARY KEY,
  document_id  TEXT NOT NULL REFERENCES documents(id),
  requested_by TEXT NOT NULL REFERENCES users(id),
  source       TEXT NOT NULL,
  suggestions  TEXT NOT NULL,
  created_at   INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL,
  actor_id     TEXT,
  actor_email  TEXT,
  action       TEXT NOT NULL,
  outcome      TEXT NOT NULL CHECK (outcome IN ('success','denied','failure')),
  document_id  TEXT,
  target_user_id TEXT,
  ip           TEXT,
  details      TEXT NOT NULL,
  prev_hash    TEXT NOT NULL,
  hash         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_log(document_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);

CREATE TABLE IF NOT EXISTS login_challenges (
  id           TEXT PRIMARY KEY,
  email        TEXT NOT NULL COLLATE NOCASE,
  purpose      TEXT NOT NULL CHECK (purpose IN ('login','signup')),
  signup_name  TEXT,
  code_hash    TEXT NOT NULL,
  created_at   INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  attempts     INTEGER NOT NULL DEFAULT 0,
  consumed_at  INTEGER,
  ip           TEXT
);
CREATE INDEX IF NOT EXISTS idx_challenges_email ON login_challenges(email);

CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

-- Migration (src/db.ts migrate()): ALTER TABLE users ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0,1));
