PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('member', 'admin')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1))
) STRICT;

CREATE TABLE IF NOT EXISTS sessions (
    token_hash BLOB PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    expires_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS documents (
    id TEXT PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    filename TEXT NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS payloads (
    document_id TEXT PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
    data_nonce BLOB NOT NULL,
    wrap_nonce BLOB NOT NULL UNIQUE,
    wrapped_key BLOB NOT NULL,
    ciphertext BLOB NOT NULL
) STRICT;

CREATE TABLE IF NOT EXISTS grants (
    document_id TEXT NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id),
    role TEXT NOT NULL CHECK (role IN ('viewer', 'editor')),
    expires_at INTEGER,
    PRIMARY KEY (document_id, user_id)
) STRICT;

CREATE INDEX IF NOT EXISTS grants_by_user ON grants(user_id, document_id);

CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY,
    recorded_at INTEGER NOT NULL,
    actor_id INTEGER,
    action TEXT NOT NULL,
    document_id TEXT,
    outcome TEXT NOT NULL,
    detail TEXT,
    mac BLOB NOT NULL
) STRICT;

CREATE INDEX IF NOT EXISTS audit_login ON audit(action, outcome, detail, recorded_at);

CREATE TABLE IF NOT EXISTS audit_head (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    seq INTEGER NOT NULL,
    last_mac BLOB NOT NULL,
    signature BLOB NOT NULL
) STRICT;
