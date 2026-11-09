PRAGMA foreign_keys=ON;
-- Canonical schema is also embedded in app.py init_db().
CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','owner','viewer')), active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE documents(id TEXT PRIMARY KEY, original_name TEXT NOT NULL, stored_name TEXT UNIQUE NOT NULL,
 owner_id INTEGER NOT NULL REFERENCES users(id), category TEXT NOT NULL, mime TEXT NOT NULL, size INTEGER NOT NULL,
 sha256 TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE grants(id INTEGER PRIMARY KEY, document_id TEXT NOT NULL REFERENCES documents(id),
 user_id INTEGER NOT NULL REFERENCES users(id), permission TEXT NOT NULL CHECK(permission IN ('read','edit')),
 granted_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, UNIQUE(document_id,user_id));
CREATE TABLE audit(id INTEGER PRIMARY KEY, at TEXT NOT NULL, actor_id INTEGER, actor_name TEXT NOT NULL,
 action TEXT NOT NULL, document_id TEXT, details TEXT NOT NULL, previous_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
