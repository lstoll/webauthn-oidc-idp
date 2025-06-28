CREATE TABLE web_sessions (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    expires_at TEXT NOT NULL
);
