CREATE TABLE pending_enrollments (
    id TEXT PRIMARY KEY NOT NULL,
    user_id TEXT NOT NULL,
    enrollment_key TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL,
    confirmation_key TEXT,
    credential_id BLOB,
    credential_data JSON,
    name TEXT
);

CREATE INDEX idx_pending_enrollments_user_id ON pending_enrollments (user_id);
CREATE INDEX idx_pending_enrollments_created_at ON pending_enrollments (created_at);

CREATE TABLE dynamic_clients (
    id TEXT PRIMARY KEY NOT NULL,
    active BOOLEAN NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL,
    client_secret TEXT NOT NULL,
    registration_blob JSON NOT NULL
);

CREATE INDEX idx_dynamic_clients_expires_at ON dynamic_clients (expires_at);
CREATE INDEX idx_dynamic_clients_created_at ON dynamic_clients (created_at);
