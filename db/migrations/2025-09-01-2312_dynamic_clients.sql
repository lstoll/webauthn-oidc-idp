-- Dynamic clients table to store OIDC dynamic client registrations
CREATE TABLE dynamic_clients (
    id TEXT PRIMARY KEY, -- Prefixed UUID (dc.<uuidv4>)
    client_secret_hash TEXT NOT NULL, -- SHA256 hash of the actual client secret
    registration_blob TEXT NOT NULL, -- JSON blob containing the complete OIDC client registration
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the client was created
    expires_at DATETIME NOT NULL, -- When the client expires (14 days after creation)
    active BOOLEAN NOT NULL DEFAULT TRUE -- Whether the client is active
);

-- Index for efficient client lookup and expiration checks
CREATE INDEX idx_dynamic_clients_active_expires ON dynamic_clients(active, expires_at);
CREATE INDEX idx_dynamic_clients_id_active ON dynamic_clients(id, active);
