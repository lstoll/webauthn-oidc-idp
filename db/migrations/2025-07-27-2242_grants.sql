CREATE TABLE grants (
    id TEXT PRIMARY KEY, -- UUID for the grant
    auth_code TEXT UNIQUE, -- Authorization code, if present
    refresh_token TEXT UNIQUE, -- Refresh token, if present
    user_id TEXT NOT NULL, -- User ID that was granted access
    client_id TEXT NOT NULL, -- Client ID that was granted access
    granted_scopes TEXT NOT NULL, -- JSON array of granted scopes
    request_data BLOB NOT NULL, -- JSON marshaled request data
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the grant was created
    expires_at DATETIME NOT NULL -- When the grant expires
);

CREATE INDEX idx_grants_auth_code ON grants (auth_code);
CREATE INDEX idx_grants_refresh_token ON grants (refresh_token);
CREATE INDEX idx_grants_expires_at ON grants (expires_at);
CREATE INDEX idx_grants_user_id ON grants (user_id);
CREATE INDEX idx_grants_client_id ON grants (client_id);
