-- Drop existing indexes on the columns we're changing
DROP INDEX idx_grants_auth_code;
DROP INDEX idx_grants_refresh_token;

-- SQLite doesn't support dropping UNIQUE constraints directly, so we need to recreate the table
-- Create new table with BLOB columns included
CREATE TABLE grants_new (
    id TEXT PRIMARY KEY, -- UUID for the grant
    auth_code BLOB, -- Authorization code, if present
    refresh_token BLOB, -- Refresh token, if present
    user_id TEXT NOT NULL, -- User ID that was granted access
    client_id TEXT NOT NULL, -- Client ID that was granted access
    granted_scopes TEXT NOT NULL, -- JSON array of granted scopes
    request_data BLOB NOT NULL, -- JSON marshaled request data
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the grant was created
    expires_at DATETIME NOT NULL -- When the grant expires
);

-- Copy data from old table to new table (excluding the columns we're changing)
INSERT INTO grants_new SELECT id, NULL, NULL, user_id, client_id, granted_scopes, request_data, created_at, expires_at FROM grants;

-- Drop the old table
DROP TABLE grants;

-- Rename new table to original name
ALTER TABLE grants_new RENAME TO grants;

-- Recreate all indexes
CREATE INDEX idx_grants_auth_code ON grants (auth_code);
CREATE INDEX idx_grants_refresh_token ON grants (refresh_token);
CREATE INDEX idx_grants_expires_at ON grants (expires_at);
CREATE INDEX idx_grants_user_id ON grants (user_id);
CREATE INDEX idx_grants_client_id ON grants (client_id);
