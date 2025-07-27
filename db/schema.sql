CREATE TABLE migrations (
		idx integer primary key not null,
		at datetime not null
		);

CREATE TABLE tink_keysets (
    id TEXT PRIMARY KEY,
    keyset_data BLOB NOT NULL,
    metadata_data BLOB NOT NULL,
    version INTEGER NOT NULL
);

CREATE TABLE users
-- Users of the system
(
    id TEXT PRIMARY KEY, -- ID for the user, uuid
    email TEXT UNIQUE NOT NULL, -- Email address for the user
    full_name TEXT NOT NULL, -- Full name for the user
    enrollment_key TEXT, -- Key used to enroll tokens for the user
    override_subject TEXT UNIQUE, -- Subject to use for the user, if provided
    webauthn_handle TEXT UNIQUE NOT NULL -- webauthn user handle, registered with authenticators. uuidv4.
);

CREATE TABLE credentials
-- Webauthn credentials
(
    id TEXT PRIMARY KEY, -- ID for the credential, uuid
    credential_id BLOB NOT NULL, -- ID for the credential, opaque bytes from go-webauthn credemtial data
    user_id TEXT NOT NULL, -- ID for the user
    name TEXT NOT NULL, -- Name for the credential
    credential_data BLOB NOT NULL, -- Credential data from go-webauthn, JSON encoded
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, -- When the credential was created
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE web_sessions (
    id TEXT PRIMARY KEY,
    data BLOB NOT NULL,
    expires_at TEXT NOT NULL
);

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

