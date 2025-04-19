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
