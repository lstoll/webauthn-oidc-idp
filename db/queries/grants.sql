-- name: CreateGrant :exec
INSERT INTO grants (id, auth_code, refresh_token, user_id, client_id, granted_scopes, request_data, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: UpdateGrant :exec
UPDATE grants
SET auth_code = ?, refresh_token = ?, user_id = ?, client_id = ?, granted_scopes = ?, request_data = ?, expires_at = ?
WHERE id = ?;

-- name: ExpireGrant :exec
UPDATE grants SET expires_at = datetime('now') WHERE id = ?;

-- name: GetGrant :one
SELECT id, auth_code, refresh_token, user_id, client_id, granted_scopes, request_data, created_at, expires_at
FROM grants
WHERE id = ? AND expires_at > datetime('now');

-- name: GetGrantByAuthCode :one
SELECT id, auth_code, refresh_token, user_id, client_id, granted_scopes, request_data, created_at, expires_at
FROM grants
WHERE auth_code = ? AND expires_at > datetime('now');

-- name: GetGrantByRefreshToken :one
SELECT id, auth_code, refresh_token, user_id, client_id, granted_scopes, request_data, created_at, expires_at
FROM grants
WHERE refresh_token = ? AND expires_at > datetime('now');

-- name: CleanupExpiredGrants :exec
DELETE FROM grants WHERE expires_at <= datetime('now');
