-- name: CreateDynamicClient :exec
INSERT INTO dynamic_clients (
    id, client_secret_hash, registration_blob, expires_at
) VALUES (
    ?, ?, ?, ?
);

-- name: GetDynamicClient :one
SELECT * FROM dynamic_clients
WHERE id = ? AND active = TRUE AND expires_at > datetime('now');

-- name: GetDynamicClientBySecretHash :one
SELECT * FROM dynamic_clients
WHERE client_secret_hash = ? AND active = TRUE AND expires_at > datetime('now');

-- name: ListActiveDynamicClients :many
SELECT * FROM dynamic_clients
WHERE active = TRUE AND expires_at > datetime('now')
ORDER BY created_at DESC;

-- name: DeactivateDynamicClient :exec
UPDATE dynamic_clients
SET active = FALSE
WHERE id = ?;

-- name: CleanupExpiredDynamicClients :exec
DELETE FROM dynamic_clients
WHERE expires_at <= datetime('now') OR active = FALSE;
