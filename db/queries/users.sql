-- name: CreateUser :exec
INSERT INTO users (id, email, full_name, enrollment_key, override_subject)
VALUES (?, ?, ?, ?, ?);

-- name: CreateUserCredential :exec
INSERT INTO credentials (id, user_id, name, credential_id, credential_data, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetUser :one
SELECT * FROM users WHERE id = ?;

-- name: GetUserByOverrideSubject :one
SELECT * FROM users WHERE override_subject = ?;

-- name: SetUserEnrollmentKey :exec
UPDATE users SET enrollment_key = ? WHERE id = ?;

-- name: GetUsers :many
SELECT * FROM users;

-- name: GetUserCredentials :many
SELECT c.* FROM credentials c
JOIN users u ON c.user_id = u.id
WHERE u.id = ?;

-- name: UpdateCredentialDataByCredentialID :exec
UPDATE credentials SET credential_data = ? WHERE credential_id = ?;
