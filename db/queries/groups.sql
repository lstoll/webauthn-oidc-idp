-- name: CreateGroup :one
INSERT INTO groups (id, name, description, active)
VALUES (?, ?, ?, ?)
RETURNING *;

-- name: GetGroup :one
SELECT * FROM groups WHERE id = ?;

-- name: GetGroupByName :one
SELECT * FROM groups WHERE name = ?;

-- name: ListGroups :many
SELECT * FROM groups ORDER BY name;

-- name: ListActiveGroups :many
SELECT * FROM groups WHERE active = TRUE ORDER BY name;

-- name: UpdateGroup :one
UPDATE groups
SET name = ?, description = ?, active = ?, updated_at = CURRENT_TIMESTAMP
WHERE id = ?
RETURNING *;

-- name: DeleteGroup :exec
DELETE FROM groups WHERE id = ?;

-- name: AddUserToGroup :one
INSERT INTO user_groups (id, user_id, group_id, start_date, end_date)
VALUES (?, ?, ?, ?, ?)
RETURNING *;

-- name: GetUserGroupMembership :one
SELECT * FROM user_groups WHERE id = ?;

-- name: GetUserActiveGroupMemberships :many
SELECT ug.*, g.name as group_name, g.description as group_description
FROM user_groups ug
JOIN groups g ON ug.group_id = g.id
WHERE ug.user_id = ?
  AND g.active = TRUE
  AND (ug.end_date IS NULL OR ug.end_date > CURRENT_TIMESTAMP)
ORDER BY g.name;

-- name: GetUserGroupMemberships :many
SELECT ug.*, g.name as group_name, g.description as group_description
FROM user_groups ug
JOIN groups g ON ug.group_id = g.id
WHERE ug.user_id = ?
ORDER BY g.name, ug.start_date DESC;

-- name: RemoveUserFromGroup :exec
UPDATE user_groups
SET end_date = CURRENT_TIMESTAMP
WHERE user_id = ? AND group_id = ? AND (end_date IS NULL OR end_date > CURRENT_TIMESTAMP);

-- name: CheckUserInGroup :one
SELECT COUNT(*) as count
FROM user_groups ug
JOIN groups g ON ug.group_id = g.id
WHERE ug.user_id = ?
  AND g.name = ?
  AND g.active = TRUE
  AND (ug.end_date IS NULL OR ug.end_date > CURRENT_TIMESTAMP);
