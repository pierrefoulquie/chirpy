-- name: GetUser :one
SELECT * FROM users
WHERE email = $1;

-- name: GenerateRefreshToken :exec
INSERT INTO refresh_tokens(token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES ($1, NOW(), NOW(), $2, (NOW() + INTERVAL '60 days'), NULL);

-- name: ValidateRefreshToken :one
SELECT * FROM refresh_tokens
WHERE token = $1;


-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW(), updated_at = NOW()
WHERE token = $1;

