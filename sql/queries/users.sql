-- name: CreateUser :one
INSERT INTO users(id, created_at, updated_at, email, hashed_password)
VALUES(gen_random_uuid(),NOW(),NOW(),$1, $2)
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: Reset :exec
DELETE FROM users;

-- name: UpdateUser :one
UPDATE users
SET email = $2,
hashed_password = $3,
updated_at = NOW()
WHERE id = $1
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: UpdateToRed :exec
UPDATE users
SET is_chirpy_red = true
WHERE id = $1;
