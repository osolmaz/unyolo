-- name: Health :one
SELECT 1;

-- name: PutPlan :exec
INSERT INTO plans (digest, schema_name, canonical, created_at)
VALUES (?, ?, ?, ?)
ON CONFLICT(digest) DO NOTHING;

-- name: GetPlan :one
SELECT digest, schema_name, canonical, created_at
FROM plans
WHERE digest = ?;

-- name: CountPlans :one
SELECT count(*) FROM plans;
