-- Unique @username for pilot discovery (stored in profile JSON; normalized without leading @).
-- Empty / missing username is allowed until profile setup completes.

CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique
ON users (
  lower(regexp_replace(COALESCE(profile->>'username', ''), '^@+', ''))
)
WHERE COALESCE(profile->>'username', '') <> '';
