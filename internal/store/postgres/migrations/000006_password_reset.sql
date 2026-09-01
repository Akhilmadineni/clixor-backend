CREATE TABLE password_reset_challenges (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
    attempts smallint NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX password_reset_challenges_user_active
    ON password_reset_challenges(user_id)
    WHERE consumed_at IS NULL;

CREATE INDEX password_reset_challenges_expiry
    ON password_reset_challenges(expires_at);
