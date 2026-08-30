CREATE TABLE account_deletion_intents (
    request_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    state text NOT NULL CHECK (state IN ('pending','completed')),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    CHECK ((state='pending' AND completed_at IS NULL) OR
           (state='completed' AND completed_at IS NOT NULL))
);

CREATE INDEX account_deletion_intents_user_idx
    ON account_deletion_intents(user_id,created_at DESC);
