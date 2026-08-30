CREATE TABLE conversation_invite_links (
    id uuid PRIMARY KEY,
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_by uuid NOT NULL REFERENCES users(id),
    max_uses integer NOT NULL CHECK (max_uses BETWEEN 1 AND 1000),
    uses integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL
);

CREATE INDEX conversation_invite_links_conversation_idx
    ON conversation_invite_links (conversation_id, created_at DESC);
CREATE INDEX conversation_invite_links_expiry_idx
    ON conversation_invite_links (expires_at)
    WHERE revoked_at IS NULL;
