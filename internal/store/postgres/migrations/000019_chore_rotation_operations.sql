CREATE TABLE chore_rotation_operations (
    operation_id uuid PRIMARY KEY,
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    actor_id uuid NOT NULL REFERENCES users(id),
    chore_id uuid NOT NULL,
    request_hash bytea NOT NULL CHECK (octet_length(request_hash) = 32),
    chore_result jsonb NOT NULL,
    feed_result jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '90 days'),
    UNIQUE (conversation_id, operation_id)
);
CREATE INDEX chore_rotation_operations_expiry_idx ON chore_rotation_operations(expires_at);

-- Operation rows intentionally outlive normal client retry windows. Operators
-- may delete only expired rows in bounded batches; 90 days is the minimum
-- supported replay window and cleanup is never part of the write transaction.
