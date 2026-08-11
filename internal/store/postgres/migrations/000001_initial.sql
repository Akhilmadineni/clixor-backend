CREATE TABLE IF NOT EXISTS schema_migrations (
    version bigint PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id uuid PRIMARY KEY,
    email text,
    phone text,
    display_name text NOT NULL DEFAULT '',
    avatar_url text NOT NULL DEFAULT '',
    profile jsonb NOT NULL DEFAULT '{}'::jsonb,
    password_hash text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT users_identity_check CHECK (email IS NOT NULL OR phone IS NOT NULL)
);
CREATE UNIQUE INDEX users_email_unique ON users (lower(email)) WHERE email IS NOT NULL;
CREATE UNIQUE INDEX users_phone_unique ON users (phone) WHERE phone IS NOT NULL;

CREATE TABLE devices (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name text NOT NULL,
    platform text NOT NULL,
    push_token text NOT NULL DEFAULT '',
    identity_key text NOT NULL DEFAULT '',
    signed_prekey jsonb,
    last_seen_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX devices_user_id_idx ON devices (user_id);

CREATE TABLE one_time_prekeys (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    key_id bigint NOT NULL,
    public_key text NOT NULL,
    claimed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (device_id, key_id)
);
CREATE INDEX one_time_prekeys_available_idx ON one_time_prekeys (device_id, id) WHERE claimed_at IS NULL;

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    refresh_token_hash bytea NOT NULL,
    previous_refresh_token_hash bytea,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expiry_idx ON sessions (expires_at) WHERE revoked_at IS NULL;

CREATE TABLE conversations (
    id uuid PRIMARY KEY,
    kind text NOT NULL CHECK (kind IN ('direct', 'group')),
    direct_key text,
    title text NOT NULL DEFAULT '',
    avatar_url text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by uuid NOT NULL REFERENCES users(id),
    last_seq bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX conversations_direct_key_unique ON conversations (direct_key) WHERE direct_key IS NOT NULL;

CREATE TABLE conversation_members (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
    joined_at timestamptz NOT NULL,
    muted_until timestamptz,
    PRIMARY KEY (conversation_id, user_id)
);
CREATE INDEX conversation_members_user_updated_idx ON conversation_members (user_id, conversation_id);

CREATE TABLE messages (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    client_message_id text NOT NULL,
    sender_id uuid NOT NULL REFERENCES users(id),
    sender_device_id uuid NOT NULL REFERENCES devices(id),
    seq bigint NOT NULL,
    content_type text NOT NULL,
    ciphertext text NOT NULL,
    envelope jsonb,
    reply_to_id uuid,
    created_at timestamptz NOT NULL,
    server_received_at timestamptz NOT NULL,
    PRIMARY KEY (conversation_id, id),
    UNIQUE (conversation_id, seq),
    UNIQUE (conversation_id, sender_id, client_message_id)
) PARTITION BY HASH (conversation_id);

CREATE TABLE messages_p00 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 0);
CREATE TABLE messages_p01 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 1);
CREATE TABLE messages_p02 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 2);
CREATE TABLE messages_p03 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 3);
CREATE TABLE messages_p04 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 4);
CREATE TABLE messages_p05 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 5);
CREATE TABLE messages_p06 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 6);
CREATE TABLE messages_p07 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 7);
CREATE TABLE messages_p08 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 8);
CREATE TABLE messages_p09 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 9);
CREATE TABLE messages_p10 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 10);
CREATE TABLE messages_p11 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 11);
CREATE TABLE messages_p12 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 12);
CREATE TABLE messages_p13 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 13);
CREATE TABLE messages_p14 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 14);
CREATE TABLE messages_p15 PARTITION OF messages FOR VALUES WITH (MODULUS 16, REMAINDER 15);
CREATE INDEX messages_conversation_seq_idx ON messages (conversation_id, seq);
CREATE INDEX messages_sender_idx ON messages (sender_id, server_received_at DESC);

CREATE TABLE receipts (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    delivered_seq bigint NOT NULL DEFAULT 0,
    read_seq bigint NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (conversation_id, user_id),
    CHECK (read_seq <= delivered_seq)
);

CREATE TABLE entities (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    kind text NOT NULL,
    id uuid NOT NULL,
    version bigint NOT NULL,
    payload jsonb NOT NULL,
    created_by uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    deleted_at timestamptz,
    PRIMARY KEY (conversation_id, kind, id)
);
CREATE INDEX entities_sync_idx ON entities (conversation_id, kind, updated_at, id);

CREATE TABLE outbox_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    topic text NOT NULL,
    aggregate_id uuid NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz,
    attempts integer NOT NULL DEFAULT 0,
    published_at timestamptz
);
CREATE INDEX outbox_unpublished_idx ON outbox_events (id) WHERE published_at IS NULL;

CREATE TABLE media_objects (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES users(id),
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    object_key text NOT NULL UNIQUE,
    content_type text NOT NULL,
    byte_size bigint NOT NULL,
    ciphertext_sha256 text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'ready', 'deleted')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX media_objects_conversation_idx ON media_objects (conversation_id, created_at DESC);
