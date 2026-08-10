CREATE TABLE conversation_invites (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    phone text NOT NULL,
    role text NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'admin')),
    invited_by uuid NOT NULL REFERENCES users(id),
    invited_at timestamptz NOT NULL DEFAULT now(),
    claimed_by uuid REFERENCES users(id),
    claimed_at timestamptz,
    PRIMARY KEY (conversation_id, phone)
);
CREATE INDEX conversation_invites_phone_unclaimed_idx
    ON conversation_invites(phone, conversation_id)
    WHERE claimed_at IS NULL;

CREATE TABLE external_identities (
    provider text NOT NULL,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject)
);
CREATE INDEX external_identities_user_idx ON external_identities(user_id);
