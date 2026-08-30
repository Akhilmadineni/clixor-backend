-- Password-reset and password-changed messages are durable application state,
-- but their recipient, reset code, subject, and body must never be stored in
-- plaintext. The application seals a versioned semantic payload with AES-256-
-- GCM before beginning this insert. Immutable row metadata is authenticated as
-- AAD, so changing a delivery's identity, challenge, or purpose makes decryption
-- fail closed. Both purposes deliberately cascade with the reset challenge:
-- account deletion removes the challenge and suppresses any queued notification
-- rather than retaining an encrypted recipient for a deleted account.
--
-- Migration 12 is intentionally mail-only. The unrelated push-token uniqueness
-- cleanup previously discussed for this version remains deferred until its own
-- rolling-compatibility review.
CREATE TABLE mail_deliveries (
    id uuid PRIMARY KEY,
    password_reset_challenge_id uuid NOT NULL
        REFERENCES password_reset_challenges(id) ON DELETE CASCADE,
    purpose text NOT NULL
        CHECK (purpose IN ('password_reset', 'password_changed')),
    encrypted_payload bytea NOT NULL
        CHECK (octet_length(encrypted_payload) >= 29),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered', 'dead_letter', 'canceled')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz,
    lease_token uuid,
    last_error_class text NOT NULL DEFAULT ''
        CHECK (last_error_class ~ '^[a-z_]{0,64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    canceled_at timestamptz,
    CHECK ((locked_until IS NULL) = (lease_token IS NULL)),
    CHECK (status = 'pending' OR (locked_until IS NULL AND lease_token IS NULL)),
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK ((status = 'dead_letter') = (dead_lettered_at IS NOT NULL)),
    CHECK ((status = 'canceled') = (canceled_at IS NOT NULL))
);

CREATE INDEX mail_deliveries_pending_idx
    ON mail_deliveries (next_attempt_at, id)
    WHERE status = 'pending';

CREATE INDEX mail_deliveries_delivered_idx
    ON mail_deliveries (delivered_at, id)
    WHERE status = 'delivered';

CREATE INDEX mail_deliveries_dead_letter_idx
    ON mail_deliveries (dead_lettered_at, id)
    WHERE status = 'dead_letter';

CREATE INDEX mail_deliveries_canceled_idx
    ON mail_deliveries (canceled_at, id)
    WHERE status = 'canceled';
