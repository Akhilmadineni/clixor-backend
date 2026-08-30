-- The compatibility rollout intentionally does not add a unique push-token
-- index. Production-05b replicas may still be serving during the rolling
-- deployment and do not transfer token ownership before their device upsert;
-- adding the constraint here would turn a previously successful 05b request
-- into a uniqueness error. The new store serializes and transfers ownership
-- with an advisory lock. Deterministic legacy cleanup plus the database
-- constraint are deferred to coordinated migration 12, after reserved media
-- migration 10 and outbox-retention migration 11, once all 05b replicas are
-- drained. Never rewrite this migration after it has been applied.

-- Realtime publication and APNs delivery have different failure domains. Each
-- eligible device gets one idempotent durable delivery. A bounded worker owns
-- retries and dead-lettering independently of source outbox acknowledgement.
CREATE TABLE push_deliveries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    outbox_event_id bigint NOT NULL REFERENCES outbox_events(id) ON DELETE CASCADE,
    device_id uuid NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    title text NOT NULL,
    body text NOT NULL,
    kind text NOT NULL,
    conversation_id uuid NOT NULL,
    entity_id uuid NOT NULL,
    notification_id text NOT NULL,
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'delivered', 'invalid_token', 'dead_letter', 'canceled')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until timestamptz,
    lease_token uuid,
    last_error_class text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    UNIQUE (outbox_event_id, device_id)
);

CREATE INDEX push_deliveries_pending_idx
    ON push_deliveries (next_attempt_at, id)
    WHERE status = 'pending';
CREATE INDEX push_deliveries_dead_letter_idx
    ON push_deliveries (dead_lettered_at, id)
    WHERE status = 'dead_letter';
CREATE INDEX push_deliveries_delivered_idx
    ON push_deliveries (delivered_at, id)
    WHERE delivered_at IS NOT NULL;
