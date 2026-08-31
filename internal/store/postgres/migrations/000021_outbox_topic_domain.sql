-- message.created contains E2EE ciphertext/envelopes and is deliberately
-- preserved byte-for-byte by account erasure. Keep the durable topic domain
-- closed so a future server-readable event cannot bypass erasure without an
-- explicit schema and migration review.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

-- Older relay versions persisted display names, conversation titles, and
-- entity descriptions in retry rows. The current sender intentionally uses
-- generic copy, so make the upgrade erase every historical rich value before
-- the topic domain is sealed. IS DISTINCT FROM avoids rewriting rows that were
-- already produced by the privacy-safe relay.
UPDATE push_deliveries
SET title='Clixor',
    body='You have new activity. Open the app to view it.',
    kind='activity',
    updated_at=now()
WHERE title IS DISTINCT FROM 'Clixor'
   OR body IS DISTINCT FROM 'You have new activity. Open the app to view it.'
   OR kind IS DISTINCT FROM 'activity';

-- Account deletion scopes transport rows by conversation and topic while it
-- owns the global delivery fence. Avoid a table scan that would otherwise
-- pause all realtime and APNs delivery as the outbox grows.
CREATE INDEX outbox_account_erasure_idx
    ON outbox_events (aggregate_id, topic, id);

CREATE INDEX conversation_member_tombstones_user_idx
    ON conversation_member_tombstones (user_id, conversation_id);

-- created_by is the authority pointer used together with the owner role by
-- conversation deletion. Never guess how to repair historical divergence:
-- refuse the rollout so an operator can review the exceptional conversation.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM conversations conversation
        WHERE (
            SELECT count(*) FROM conversation_members owner
            WHERE owner.conversation_id=conversation.id AND owner.role='owner'
        ) <> 1
        OR NOT EXISTS (
            SELECT 1 FROM conversation_members owner
            WHERE owner.conversation_id=conversation.id
              AND owner.role='owner'
              AND owner.user_id=conversation.created_by
        )
    ) THEN
        RAISE EXCEPTION 'conversation must have exactly one owner matching created_by; review before migration';
    END IF;
END
$$;

CREATE UNIQUE INDEX conversation_members_single_owner_idx
    ON conversation_members (conversation_id)
    WHERE role='owner';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM outbox_events
        WHERE topic NOT IN (
            'conversation.created',
            'conversation.updated',
            'conversation.member_added',
            'message.created',
            'receipt.updated',
            'entity.updated',
            'entity.deleted',
            'media.delete'
        )
    ) THEN
        RAISE EXCEPTION 'outbox_events contains an unreviewed topic; refusing to seal topic domain';
    END IF;
END
$$;

ALTER TABLE outbox_events
    ADD CONSTRAINT outbox_events_topic_domain_check
    CHECK (topic IN (
        'conversation.created',
        'conversation.updated',
        'conversation.member_added',
        'message.created',
        'receipt.updated',
        'entity.updated',
        'entity.deleted',
        'media.delete'
    ));
