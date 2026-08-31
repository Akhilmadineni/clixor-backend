-- message.created contains E2EE ciphertext/envelopes and is deliberately
-- preserved byte-for-byte by account erasure. Keep the durable topic domain
-- closed so a future server-readable event cannot bypass erasure without an
-- explicit schema and migration review.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM outbox_events
        WHERE topic NOT IN (
            'conversation.created',
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
        'conversation.member_added',
        'message.created',
        'receipt.updated',
        'entity.updated',
        'entity.deleted',
        'media.delete'
    ));
