-- Expand the closed outbox topic domain so leave-group can enqueue
-- conversation.member_removed for APNs and realtime remaining members.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

ALTER TABLE outbox_events DROP CONSTRAINT IF EXISTS outbox_events_topic_domain_check;

ALTER TABLE outbox_events
    ADD CONSTRAINT outbox_events_topic_domain_check
    CHECK (topic IN (
        'conversation.created',
        'conversation.updated',
        'conversation.member_added',
        'conversation.member_removed',
        'message.created',
        'receipt.updated',
        'entity.updated',
        'entity.deleted',
        'media.delete'
    ));
