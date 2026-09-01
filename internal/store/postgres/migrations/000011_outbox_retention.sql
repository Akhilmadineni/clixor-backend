-- Retention scans only acknowledged source events. The ID tiebreaker keeps each
-- bounded SKIP LOCKED batch deterministic when many events share a timestamp.
CREATE INDEX outbox_published_retention_idx
    ON outbox_events (published_at, id)
    WHERE published_at IS NOT NULL;
