ALTER TABLE media_objects
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN upload_valid_until timestamptz,
    ADD COLUMN verification_lease_token uuid,
    ADD COLUMN verification_locked_until timestamptz;
ALTER TABLE profile_media_objects
    ADD COLUMN expires_at timestamptz,
    ADD COLUMN upload_valid_until timestamptz,
    ADD COLUMN verification_lease_token uuid,
    ADD COLUMN verification_locked_until timestamptz;

UPDATE media_objects
SET expires_at = CASE WHEN status = 'pending' THEN created_at + interval '5 minutes' END,
    upload_valid_until = created_at + interval '5 minutes';

UPDATE profile_media_objects
SET expires_at = CASE WHEN status = 'pending' THEN created_at + interval '5 minutes' END,
    upload_valid_until = created_at + interval '5 minutes';

ALTER TABLE media_objects ALTER COLUMN upload_valid_until SET NOT NULL;
ALTER TABLE profile_media_objects ALTER COLUMN upload_valid_until SET NOT NULL;

ALTER TABLE media_objects
    ADD CONSTRAINT media_objects_pending_expiry_check
    CHECK ((status = 'pending') = (expires_at IS NOT NULL)),
    ADD CONSTRAINT media_objects_verification_lease_check
    CHECK (
        (verification_lease_token IS NULL) = (verification_locked_until IS NULL)
        AND (verification_lease_token IS NULL OR status = 'pending')
    );

ALTER TABLE profile_media_objects
    ADD CONSTRAINT profile_media_objects_pending_expiry_check
    CHECK ((status = 'pending') = (expires_at IS NOT NULL)),
    ADD CONSTRAINT profile_media_objects_verification_lease_check
    CHECK (
        (verification_lease_token IS NULL) = (verification_locked_until IS NULL)
        AND (verification_lease_token IS NULL OR status = 'pending')
    );

CREATE INDEX media_objects_pending_owner_idx
    ON media_objects (owner_id, expires_at)
    WHERE status = 'pending';

CREATE INDEX media_objects_pending_conversation_idx
    ON media_objects (conversation_id, expires_at)
    WHERE status = 'pending';

CREATE INDEX profile_media_objects_pending_owner_idx
    ON profile_media_objects (owner_id, expires_at)
    WHERE status = 'pending';

CREATE INDEX media_objects_verification_lease_idx
    ON media_objects (verification_locked_until, id)
    WHERE status = 'pending';

CREATE INDEX profile_media_objects_verification_lease_idx
    ON profile_media_objects (verification_locked_until, id)
    WHERE status = 'pending';

CREATE INDEX media_objects_stored_owner_idx
    ON media_objects (owner_id, status)
    WHERE status <> 'deleted';

CREATE INDEX media_objects_stored_conversation_idx
    ON media_objects (conversation_id, status)
    WHERE status <> 'deleted';

CREATE INDEX profile_media_objects_stored_owner_idx
    ON profile_media_objects (owner_id, status)
    WHERE status <> 'deleted';

ALTER TABLE outbox_events
    ADD COLUMN available_at timestamptz NOT NULL DEFAULT now();

DROP INDEX outbox_unpublished_idx;
CREATE INDEX outbox_unpublished_idx
    ON outbox_events (available_at, id)
    WHERE published_at IS NULL;

CREATE INDEX outbox_media_delete_unpublished_idx
    ON outbox_events (available_at, id)
    WHERE published_at IS NULL AND topic = 'media.delete';
