CREATE TABLE profile_media_objects (
    id uuid PRIMARY KEY,
    owner_id uuid NOT NULL REFERENCES users(id),
    object_key text NOT NULL UNIQUE,
    content_type text NOT NULL,
    byte_size bigint NOT NULL,
    ciphertext_sha256 text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'ready', 'deleted')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE INDEX profile_media_owner_created_idx
    ON profile_media_objects (owner_id, created_at DESC);

-- During the compatibility rollout, a request can still land on a production-05b
-- replica after a newer replica created an invite, reset challenge, or profile
-- upload. The old account-deletion transaction cannot know about those tables.
-- Keep the cleanup next to the additive schema so every writer, including an
-- old binary, gets the same irreversible result when it tombstones a user.
CREATE FUNCTION cleanup_account_extensions_on_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    object_keys jsonb;
BEGIN
    UPDATE conversation_invite_links
    SET revoked_at = COALESCE(revoked_at, NEW.deleted_at)
    WHERE created_by = NEW.id;

    DELETE FROM password_reset_challenges
    WHERE user_id = NEW.id;

    -- Match the application's bounded media.delete contract. Object deletion is
    -- idempotent, and the outbox rows commit atomically with the tombstone.
    FOR object_keys IN
        WITH removed AS (
            DELETE FROM profile_media_objects
            WHERE owner_id = NEW.id
            RETURNING object_key
        ), numbered AS (
            SELECT object_key,
                   (row_number() OVER (ORDER BY object_key) - 1) / 500 AS batch_number
            FROM removed
        )
        SELECT jsonb_agg(object_key ORDER BY object_key)
        FROM numbered
        GROUP BY batch_number
        ORDER BY batch_number
    LOOP
        INSERT INTO outbox_events(topic, aggregate_id, payload)
        VALUES (
            'media.delete',
            NEW.id,
            jsonb_build_object('object_keys', object_keys)
        );
    END LOOP;

    RETURN NEW;
END;
$$;

CREATE TRIGGER users_cleanup_account_extensions_on_delete
AFTER UPDATE OF deleted_at ON users
FOR EACH ROW
WHEN (OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL)
EXECUTE FUNCTION cleanup_account_extensions_on_delete();
