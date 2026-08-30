ALTER TABLE media_objects
    ADD COLUMN upload_capability_id text,
    ADD CONSTRAINT media_objects_upload_capability_id_check
    CHECK (
        upload_capability_id IS NULL OR
        (octet_length(upload_capability_id) BETWEEN 1 AND 1024 AND
         btrim(upload_capability_id) = upload_capability_id)
    ) NOT VALID,
    ADD CONSTRAINT media_objects_ready_capability_revoked_check
    CHECK (status <> 'ready' OR upload_capability_id IS NULL) NOT VALID;

ALTER TABLE media_objects
    VALIDATE CONSTRAINT media_objects_upload_capability_id_check,
    VALIDATE CONSTRAINT media_objects_ready_capability_revoked_check;

ALTER TABLE profile_media_objects
    ADD COLUMN upload_capability_id text,
    ADD CONSTRAINT profile_media_objects_upload_capability_id_check
    CHECK (
        upload_capability_id IS NULL OR
        (octet_length(upload_capability_id) BETWEEN 1 AND 1024 AND
         btrim(upload_capability_id) = upload_capability_id)
    ) NOT VALID,
    ADD CONSTRAINT profile_media_objects_ready_capability_revoked_check
    CHECK (status <> 'ready' OR upload_capability_id IS NULL) NOT VALID;

ALTER TABLE profile_media_objects
    VALIDATE CONSTRAINT profile_media_objects_upload_capability_id_check,
    VALIDATE CONSTRAINT profile_media_objects_ready_capability_revoked_check;

-- A production-05b replica can tombstone an account while a new replica has
-- an OCI upload between its staging rename and database publication. Expand
-- every legacy profile key to both possible names and keep deletion behind the
-- original upload URL expiry. Migration 14 intentionally replaces migration
-- 8's function without changing its trigger or its invite/reset cleanup.
CREATE OR REPLACE FUNCTION cleanup_account_extensions_on_delete()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
DECLARE
    deletion record;
BEGIN
    UPDATE conversation_invite_links
    SET revoked_at = COALESCE(revoked_at, NEW.deleted_at)
    WHERE created_by = NEW.id;

    DELETE FROM password_reset_challenges
    WHERE user_id = NEW.id;

    FOR deletion IN
        WITH removed AS (
            DELETE FROM profile_media_objects
            WHERE owner_id = NEW.id
            RETURNING object_key, upload_valid_until
        ), expanded AS (
            SELECT CASE
                       WHEN object_key LIKE 'published/%'
                       THEN substring(object_key FROM 11)
                       ELSE object_key
                   END AS object_key,
                   upload_valid_until
            FROM removed
            UNION ALL
            SELECT CASE
                       WHEN object_key LIKE 'published/%'
                       THEN object_key
                       ELSE 'published/' || object_key
                   END AS object_key,
                   upload_valid_until
            FROM removed
        ), numbered AS (
            SELECT object_key,
                   upload_valid_until,
                   (row_number() OVER (ORDER BY object_key) - 1) / 500 AS batch_number
            FROM expanded
        )
        SELECT jsonb_agg(object_key ORDER BY object_key) AS object_keys,
               max(greatest(
                   statement_timestamp() + interval '3 minutes',
                   upload_valid_until + interval '3 minutes'
               )) AS not_before
        FROM numbered
        GROUP BY batch_number
        ORDER BY batch_number
    LOOP
        INSERT INTO outbox_events(topic, aggregate_id, payload, available_at)
        VALUES (
            'media.delete',
            NEW.id,
            jsonb_build_object(
                'object_keys', deletion.object_keys,
                'not_before', deletion.not_before
            ),
            deletion.not_before
        );
    END LOOP;

    RETURN NEW;
END;
$$;
