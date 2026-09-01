-- Migration 16 installs this bridge for a fresh rollout. Migration 17 already
-- fails a version-only runner if an older copy of 16 was recorded. Revalidate
-- the prerequisite here before sealing the final function definitions so a
-- custom runner cannot apply this file alone as an unsafe historical repair.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
LOCK TABLE users IN EXCLUSIVE MODE;
LOCK TABLE conversations IN EXCLUSIVE MODE;
LOCK TABLE conversation_members, conversation_member_local_ids,
    conversation_member_tombstones
    IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        JOIN pg_proc function ON function.oid=trigger.tgfoid
        WHERE trigger.tgrelid='conversation_members'::regclass
          AND trigger.tgname='conversation_members_bridge_identity_insert'
          AND NOT trigger.tgisinternal AND trigger.tgenabled<>'D'
          AND function.proname='reserve_conversation_member_bridge_identity'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        JOIN pg_proc function ON function.oid=trigger.tgfoid
        WHERE trigger.tgrelid='conversation_members'::regclass
          AND trigger.tgname='conversation_members_bridge_tombstone_delete'
          AND NOT trigger.tgisinternal AND trigger.tgenabled<>'D'
          AND function.proname='preserve_conversation_member_bridge_tombstone'
    ) THEN
        RAISE EXCEPTION 'migration 16 compatibility bridge is absent; refusing unsafe historical repair'
            USING ERRCODE='55000';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION resolve_conversation_member_bridge_local_id(
    target_conversation_id uuid,
    target_user_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
AS $$
DECLARE
    conversation_metadata jsonb;
    candidate uuid;
    candidate_count bigint;
    candidate_owner_count bigint;
BEGIN
    SELECT COALESCE(metadata,'{}'::jsonb)
    INTO conversation_metadata
    FROM conversations
    WHERE id=target_conversation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation is unavailable for member identity reservation'
            USING ERRCODE='23503';
    END IF;

    SELECT count(*)
    INTO candidate_count
    FROM jsonb_array_elements(
        CASE WHEN jsonb_typeof(conversation_metadata->'members')='array'
             THEN conversation_metadata->'members' ELSE '[]'::jsonb END
    ) AS entry(value)
    WHERE lower(entry.value->>'backendUserId')=target_user_id::text
      AND (entry.value->>'id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';

    IF candidate_count=1 THEN
        SELECT (entry.value->>'id')::uuid
        INTO candidate
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(conversation_metadata->'members')='array'
                 THEN conversation_metadata->'members' ELSE '[]'::jsonb END
        ) AS entry(value)
        WHERE lower(entry.value->>'backendUserId')=target_user_id::text
          AND (entry.value->>'id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
        LIMIT 1;

        SELECT count(*)
        INTO candidate_owner_count
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(conversation_metadata->'members')='array'
                 THEN conversation_metadata->'members' ELSE '[]'::jsonb END
        ) AS entry(value)
        WHERE (entry.value->>'id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          AND (entry.value->>'id')::uuid=candidate;

        IF candidate_owner_count=1
           AND NOT EXISTS (
               SELECT 1 FROM conversation_members active
               WHERE active.conversation_id=target_conversation_id
                 AND active.user_id=candidate
                 AND active.user_id<>target_user_id
           )
           AND NOT EXISTS (
               SELECT 1 FROM conversation_member_local_ids reserved
               WHERE reserved.conversation_id=target_conversation_id
                 AND reserved.local_id=candidate
                 AND reserved.user_id<>target_user_id
           )
           AND NOT EXISTS (
               SELECT 1
               FROM jsonb_array_elements(
                   CASE WHEN jsonb_typeof(conversation_metadata->'members')='array'
                        THEN conversation_metadata->'members' ELSE '[]'::jsonb END
               ) AS entry(value)
               WHERE lower(entry.value->>'backendUserId')=candidate::text
                 AND lower(entry.value->>'backendUserId')<>target_user_id::text
           ) THEN
            RETURN candidate;
        END IF;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM jsonb_array_elements(
            CASE WHEN jsonb_typeof(conversation_metadata->'members')='array'
                 THEN conversation_metadata->'members' ELSE '[]'::jsonb END
        ) AS entry(value)
        WHERE (entry.value->>'id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
          AND (entry.value->>'id')::uuid=target_user_id
          AND lower(entry.value->>'backendUserId')<>target_user_id::text
    ) OR EXISTS (
        SELECT 1 FROM conversation_member_local_ids reserved
        WHERE reserved.conversation_id=target_conversation_id
          AND reserved.local_id=target_user_id
          AND reserved.user_id<>target_user_id
    ) THEN
        RAISE EXCEPTION 'member backend UUID collides with a reserved local identity'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
    RETURN target_user_id;
END;
$$;

CREATE OR REPLACE FUNCTION reserve_conversation_member_bridge_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    resolved_local_id uuid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM conversation_member_local_ids mapping
        WHERE mapping.conversation_id=NEW.conversation_id
          AND mapping.user_id=NEW.user_id
    ) THEN
        resolved_local_id := resolve_conversation_member_bridge_local_id(
            NEW.conversation_id, NEW.user_id
        );
        INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
        VALUES(NEW.conversation_id,NEW.user_id,resolved_local_id)
        ON CONFLICT (conversation_id,user_id) DO NOTHING;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM conversation_member_local_ids mapping
        WHERE mapping.conversation_id=NEW.conversation_id
          AND mapping.user_id=NEW.user_id
    ) THEN
        RAISE EXCEPTION 'conversation member has no immutable local identity'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION preserve_conversation_member_bridge_tombstone()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    reserved_local_id uuid;
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM conversations WHERE id=OLD.conversation_id
    ) THEN
        RETURN OLD;
    END IF;
    SELECT local_id
    INTO reserved_local_id
    FROM conversation_member_local_ids
    WHERE conversation_id=OLD.conversation_id AND user_id=OLD.user_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'conversation member has no immutable local identity'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
    INSERT INTO conversation_member_tombstones(conversation_id,user_id,local_id)
    VALUES(OLD.conversation_id,OLD.user_id,reserved_local_id)
    ON CONFLICT (conversation_id,user_id) DO NOTHING;
    IF NOT EXISTS (
        SELECT 1 FROM conversation_member_tombstones tombstone
        WHERE tombstone.conversation_id=OLD.conversation_id
          AND tombstone.user_id=OLD.user_id
          AND tombstone.local_id=reserved_local_id
    ) THEN
        RAISE EXCEPTION 'conversation member tombstone disagrees with immutable local identity'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
    RETURN OLD;
END;
$$;

-- Repair active members committed by an old replica after the original
-- one-time backfill. The authority locks make this deterministic and ensure no
-- writer can slip between repair and trigger installation.
INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
SELECT member.conversation_id,member.user_id,
       resolve_conversation_member_bridge_local_id(member.conversation_id,member.user_id)
FROM conversation_members member
WHERE NOT EXISTS (
    SELECT 1 FROM conversation_member_local_ids mapping
    WHERE mapping.conversation_id=member.conversation_id
      AND mapping.user_id=member.user_id
)
ORDER BY member.conversation_id,member.user_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM conversation_members member
        WHERE NOT EXISTS (
            SELECT 1 FROM conversation_member_local_ids mapping
            WHERE mapping.conversation_id=member.conversation_id
              AND mapping.user_id=member.user_id
        )
    ) THEN
        RAISE EXCEPTION 'active conversation member has no immutable local identity'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
END $$;

DROP TRIGGER IF EXISTS conversation_members_bridge_identity_insert
ON conversation_members;
CREATE TRIGGER conversation_members_bridge_identity_insert
AFTER INSERT ON conversation_members
FOR EACH ROW EXECUTE FUNCTION reserve_conversation_member_bridge_identity();

DROP TRIGGER IF EXISTS conversation_members_bridge_tombstone_delete
ON conversation_members;
CREATE TRIGGER conversation_members_bridge_tombstone_delete
BEFORE DELETE ON conversation_members
FOR EACH ROW EXECUTE FUNCTION preserve_conversation_member_bridge_tombstone();
