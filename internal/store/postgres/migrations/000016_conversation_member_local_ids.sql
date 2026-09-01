-- Immutable server-owned mapping from account IDs to the UUIDs embedded by
-- legacy iOS clients in expense/task/chore payloads. Two uniqueness constraints
-- prevent metadata from remapping an account or assigning one local UUID to
-- multiple identities in a conversation.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TABLE conversation_member_local_ids (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id),
    local_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, user_id),
    UNIQUE (conversation_id, local_id)
);

-- Fence the exact production-05b writer shapes before the one-time backfill.
-- A writer already holding user/conversation authority commits first and is
-- included below; a later writer resumes only after the compatibility triggers
-- are committed. Migration 20 repeats this bridge for databases that applied an
-- earlier copy of migration 16 before the bridge existed.
LOCK TABLE users IN EXCLUSIVE MODE;
LOCK TABLE conversations IN EXCLUSIVE MODE;
LOCK TABLE conversation_members, conversation_member_local_ids,
    conversation_member_tombstones
    IN SHARE ROW EXCLUSIVE MODE;

-- Preserve a legacy UUID only when there is exactly one valid proposal for the
-- user, exactly one owner of that UUID, and it is not another member's backend
-- UUID. Every other row uses its backend UUID as a collision-free baseline.
WITH raw_candidates AS (
    SELECT c.id AS conversation_id,
           m.user_id,
           (entry.value->>'id')::uuid AS local_id
    FROM conversations c
    JOIN conversation_members m ON m.conversation_id=c.id
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(c.metadata->'members')='array'
             THEN c.metadata->'members' ELSE '[]'::jsonb END
    ) AS entry(value)
    WHERE lower(entry.value->>'backendUserId')=m.user_id::text
      AND (entry.value->>'id') ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
), ranked_candidates AS (
    SELECT raw_candidates.*,
           count(*) OVER (PARTITION BY conversation_id,user_id) AS user_candidates,
           count(*) OVER (PARTITION BY conversation_id,local_id) AS local_owners
    FROM raw_candidates
), safe_candidates AS (
    SELECT r.conversation_id,r.user_id,r.local_id
    FROM ranked_candidates r
    WHERE r.user_candidates=1 AND r.local_owners=1
      AND NOT EXISTS (
          SELECT 1 FROM conversation_members collision
          WHERE collision.conversation_id=r.conversation_id
            AND collision.user_id=r.local_id
            AND collision.user_id<>r.user_id
      )
)
INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
SELECT m.conversation_id,m.user_id,COALESCE(s.local_id,m.user_id)
FROM conversation_members m
LEFT JOIN safe_candidates s
  ON s.conversation_id=m.conversation_id AND s.user_id=m.user_id;

-- Resolve the same conservative legacy metadata proposal used by the backfill.
-- Ambiguous proposals fall back to the backend UUID; a fallback that is itself
-- reserved by another metadata identity fails closed instead of reinterpreting
-- financial history.
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
    -- A parent conversation delete needs no historical identity because every
    -- associated entity is being deleted and the tombstone would be cascaded.
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

CREATE TRIGGER conversation_members_bridge_identity_insert
AFTER INSERT ON conversation_members
FOR EACH ROW EXECUTE FUNCTION reserve_conversation_member_bridge_identity();

CREATE TRIGGER conversation_members_bridge_tombstone_delete
BEFORE DELETE ON conversation_members
FOR EACH ROW EXECUTE FUNCTION preserve_conversation_member_bridge_tombstone();
