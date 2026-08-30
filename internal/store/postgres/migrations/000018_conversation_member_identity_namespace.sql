-- Reserve every historical financial identity before enforcing the disjoint
-- backend/local UUID namespace. Refuse to guess if an older deployment already
-- persisted contradictory history: silently remapping it would reinterpret
-- existing expenses and settlements.
--
-- Deployments run migrations while the previous API replicas are still
-- serving. Membership transactions lock a user row and then a conversation row
-- before mutating either identity table. Fence those relation authorities in
-- the same order before taking the identity-table locks. EXCLUSIVE conflicts
-- with SELECT FOR UPDATE's ROW SHARE relation lock, so we never wait on an old
-- transaction's user/conversation row while already blocking its table write.
-- Retain all locks until this migration transaction commits. An old replica must
-- therefore either commit before validation or resume only after the triggers
-- below are visible; no write can slip between validation and enforcement.
LOCK TABLE users IN EXCLUSIVE MODE;
LOCK TABLE conversations IN EXCLUSIVE MODE;
LOCK TABLE conversation_members, conversation_member_local_ids
    IN SHARE ROW EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM conversation_member_tombstones tombstone
        JOIN conversation_member_local_ids mapping
          ON mapping.conversation_id=tombstone.conversation_id
         AND mapping.user_id=tombstone.user_id
        WHERE mapping.local_id<>tombstone.local_id
    ) THEN
        RAISE EXCEPTION 'conversation member tombstone disagrees with immutable local ID'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM conversation_member_tombstones tombstone
        JOIN conversation_member_local_ids mapping
          ON mapping.conversation_id=tombstone.conversation_id
         AND mapping.local_id=tombstone.local_id
         AND mapping.user_id<>tombstone.user_id
    ) THEN
        RAISE EXCEPTION 'conversation member tombstone local ID has another owner'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
END $$;

INSERT INTO conversation_member_local_ids(conversation_id,user_id,local_id)
SELECT tombstone.conversation_id,tombstone.user_id,tombstone.local_id
FROM conversation_member_tombstones tombstone
ON CONFLICT (conversation_id,user_id) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM conversation_members active
        JOIN conversation_member_local_ids reserved
          ON reserved.conversation_id=active.conversation_id
         AND reserved.local_id=active.user_id
         AND reserved.user_id<>active.user_id
    ) THEN
        RAISE EXCEPTION 'active backend UUID collides with another member local ID'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;
END $$;

CREATE OR REPLACE FUNCTION enforce_conversation_member_identity_namespace()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Serialize all namespace changes for one conversation, including writes
    -- made outside the API implementation.
    PERFORM id FROM conversations WHERE id=NEW.conversation_id FOR UPDATE;

    IF TG_TABLE_NAME='conversation_member_local_ids' AND TG_OP='UPDATE' THEN
        RAISE EXCEPTION 'conversation member local IDs are immutable'
            USING ERRCODE='23514',
                  CONSTRAINT='conversation_member_backend_local_disjoint';
    END IF;

    IF TG_TABLE_NAME='conversation_members' THEN
        IF EXISTS (
            SELECT 1 FROM conversation_member_local_ids reserved
            WHERE reserved.conversation_id=NEW.conversation_id
              AND reserved.local_id=NEW.user_id
              AND reserved.user_id<>NEW.user_id
        ) OR EXISTS (
            SELECT 1
            FROM conversation_member_local_ids own
            JOIN conversation_members active
              ON active.conversation_id=own.conversation_id
             AND active.user_id=own.local_id
            WHERE own.conversation_id=NEW.conversation_id
              AND own.user_id=NEW.user_id
              AND active.user_id<>NEW.user_id
        ) THEN
            RAISE EXCEPTION 'active backend UUID collides with another member local ID'
                USING ERRCODE='23514',
                      CONSTRAINT='conversation_member_backend_local_disjoint';
        END IF;
    ELSE
        IF EXISTS (
            SELECT 1 FROM conversation_members active
            WHERE active.conversation_id=NEW.conversation_id
              AND active.user_id=NEW.local_id
              AND active.user_id<>NEW.user_id
        ) OR (
            EXISTS (
                SELECT 1 FROM conversation_members active_owner
                WHERE active_owner.conversation_id=NEW.conversation_id
                  AND active_owner.user_id=NEW.user_id
            ) AND EXISTS (
                SELECT 1 FROM conversation_member_local_ids reserved
                WHERE reserved.conversation_id=NEW.conversation_id
                  AND reserved.local_id=NEW.user_id
                  AND reserved.user_id<>NEW.user_id
            )
        ) THEN
            RAISE EXCEPTION 'member local ID collides with an active backend UUID'
                USING ERRCODE='23514',
                      CONSTRAINT='conversation_member_backend_local_disjoint';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_members_identity_namespace_insert
BEFORE INSERT ON conversation_members
FOR EACH ROW EXECUTE FUNCTION enforce_conversation_member_identity_namespace();

CREATE TRIGGER conversation_members_identity_namespace_update
BEFORE UPDATE OF conversation_id,user_id ON conversation_members
FOR EACH ROW EXECUTE FUNCTION enforce_conversation_member_identity_namespace();

CREATE TRIGGER conversation_member_local_ids_identity_namespace_insert
BEFORE INSERT ON conversation_member_local_ids
FOR EACH ROW EXECUTE FUNCTION enforce_conversation_member_identity_namespace();

CREATE TRIGGER conversation_member_local_ids_identity_namespace_update
BEFORE UPDATE ON conversation_member_local_ids
FOR EACH ROW EXECUTE FUNCTION enforce_conversation_member_identity_namespace();
