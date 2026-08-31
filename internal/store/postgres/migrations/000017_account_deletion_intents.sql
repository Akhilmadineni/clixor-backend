-- Migration 16 was strengthened before its first production rollout with a
-- compatibility bridge for the exact previous-binary INSERT/DELETE shapes.
-- Refuse to continue if a version-only runner skipped that amended SQL merely
-- because an older migration with the same version was already recorded.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        JOIN pg_proc function ON function.oid=trigger.tgfoid
        WHERE trigger.tgrelid=to_regclass('conversation_members')
          AND trigger.tgname='conversation_members_bridge_identity_insert'
          AND NOT trigger.tgisinternal AND trigger.tgenabled<>'D'
          AND function.proname='reserve_conversation_member_bridge_identity'
    ) OR NOT EXISTS (
        SELECT 1
        FROM pg_trigger trigger
        JOIN pg_proc function ON function.oid=trigger.tgfoid
        WHERE trigger.tgrelid=to_regclass('conversation_members')
          AND trigger.tgname='conversation_members_bridge_tombstone_delete'
          AND NOT trigger.tgisinternal AND trigger.tgenabled<>'D'
          AND function.proname='preserve_conversation_member_bridge_tombstone'
    ) OR EXISTS (
        SELECT 1 FROM conversation_members member
        WHERE NOT EXISTS (
            SELECT 1 FROM conversation_member_local_ids mapping
            WHERE mapping.conversation_id=member.conversation_id
              AND mapping.user_id=member.user_id
        )
    ) THEN
        RAISE EXCEPTION 'migration 16 compatibility bridge is absent or incomplete; refusing version-only migration advance'
            USING ERRCODE='55000';
    END IF;
END $$;

CREATE TABLE account_deletion_intents (
    request_id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    state text NOT NULL CHECK (state IN ('pending','completed')),
    created_at timestamptz NOT NULL,
    completed_at timestamptz,
    CHECK ((state='pending' AND completed_at IS NULL) OR
           (state='completed' AND completed_at IS NOT NULL))
);

CREATE INDEX account_deletion_intents_user_idx
    ON account_deletion_intents(user_id,created_at DESC);
