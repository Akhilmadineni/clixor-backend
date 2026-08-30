-- Immutable server-owned mapping from account IDs to the UUIDs embedded by
-- legacy iOS clients in expense/task/chore payloads. Two uniqueness constraints
-- prevent metadata from remapping an account or assigning one local UUID to
-- multiple identities in a conversation.
CREATE TABLE conversation_member_local_ids (
    conversation_id uuid NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id),
    local_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (conversation_id, user_id),
    UNIQUE (conversation_id, local_id)
);

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
