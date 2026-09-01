-- Migration 000009 deliberately deferred this constraint while legacy 05b
-- replicas could still write devices. Migration numbers 10-12 were later
-- assigned to media retention and durable mail, so this coordinated cutover
-- is migration 13. Apply it only after every legacy replica has been drained.

-- Block device writes for the short normalization/deduplication window. This
-- makes cleanup and index creation one atomic ownership transition.
LOCK TABLE devices IN ACCESS EXCLUSIVE MODE;

UPDATE devices
SET push_token = lower(btrim(push_token))
WHERE push_token <> lower(btrim(push_token));

WITH ranked AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY push_token
               ORDER BY last_seen_at DESC NULLS LAST,
                        created_at DESC,
                        id DESC
           ) AS ownership_rank
    FROM devices
    WHERE push_token <> ''
)
UPDATE devices AS device
SET push_token = ''
FROM ranked
WHERE device.id = ranked.id
  AND ranked.ownership_rank > 1;

CREATE UNIQUE INDEX devices_push_token_unique
    ON devices (push_token)
    WHERE push_token <> '';
