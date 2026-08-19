-- Account rows become identity-free tombstones when shared records still refer
-- to them. This preserves group expenses/messages without retaining credentials
-- or discovery identifiers.
ALTER TABLE users ADD COLUMN deleted_at timestamptz;
ALTER TABLE users DROP CONSTRAINT users_identity_check;
CREATE INDEX users_deleted_at_idx ON users (deleted_at) WHERE deleted_at IS NOT NULL;
