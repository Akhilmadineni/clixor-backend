-- Store only age-policy decisions. Exact birth dates and identity documents
-- must never be persisted in the Clixor database.
CREATE TABLE age_assurances (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    status text NOT NULL CHECK (status IN ('adult', 'underage')),
    minimum_age integer NOT NULL CHECK (minimum_age = 18),
    source text NOT NULL CHECK (source IN ('apple_declared_age_range', 'self_attested_date_of_birth')),
    declaration text NOT NULL,
    policy_version text NOT NULL,
    checked_at timestamptz NOT NULL,
    expires_at timestamptz
);
CREATE INDEX age_assurances_expiry_idx ON age_assurances (expires_at) WHERE expires_at IS NOT NULL;
