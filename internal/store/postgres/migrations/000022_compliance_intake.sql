-- Additive: does not change existing authentication, group, or message contracts.
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';

CREATE TABLE user_blocks (
    blocker_id uuid NOT NULL REFERENCES users(id),
    blocked_id uuid NOT NULL REFERENCES users(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(blocker_id,blocked_id),
    CHECK(blocker_id<>blocked_id)
);
CREATE INDEX user_blocks_reverse_idx ON user_blocks(blocked_id,blocker_id);

CREATE TABLE legal_acceptances (
    user_id uuid NOT NULL REFERENCES users(id),
    version text NOT NULL CHECK (length(version) BETWEEN 1 AND 80),
    document_sha256 text NOT NULL CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    age_group text NOT NULL CHECK (age_group IN ('minor_13_plus','age_of_majority')),
    guardian_permission boolean NOT NULL,
    accepted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id,version),
    CHECK ((age_group='minor_13_plus' AND guardian_permission) OR
           (age_group='age_of_majority' AND NOT guardian_permission))
);

CREATE TABLE compliance_cases (
    id uuid PRIMARY KEY,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    request_hash bytea NOT NULL CHECK (octet_length(request_hash)=32),
    submission jsonb NOT NULL CHECK (jsonb_typeof(submission)='object'),
    status text NOT NULL DEFAULT 'received' CHECK (status IN ('received','reviewing','awaiting_information','resolved','declined')),
    received_at timestamptz NOT NULL DEFAULT now(),
    review_due_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    public_update text NOT NULL DEFAULT '' CHECK (length(public_update)<=2000)
);
CREATE INDEX compliance_cases_queue_idx ON compliance_cases (review_due_at NULLS LAST,received_at)
    WHERE status NOT IN ('resolved','declined');

CREATE TABLE compliance_reviews (
    id bigserial PRIMARY KEY,
    case_id uuid NOT NULL REFERENCES compliance_cases(id),
    operator_id text NOT NULL,
    previous_status text NOT NULL,
    next_status text NOT NULL,
    reason text NOT NULL,
    public_update text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
-- Report data is sensitive. No public or reporter endpoint exposes this table.
-- Case retention/holds require an approved schedule; do not auto-delete evidence.
