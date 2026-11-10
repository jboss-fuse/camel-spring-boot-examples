CREATE TABLE IF NOT EXISTS claims (
    claim_id VARCHAR(40) PRIMARY KEY,
    member_id VARCHAR(40) NOT NULL,
    procedure_code VARCHAR(40) NOT NULL,
    billed_amount DECIMAL(12,2) NOT NULL,
    currency VARCHAR(3) NOT NULL
);
CREATE TABLE IF NOT EXISTS coverage (
    member_id VARCHAR(40) PRIMARY KEY,
    active BOOLEAN NOT NULL,
    covered_procedure VARCHAR(40) NOT NULL,
    claim_limit DECIMAL(12,2) NOT NULL,
    currency VARCHAR(3) NOT NULL,
    policy_version VARCHAR(40) NOT NULL
);
CREATE TABLE IF NOT EXISTS manual_reviews (
    event_id VARCHAR(128) PRIMARY KEY,
    claim_id VARCHAR(128) NOT NULL,
    correlation_id VARCHAR(128) NOT NULL,
    reason_codes VARCHAR(2000) NOT NULL,
    completed_at VARCHAR(40) NOT NULL
);
ALTER TABLE manual_reviews ADD COLUMN IF NOT EXISTS resolution_decision_id VARCHAR(128);
CREATE TABLE IF NOT EXISTS human_decisions (
    decision_id VARCHAR(128) PRIMARY KEY,
    review_event_id VARCHAR(128) NOT NULL,
    outcome VARCHAR(16) NOT NULL,
    reviewer_id VARCHAR(128) NOT NULL,
    reason VARCHAR(1000) NOT NULL,
    submitted_at VARCHAR(40) NOT NULL,
    status VARCHAR(16) NOT NULL,
    rejection_code VARCHAR(40),
    published_at VARCHAR(40)
);
