CREATE TABLE investigations (
    id              SERIAL PRIMARY KEY,
    case_ref        VARCHAR(64),
    title           TEXT NOT NULL,
    classification  VARCHAR(32) DEFAULT 'confidential',
    summary         TEXT,
    status          VARCHAR(32) DEFAULT 'active',
    assigned_to     VARCHAR(128),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Seed data: deliberately references the payment degradation event
-- to demonstrate that the chatbot can see the availability event
-- but cannot reach this linked investigation record.
INSERT INTO investigations (case_ref, title, classification, summary, status, assigned_to) VALUES
    ('INC-2024-001', 'Suspected credential stuffing — Payment Service', 'confidential',
     'Elevated error rates on payment processing correlate with anomalous authentication patterns from Eastern European IP ranges. Possible credential stuffing campaign in progress. Do not disclose externally.',
     'active', 'secops-team');
