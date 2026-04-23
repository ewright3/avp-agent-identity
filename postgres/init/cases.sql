CREATE TABLE cases (
    id          SERIAL PRIMARY KEY,
    customer_id VARCHAR(64) NOT NULL,
    subject     TEXT NOT NULL,
    body        TEXT,
    status      VARCHAR(32) DEFAULT 'open',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO cases (customer_id, subject, body, status) VALUES
    ('cust-001', 'Cannot log in to my account', 'Getting an error when trying to log in since this morning.', 'open'),
    ('cust-002', 'Billing charge I don''t recognize', 'There is a charge on my account from last Tuesday I did not authorize.', 'open'),
    ('cust-001', 'Password reset email not arriving', 'I requested a password reset 30 minutes ago and have not received the email.', 'closed');
