CREATE TABLE customers (
    id              VARCHAR(64) PRIMARY KEY,
    name            VARCHAR(256) NOT NULL,
    email           VARCHAR(256) NOT NULL,
    phone           VARCHAR(32),
    address         TEXT,
    account_status  VARCHAR(32) DEFAULT 'active',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO customers (id, name, email, phone, address, account_status) VALUES
    ('cust-001', 'Alice Johnson', 'alice@example.com', '555-0101', '123 Main St, Springfield, IL', 'active'),
    ('cust-002', 'Bob Martinez',  'bob@example.com',   '555-0102', '456 Oak Ave, Portland, OR',    'active');
