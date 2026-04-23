CREATE TABLE payments (
    id              SERIAL PRIMARY KEY,
    order_id        INTEGER NOT NULL,
    customer_id     VARCHAR(64) NOT NULL,
    card_last_four  VARCHAR(4) NOT NULL,
    card_brand      VARCHAR(32) NOT NULL,
    amount          NUMERIC(10, 2) NOT NULL,
    status          VARCHAR(32) DEFAULT 'captured',
    processor_ref   VARCHAR(128),
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Payment records deliberately reference the same order IDs.
-- The chatbot can see order status but cannot reach this table.
-- The developer can reach it only with JIT elevation.
INSERT INTO payments (order_id, customer_id, card_last_four, card_brand, amount, status, processor_ref) VALUES
    (1, 'cust-001', '4242', 'Visa',       89.99,  'captured',  'ch_001_abc'),
    (2, 'cust-001', '4242', 'Visa',       12.99,  'captured',  'ch_002_def'),
    (3, 'cust-002', '1234', 'Mastercard', 149.99, 'pending',   'ch_003_ghi'),
    (4, 'cust-002', '1234', 'Mastercard',  34.99, 'captured',  'ch_004_jkl'),
    (5, 'cust-003', '5678', 'Amex',        59.99, 'captured',  'ch_005_mno');
