CREATE TABLE orders (
    id           SERIAL PRIMARY KEY,
    customer_id  VARCHAR(64) NOT NULL,
    product      TEXT NOT NULL,
    amount       NUMERIC(10, 2) NOT NULL,
    status       VARCHAR(32) DEFAULT 'pending',
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    updated_at   TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO orders (customer_id, product, amount, status) VALUES
    ('cust-001', 'Wireless Headphones',   89.99,  'delivered'),
    ('cust-001', 'USB-C Charging Cable',   12.99,  'shipped'),
    ('cust-002', 'Mechanical Keyboard',   149.99,  'pending'),
    ('cust-002', 'Laptop Stand',           34.99,  'delivered'),
    ('cust-003', 'Webcam HD 1080p',        59.99,  'processing');
