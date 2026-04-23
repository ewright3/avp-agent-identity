CREATE TABLE system_logs (
    id          SERIAL PRIMARY KEY,
    level       VARCHAR(16) NOT NULL,  -- 'info', 'warn', 'error'
    service     VARCHAR(64) NOT NULL,
    message     TEXT NOT NULL,
    metadata    JSONB,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO system_logs (level, service, message, metadata) VALUES
    ('error', 'payment-processor', 'Payment capture timeout for order_id=3',
        '{"order_id": 3, "customer_id": "cust-002", "processor": "stripe", "timeout_ms": 30000}'),
    ('warn',  'order-service',     'Retry attempt 2 of 3 for order_id=3',
        '{"order_id": 3, "attempt": 2}'),
    ('info',  'order-service',     'Order 1 status updated to delivered',
        '{"order_id": 1, "previous_status": "shipped", "new_status": "delivered"}'),
    ('error', 'payment-processor', 'Card declined for order_id=5, processor_ref=ch_005_mno',
        '{"order_id": 5, "customer_id": "cust-003", "decline_code": "insufficient_funds"}');
