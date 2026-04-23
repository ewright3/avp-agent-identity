CREATE TABLE availability_events (
    id          SERIAL PRIMARY KEY,
    service     VARCHAR(128) NOT NULL,
    status      VARCHAR(32) NOT NULL,  -- 'operational', 'degraded', 'outage'
    message     TEXT,
    started_at  TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ
);

INSERT INTO availability_events (service, status, message, started_at, resolved_at) VALUES
    ('Authentication Service', 'operational', 'All systems normal.', NOW() - INTERVAL '7 days', NOW() - INTERVAL '6 days'),
    ('Payment Processing',     'degraded',    'Elevated error rates on payment processing. Engineering is investigating.', NOW() - INTERVAL '2 hours', NULL),
    ('Core API',               'operational', 'All systems normal.', NOW() - INTERVAL '30 days', NOW() - INTERVAL '29 days');
