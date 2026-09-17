BEGIN;

CREATE TABLE IF NOT EXISTS cti_iocs.schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.feed_registry (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    source_type VARCHAR(32) NOT NULL DEFAULT 'json',
    endpoint TEXT NOT NULL,
    credential_ref VARCHAR(128),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (poll_interval_seconds > 0),
    last_poll TIMESTAMPTZ,
    next_poll TIMESTAMPTZ,
    status VARCHAR(32) NOT NULL DEFAULT 'unknown',
    failure_count INTEGER NOT NULL DEFAULT 0,
    checkpoint TEXT,
    settings JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS cti_iocs.ioc_provenance (
    ioc_id BIGINT NOT NULL REFERENCES cti_iocs.iocs(id) ON DELETE CASCADE,
    source_name VARCHAR(64) NOT NULL,
    source_reference TEXT,
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    raw_data JSONB NOT NULL DEFAULT '{}',
    PRIMARY KEY (ioc_id, source_name)
);

CREATE TABLE IF NOT EXISTS cti_iocs.ioc_relationships (
    id BIGSERIAL PRIMARY KEY,
    source_ioc_id BIGINT NOT NULL REFERENCES cti_iocs.iocs(id) ON DELETE CASCADE,
    target_ioc_id BIGINT NOT NULL REFERENCES cti_iocs.iocs(id) ON DELETE CASCADE,
    relationship_type VARCHAR(64) NOT NULL,
    confidence_score INTEGER CHECK (confidence_score BETWEEN 0 AND 100),
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_ioc_id, target_ioc_id, relationship_type)
);

CREATE TABLE IF NOT EXISTS cti_iocs.security_events (
    id BIGSERIAL PRIMARY KEY,
    external_id VARCHAR(256),
    event_type VARCHAR(128) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload JSONB NOT NULL,
    source VARCHAR(128) NOT NULL,
    correlation_key VARCHAR(512),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.alert_rules (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    conditions JSONB NOT NULL DEFAULT '{}',
    routing JSONB NOT NULL DEFAULT '{}',
    created_by VARCHAR(256) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.alerts (
    id BIGSERIAL PRIMARY KEY,
    ioc_id BIGINT REFERENCES cti_iocs.iocs(id),
    event_id BIGINT REFERENCES cti_iocs.security_events(id),
    rule_id BIGINT REFERENCES cti_iocs.alert_rules(id),
    severity_score INTEGER NOT NULL CHECK (severity_score BETWEEN 0 AND 100),
    status VARCHAR(32) NOT NULL DEFAULT 'new',
    assignee VARCHAR(256),
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    acknowledged_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cti_iocs.incidents (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(256) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'new',
    assignee VARCHAR(256),
    severity_score INTEGER NOT NULL DEFAULT 0 CHECK (severity_score BETWEEN 0 AND 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.incident_timeline (
    id BIGSERIAL PRIMARY KEY,
    incident_id BIGINT NOT NULL REFERENCES cti_iocs.incidents(id) ON DELETE CASCADE,
    actor VARCHAR(256) NOT NULL,
    action VARCHAR(128) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.audit_log (
    id BIGSERIAL PRIMARY KEY,
    actor VARCHAR(256) NOT NULL,
    action VARCHAR(128) NOT NULL,
    target_type VARCHAR(128) NOT NULL,
    target_id VARCHAR(256),
    result VARCHAR(32) NOT NULL,
    request_id VARCHAR(128),
    source_ip INET,
    before_data JSONB,
    after_data JSONB,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.dashboard_layouts (
    id BIGSERIAL PRIMARY KEY,
    owner VARCHAR(256) NOT NULL,
    role VARCHAR(32) NOT NULL,
    layout JSONB NOT NULL DEFAULT '{}',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (owner, role)
);

CREATE TABLE IF NOT EXISTS cti_iocs.reports (
    id BIGSERIAL PRIMARY KEY,
    requested_by VARCHAR(256) NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'queued',
    parameters JSONB NOT NULL DEFAULT '{}',
    artifact_path TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cti_iocs.integration_hooks (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    kind VARCHAR(32) NOT NULL,
    endpoint TEXT NOT NULL,
    secret_ref VARCHAR(128),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS cti_iocs.users (
    id BIGSERIAL PRIMARY KEY,
    username VARCHAR(128) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(32) NOT NULL,
    scopes JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_events_occurred_at ON cti_iocs.security_events (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status_score ON cti_iocs.alerts (status, severity_score DESC);
CREATE INDEX IF NOT EXISTS idx_timeline_incident_time ON cti_iocs.incident_timeline (incident_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_occurred_at ON cti_iocs.audit_log (occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_search ON cti_iocs.iocs USING GIN (to_tsvector('simple', ioc_value || ' ' || source_name));

INSERT INTO cti_iocs.schema_version(version) VALUES (2) ON CONFLICT DO NOTHING;

INSERT INTO cti_iocs.feed_registry(name, source_type, endpoint, poll_interval_seconds)
VALUES
 ('MalwareBazaar', 'json', 'https://mb-api.abuse.ch/api/v1/', 3600),
 ('AbuseIPDB', 'json', 'https://api.abuseipdb.com/api/v2/blacklist', 1800),
 ('ThreatFox', 'json', 'https://threatfox-api.abuse.ch/api/v1/', 1800),
 ('GreyNoise', 'json', 'https://api.greynoise.io/v3/community/', 3600),
 ('CISA_KEV', 'json', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 21600),
 ('OpenPhish', 'text', 'https://openphish.com/feed.txt', 1800)
ON CONFLICT (name) DO NOTHING;
COMMIT;
