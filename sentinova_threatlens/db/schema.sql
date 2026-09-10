CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE SCHEMA IF NOT EXISTS cti_iocs;

CREATE TABLE IF NOT EXISTS cti_iocs.iocs (
    id              BIGSERIAL    PRIMARY KEY,
    ioc_value       TEXT         NOT NULL,
    ioc_type        VARCHAR(20)  NOT NULL,
    source_name     VARCHAR(64)  NOT NULL,
    raw_data        JSONB        NOT NULL DEFAULT '{}',
    normalized_data JSONB        NOT NULL DEFAULT '{}',
    first_seen      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_enriched   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_ioc_value
    ON cti_iocs.iocs (ioc_value);

CREATE INDEX IF NOT EXISTS idx_iocs_ioc_type
    ON cti_iocs.iocs (ioc_type);

CREATE INDEX IF NOT EXISTS idx_iocs_source_name
    ON cti_iocs.iocs (source_name);

CREATE INDEX IF NOT EXISTS idx_iocs_last_seen
    ON cti_iocs.iocs (last_seen DESC);

CREATE INDEX IF NOT EXISTS idx_iocs_normalized_gin
    ON cti_iocs.iocs USING GIN (normalized_data);
