CREATE EXTENSION IF NOT EXISTS "pgcrypto";


CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    username VARCHAR(255) NOT NULL,
    os VARCHAR(100),
    os_version VARCHAR(100),
    os_family VARCHAR(20),
    platform_profile VARCHAR(20),
    kernel_version VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'REGISTERED',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS telemetry_snapshots (
    id BIGSERIAL PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    cpu_usage_percent NUMERIC(6,2),

    memory_total_mb NUMERIC(12,2),
    memory_used_mb NUMERIC(12,2),
    memory_available_mb NUMERIC(12,2),
    memory_usage_percent NUMERIC(6,2),

    load_1m NUMERIC(10,2),
    load_5m NUMERIC(10,2),
    load_15m NUMERIC(10,2),

    disk_total_gb NUMERIC(12,2),
    disk_used_gb NUMERIC(12,2),
    disk_free_gb NUMERIC(12,2),
    disk_usage_percent NUMERIC(6,2),

    network_data JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS service_snapshots (
    id BIGSERIAL PRIMARY KEY,
    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    captured_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    service_name VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL,
    enabled VARCHAR(50),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS patch_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,

    status VARCHAR(50) NOT NULL DEFAULT 'CREATED',

    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,

    pre_snapshot_at TIMESTAMPTZ,
    post_snapshot_at TIMESTAMPTZ,

    reboot_required BOOLEAN DEFAULT FALSE,

    package_manager VARCHAR(10),

    success BOOLEAN,

    failure_reason TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE TABLE IF NOT EXISTS patch_events (
    id BIGSERIAL PRIMARY KEY,

    patch_job_id UUID NOT NULL REFERENCES patch_jobs(id) ON DELETE CASCADE,

    event_type VARCHAR(100) NOT NULL,

    event_status VARCHAR(50),

    message TEXT,

    event_data JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS idx_telemetry_asset_time
ON telemetry_snapshots(asset_id, captured_at DESC);


CREATE INDEX IF NOT EXISTS idx_services_asset_time
ON service_snapshots(asset_id, captured_at DESC);


CREATE INDEX IF NOT EXISTS idx_patch_jobs_asset
ON patch_jobs(asset_id);


CREATE INDEX IF NOT EXISTS idx_patch_events_job
ON patch_events(patch_job_id);
