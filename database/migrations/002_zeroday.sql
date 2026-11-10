-- 002_zeroday.sql
-- Zero-Day Radar integration: synced CVE intel, package->CVE mapping,
-- stored pending updates, sync bookkeeping and multi-server patch jobs.
--
-- Apply with: psql -d linux_patching -f database/migrations/002_zeroday.sql


-- One row per CVE synced from Zero-Day Radar (GET /feed).
-- Hot filter columns are extracted; the full record is kept in `record`.
CREATE TABLE IF NOT EXISTS zeroday_cves (
    cve_id          TEXT PRIMARY KEY,
    title           TEXT,
    vendor          TEXT,
    severity        TEXT NOT NULL DEFAULT 'unknown',
    cvss_score      NUMERIC(3,1),
    epss_score      NUMERIC(6,5),
    epss_percentile NUMERIC(6,5),
    priority_score  NUMERIC(5,1),
    confidence      TEXT,
    maturity        TEXT NOT NULL DEFAULT 'none',       -- weaponized/in_the_wild/reported/poc/none
    exploited       BOOLEAN NOT NULL DEFAULT FALSE,     -- exploit.confirmed_in_the_wild
    ransomware      BOOLEAN NOT NULL DEFAULT FALSE,
    true_zero_day   BOOLEAN NOT NULL DEFAULT FALSE,
    public_poc      BOOLEAN NOT NULL DEFAULT FALSE,
    kev             BOOLEAN NOT NULL DEFAULT FALSE,
    kev_due_date    DATE,
    urgency         TEXT,                               -- act_now/this_week/normal
    first_seen      TIMESTAMPTZ,
    last_updated    TIMESTAMPTZ,
    record          JSONB NOT NULL,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_zeroday_cves_severity ON zeroday_cves(severity);
CREATE INDEX IF NOT EXISTS idx_zeroday_cves_maturity ON zeroday_cves(maturity);
CREATE INDEX IF NOT EXISTS idx_zeroday_cves_due ON zeroday_cves(kev_due_date);


-- Which CVEs a distro package (upgrade) addresses, per OS family.
-- Sources: 'osv' (Ubuntu, api.osv.dev) and 'updateinfo' (RHEL,
-- `dnf updateinfo list --with-cve` collected during patch discovery).
CREATE TABLE IF NOT EXISTS package_cves (
    id              BIGSERIAL PRIMARY KEY,
    os_family       VARCHAR(20) NOT NULL,
    package         VARCHAR(255) NOT NULL,
    version         VARCHAR(255),           -- installed version the lookup was made for
    cve_id          TEXT NOT NULL,
    fixed_version   VARCHAR(255),
    distro_severity VARCHAR(20),            -- advisory severity (RHEL updateinfo)
    source          VARCHAR(20) NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (os_family, package, cve_id)
);

CREATE INDEX IF NOT EXISTS idx_package_cves_pkg ON package_cves(package);
CREATE INDEX IF NOT EXISTS idx_package_cves_cve ON package_cves(cve_id);


-- Last known pending (upgradeable) packages per asset, written whenever
-- patch discovery runs. Lets the dashboard/updates views render without
-- running Ansible on every page load.
CREATE TABLE IF NOT EXISTS pending_packages (
    asset_id          UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    package           VARCHAR(255) NOT NULL,
    current_version   VARCHAR(255),
    available_version VARCHAR(255),
    checked_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (asset_id, package)
);


-- When each package was last looked up against OSV, including lookups
-- that found nothing — so clean packages are not re-queried every cycle.
CREATE TABLE IF NOT EXISTS package_cve_checks (
    os_family  VARCHAR(20) NOT NULL,
    package    VARCHAR(255) NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (os_family, package)
);


-- Single-row watermark for the incremental /feed sync.
CREATE TABLE IF NOT EXISTS zd_sync_state (
    id                BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    server_time       TEXT,            -- passed back verbatim as ?since=
    last_sync_at      TIMESTAMPTZ,
    last_full_sync_at TIMESTAMPTZ,
    last_error        TEXT
);


-- Cached Zero-Day responses (/sources, /metrics, /signals, item:<CVE>).
CREATE TABLE IF NOT EXISTS zd_cache (
    key        TEXT PRIMARY KEY,
    payload    JSONB NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- A patch job spanning one or more servers (the bulk flow in the UI).
-- Each per-asset execution is still a patch_jobs row, linked by group_id.
CREATE TABLE IF NOT EXISTS patch_job_groups (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    status       VARCHAR(50) NOT NULL DEFAULT 'CREATED',  -- CREATED/RUNNING/COMPLETED/PARTIAL/FAILED
    targets      JSONB NOT NULL,                          -- [{asset_id, packages[]}]
    cves_closed  JSONB,                                   -- computed at completion
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at   TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);

ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES patch_job_groups(id);
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS requested_packages JSONB;
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS cves_closed JSONB;

CREATE INDEX IF NOT EXISTS idx_patch_jobs_group ON patch_jobs(group_id);
CREATE INDEX IF NOT EXISTS idx_patch_jobs_created ON patch_jobs(created_at DESC);
