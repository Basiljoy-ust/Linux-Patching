-- Apply by hand to an already-running database (schema.sql covers fresh installs).
-- Safe to run more than once.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_family VARCHAR(20);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS platform_profile VARCHAR(20);
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS package_manager VARCHAR(10);

-- Backfill only the version actually tested; do not assume other Ubuntu
-- versions are 24.04.
UPDATE assets
SET os_family = 'Debian', platform_profile = 'ubuntu-24.04'
WHERE platform_profile IS NULL
  AND os = 'Ubuntu'
  AND os_version LIKE '24.04%';

-- Every other existing row is marked unsupported until discovery detects it.
UPDATE assets
SET platform_profile = 'unsupported'
WHERE platform_profile IS NULL;
