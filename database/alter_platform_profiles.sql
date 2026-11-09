-- Apply by hand to an already-running database (schema.sql covers fresh installs).
-- Safe to run more than once.

ALTER TABLE assets ADD COLUMN IF NOT EXISTS os_family VARCHAR(20);
ALTER TABLE assets ADD COLUMN IF NOT EXISTS platform_profile VARCHAR(20);
ALTER TABLE patch_jobs ADD COLUMN IF NOT EXISTS package_manager VARCHAR(10);

-- Ubuntu is supported as a family, any version, so every existing Ubuntu row
-- backfills to the 'ubuntu' profile regardless of its recorded os_version.
UPDATE assets
SET os_family = 'Debian', platform_profile = 'ubuntu'
WHERE platform_profile IS NULL
  AND os = 'Ubuntu';

-- Every other existing row (including RHEL, until discovery confirms a
-- supported major version) is marked unsupported until discovery runs.
UPDATE assets
SET platform_profile = 'unsupported'
WHERE platform_profile IS NULL;
