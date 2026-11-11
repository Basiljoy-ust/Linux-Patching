-- 003_distro_cve_titles.sql
-- Store a human-readable title alongside each package->CVE mapping, so
-- CVEs that Zero-Day Radar does not track still show a description and
-- severity in the UI (both taken from the distro's data via OSV).
--
-- Apply with: psql -d linux_patching -f database/migrations/003_distro_cve_titles.sql
-- Then force re-enrichment of already-mapped packages:
--   DELETE FROM package_cve_checks;
-- (the next sync cycle re-queries OSV and fills title/severity in place)

ALTER TABLE package_cves ADD COLUMN IF NOT EXISTS title TEXT;
