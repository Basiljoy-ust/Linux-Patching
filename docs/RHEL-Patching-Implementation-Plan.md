# Multi-Platform Patching Support: Ubuntu 24.04, RHEL 8, RHEL 9

**Project:** Linux Patching
**Date:** 2026-11-04
**Status:** Draft for review (revision 4: scoped to RHEL 8 and RHEL 9 only; RHEL 7 and RHEL 10 removed from this plan)

---

## 1. Purpose and scope

The Linux Patching system currently supports Ubuntu 24.04 only. This plan extends it to RHEL 8 and RHEL 9, while keeping Ubuntu 24.04 working unchanged.

| Platform | Status after this plan |
|---|---|
| Ubuntu 24.04 (Noble) | Existing. Behaviour unchanged. |
| RHEL 9 | New. |
| RHEL 8 | New. |

RHEL 7 and RHEL 10 are explicitly **out of scope**. RHEL 7 needs compatibility fallbacks (no default Python 3, systemd without JSON output, past-EOL update access) and RHEL 10 needs its own verification of `dnf5`, which is a rewrite of `dnf`, not a version bump. Both are deferred to a later plan once 8 and 9 are in production. The design below (one codebase, driven by a platform profile) adds either one later as a new profile without restructuring anything built here.

Every existing API endpoint keeps the same URL, method and response shape, so the frontend needs no change. All seven endpoints that exist today must work for RHEL 8 and RHEL 9 assets exactly as they do for Ubuntu:

| # | Endpoint | What it does |
|---|---|---|
| 1 | `GET /health` | Is the API alive? |
| 2 | `GET /api/assets` | List the registered machines. |
| 3 | `GET /api/assets/{id}/telemetry` | Latest health reading for one machine. |
| 4 | `GET /api/assets/{id}/telemetry/history` | Past health readings. |
| 5 | `GET /api/assets/{id}/services` | Running services on a machine, checked live. |
| 6 | `POST /api/assets/{id}/patch-check` | Ask a machine which updates it needs. |
| 7 | `POST /api/assets/{id}/patch-jobs` | Apply the chosen package updates (up to 50 per request). |

Written for: engineers who will implement, test and maintain the change.

---

## 2. Current state (Ubuntu, as found in the code)

### 2.1 Reboot

- **No automatic reboot.** The system never reboots a server.
- **Detection only.** `ansible/patch_execute.yml` checks whether `/var/run/reboot-required` exists after patching. The result is printed in the Ansible output.
- **Not stored or returned.** `backend/main.py` does not write `reboot_required` to `patch_jobs`, and the API response does not include it, even though the column exists in `database/schema.sql`.
- **Manual reboot.** An administrator reboots the server by hand. This plan keeps reboot **report-only**: detect and expose the flag, never reboot automatically.

### 2.2 Versions

- **No version gating.** Nothing checks the OS version before patching; any host in `patch_targets` gets the same `apt` commands.
- **Recorded but unused.** `assets.os` and `assets.os_version` are stored and returned by patch-check, but no decision uses them today.
- **Tested version.** The logs in `logs/pre-patch/` show Ubuntu 24.04 (noble, from the `noble-updates` repo name in `upgradeable-packages.txt`) with Python 3.12.3 (from the installed `python3.12` package version in `packages.txt`). No other Ubuntu release has been tested.

### 2.3 Package sources

- The project does not configure package sources. Each server uses its own apt configuration.
- **Discovery:** `apt update` (if the cache is older than 3600s), then `apt list --upgradable`, parsed by `patching/discover.py`.
- **Patching:** forced `apt update`, then `apt` with `state: latest` for only the requested packages (maximum 50 per request). No full upgrade is run.
- `unattended-upgrades` is installed on the test host. Whether it is enabled was not checked, and it may apply updates outside this system.

### 2.4 Components and their platform dependence

| Component | Depends on distribution? | Notes |
|---|---|---|
| `telemetry/collector.py` | No | Reads `/proc`. Needs Python 3 on the target. |
| `telemetry/service_inventory.py` | No for RHEL 8/9 | Uses `systemctl --output=json`, supported by systemd 239+ (RHEL 8) and 252 (RHEL 9). |
| `ansible/services_discovery.yml`, `telemetry*.yml` | No | Copy and run the scripts above. |
| `backend/save_telemetry.py`, `database.py`, `db_config.py` | No | Database access only; `save_telemetry.py` is currently hard-coded to one hostname (see 3.6). |
| `database/schema.sql` | Needs 2 new columns | Generic PostgreSQL tables. |
| `patching/discover.py` | **Yes** | Runs `apt`. Needs a `dnf` branch. |
| `ansible/patch_discovery.yml` | **Yes** | Uses `ansible.builtin.apt`. Needs a `dnf` branch. |
| `ansible/patch_execute.yml` | **Yes** | Uses `ansible.builtin.apt`; checks `/var/run/reboot-required`. Needs a `dnf` branch and a RHEL reboot check. |
| `ansible/discovery.yml` | **Yes** | Runs `apt list --upgradable`. Needs a `dnf` branch. |
| `backend/main.py` | **Partly** | Endpoint logic is generic. Discovery and job logic assume apt output and do not store the reboot flag. |

---

## 3. Design

### 3.1 Approach: one codebase, driven by a platform profile

Each server is assigned a **platform profile**: `ubuntu-24.04`, `rhel-8`, or `rhel-9`. Any other platform (including RHEL 7 and RHEL 10, if encountered) is `unsupported` and refused with HTTP 409 before any change is made. Profiles are defined in one place; the API, discovery script and playbooks read from them. Behaviour that differs between platforms (package manager, reboot check, service listing) comes from the profile, not from scattered `if` statements.

Rejected alternative: a separate code copy for RHEL. It would drift from the Ubuntu code, and every fix would need to be made twice.

RHEL 8 and RHEL 9 are close enough (both `dnf` 4.x, both systemd with JSON support) that most of the RHEL-specific work is shared between them; the only real differences are the default Python version and the systemd version, neither of which affects behaviour in this plan.

### 3.2 Platform profiles

| Profile | Family | Package manager | Python 3 on target | Reboot check | Service listing | Supported |
|---|---|---|---|---|---|---|
| `ubuntu-24.04` | Debian | `apt` | Default (3.12) | `/var/run/reboot-required` | JSON | Yes (existing) |
| `rhel-9` | RedHat | `dnf` 4.x | Default (3.9) | `needs-restarting -r` (dnf-utils) | JSON (systemd 252) | Yes |
| `rhel-8` | RedHat | `dnf` 4.x | Default (3.6); 3.9 via AppStream module if needed | `needs-restarting -r` (dnf-utils) | JSON (systemd 239) | Yes |
| any other (incl. RHEL 7, RHEL 10) | — | — | — | — | — | **No** (refused, 409) |

Profile definition (a single config module, `backend/platform_profiles.py`):

```python
PLATFORM_PROFILES = {
    "ubuntu-24.04": {
        "family": "Debian",
        "major": "24.04",
        "package_manager": "apt",
        "python": "/usr/bin/python3",
        "reboot_check": "file:/var/run/reboot-required",
        "service_list_mode": "json",
        "update_check": "apt list --upgradable",
        "update_exit_codes": [0],
    },
    "rhel-9": {
        "family": "RedHat",
        "major": "9",
        "package_manager": "dnf",
        "python": "/usr/bin/python3",
        "reboot_check": "needs-restarting -r",
        "service_list_mode": "json",
        "update_check": "dnf check-update --quiet",
        "update_exit_codes": [0, 100],
    },
    "rhel-8": {
        "family": "RedHat",
        "major": "8",
        "package_manager": "dnf",
        "python": "/usr/bin/python3",
        "reboot_check": "needs-restarting -r",
        "service_list_mode": "json",
        "update_check": "dnf check-update --quiet",
        "update_exit_codes": [0, 100],
    },
}
```

Note: the `python` path and the exit codes for `check-update` are assumptions carried over from documented `dnf4` behaviour; confirm both on a real RHEL 8 and RHEL 9 host during Phase 1 before relying on them.

### 3.3 How a server gets its profile

1. `patching/discover.py` detects the platform itself, by reading `/etc/os-release` on the target, and reports `platform_profile`, `os_family` and `package_manager` in its JSON output. Detection does not depend on Ansible facts, so it works the same whether discovery is run directly or through a playbook.
2. The first time `discover_remote_patches()` runs for an asset, `backend/main.py` persists the detected profile into `assets.os_family` / `assets.platform_profile`.
3. If the detected profile doesn't match `ubuntu-24.04`, `rhel-8`, or `rhel-9`, it is stored as `unsupported`.
4. Both `POST patch-check` and `POST patch-jobs` always run discovery first (as they already do today), then check the returned profile before proceeding. This avoids a chicken-and-egg problem on a brand-new asset that has never been discovered yet — the 409 check is based on the live discovery result, not only on a value that might not exist in the database yet. Once stored, later calls reuse it for display (`GET /api/assets`) without needing a fresh discovery.

### 3.4 Reboot handling

Reboot is **report-only**. The system never reboots a server, on any platform.

1. **Detect** after patching, using the profile's `reboot_check`:
   - Ubuntu: `/var/run/reboot-required` exists.
   - RHEL 8, 9: `needs-restarting -r` returns exit code `1` when a reboot is required, `0` when not.
2. **Store** the result in `patch_jobs.reboot_required`.
3. **Return** `reboot_required` in the `POST /patch-jobs` response and in the `PATCH_COMPLETED` event data.
4. **No automatic reboot and no reboot request field.** An administrator decides when to reboot and does it outside this system.

### 3.5 Package sources and preflight

Each platform has a preflight step that runs before any change:

| Profile | Preflight checks |
|---|---|
| Ubuntu 24.04 | Existing behaviour (`apt update` before patching). |
| RHEL 9, 8 | `subscription-manager status` (or confirm repos reachable); `dnf repolist` shows at least one enabled repo; `dnf-utils` installed (provides `needs-restarting`). |

This preflight runs inside `ansible/patch_execute.yml`, immediately before the upgrade task, for both RHEL profiles. `ansible/patch_discovery.yml` does not duplicate it: if a RHEL host has no usable repos, `dnf check-update` itself fails and is reported through the existing 502 "discovery failed" path (section 5.6), so a separate preflight there would be redundant.

If a preflight check in `patch_execute.yml` fails, no package is changed on the server, but the patch job's database row was already created and marked `RUNNING` before the playbook ran (same as the existing failure-handling flow) — the playbook failure is caught and the job is marked `FAILED` with the preflight error in `failure_reason`, the same way any other Ansible failure is handled today.

### 3.6 Remote telemetry collection (new, required for RHEL assets)

The telemetry endpoints (`GET .../telemetry`, `.../telemetry/history`) only read from `telemetry_snapshots`. The only thing that writes to that table today is `backend/save_telemetry.py`, which is hard-coded to collect from the local host only (`get_asset_id()` looks up hostname `Linux-patching1` and `collect_telemetry()` always runs the collector locally via subprocess). A RHEL 8 or RHEL 9 asset would never get a telemetry row, and `GET .../telemetry` would return 404 for it forever, unless this is fixed.

This is in scope for this plan, since telemetry endpoints must work for RHEL assets:

- New `ansible/telemetry_collect.yml`: copies `collector.py` and `service_inventory.py` to the target and fetches the resulting JSON back, following the same pattern as `ansible/patch_discovery.yml`.
- `backend/save_telemetry.py` is refactored to take a hostname: `get_asset_id(hostname)`, and a new `collect_remote_telemetry(hostname)` that runs the new playbook for non-local hosts (reusing the same subprocess/vault pattern as `discover_remote_patches()` in `main.py`), falling back to the existing local subprocess call for local hosts.
- A small CLI wrapper (`python save_telemetry.py --host <name>` or `--all`) is added so this can be run on a schedule (cron or a systemd timer) per asset, independent of the API process.

### 3.7 Asset onboarding (same manual method as Ubuntu)

No endpoint or script in this repo registers a host. The Ubuntu host was added by hand, and RHEL 8/9 hosts will be added the same way. This is a one-time human step, performed outside the codebase, and it is not part of the code changes in section 6.

For each new host, in this order:

1. **Inventory entry.** Add the host to `ansible/inventory.ini` under `[rhel_targets]`. The hostname here is the name every later step uses.
2. **Vault credentials.** Create `ansible/host_vars/<hostname>/vault.yml` with `ansible-vault create`, as described in `ansible/README.md`. Without this file every endpoint returns 503 for that host.
3. **Database row.** Insert the asset by hand, using the same hostname as step 1:

   ```sql
   INSERT INTO assets (hostname, ip_address, username, status)
   VALUES ('<inventory-hostname>', '<server-ip>', '<ssh-user>', 'ACTIVE');
   ```

   `status` must be `ACTIVE`. The column defaults to `REGISTERED`, and `patch-check`, `patch-jobs` and `GET services` all return 409 for any other value.
4. **Verify.** `GET /api/assets` lists the new row. `POST patch-check` on it returns discovery results.

Fields that the code does not fill in: `os`, `os_version`, `kernel_version`. For RHEL, the new `os_family` and `platform_profile` columns will be written by discovery (section 3.3). Until that is built, they can be set by hand in the same insert.

Known gap: nothing checks that the row's hostname matches the inventory, so a typo fails later, at the Ansible call, rather than at insert time.

---

## 4. Platform-specific details

### 4.1 Ubuntu 24.04

- Keep the existing `apt` logic unchanged.
- Other Ubuntu releases are not supported in this revision. They are refused by the profile check.

### 4.2 RHEL 8

- `dnf` 4.x. Use `ansible.builtin.dnf`.
- Default `python3` is 3.6. The shared scripts (`discover.py`, `collector.py`, `service_inventory.py`) must run correctly on 3.6: no walrus operator, no `subprocess.run(capture_output=..., text=...)` (needs 3.7+, use `Popen`/`communicate` instead), no f-string `=` debugging syntax. If a future script genuinely needs newer Python, install 3.9 from the AppStream module rather than relying on the default.
- systemd 239 supports `systemctl --output=json`. The existing JSON-based `service_inventory.py` works unchanged.
- `needs-restarting` ships in the `yum-utils`/`dnf-utils` package; confirm it's present or add it to preflight.

### 4.3 RHEL 9

- `dnf` 4.x. Use `ansible.builtin.dnf`.
- Default `python3` is 3.9. Scripts should still be written to the RHEL 8 (3.6) floor so the same files work unmodified on both.
- systemd 252. JSON service listing works unchanged.

### 4.4 Package name and version matching (both RHEL profiles)

RPM-based discovery introduces two correctness details that don't exist in the Ubuntu `apt` path:

- **Architecture suffix.** `dnf check-update` reports packages as `name.arch`, e.g. `openssl.x86_64`. The discovery output strips this to a bare `name` plus a separate `arch` field, so the JSON shape (`name`, `current_version`, `available_version`) matches the Ubuntu path. `POST patch-jobs` validation must normalize the **requested** package names the same way, so a caller sending `"openssl.x86_64"` or `"openssl"` both match the discovery result — normalization has to apply in both directions, not just to the discovered list.
- **Kernel and other `installonly` packages.** RHEL normally keeps several kernel versions installed side by side rather than replacing the old one. A naive `rpm -q kernel` returns multiple lines, so picking a single "current version" is ambiguous for exactly the package most likely to require a reboot. Resolve this explicitly rather than silently: report the newest installed version as `current_version` for `installonly` packages, and note in the response that older kernel versions remain installed.

---

## 5. Endpoint-by-endpoint plan

All seven endpoints keep the same URL, method and response shape. Each entry lists what changes per platform. Where nothing is listed, the endpoint behaves the same on all platforms.

### 5.1 `GET /health`: is the API alive?

- No change for any platform.
- **Test:** returns 200.

### 5.2 `GET /api/assets`: list the registered machines

- **New fields per asset:** `os_family`, `platform_profile`, `package_manager`.
- **Database:** add `os_family` and `platform_profile` to `assets` (see section 7).
- **Backfill:** existing assets with `os = 'Ubuntu'` **and** `os_version` starting with `24.04` are set to `platform_profile = 'ubuntu-24.04'`. Any other existing row is left as `platform_profile = 'unsupported'` rather than assumed to be 24.04 — don't guess a profile for a version that was never actually tested.

### 5.3 `GET /api/assets/{id}/telemetry`: latest health readings

- No change in the endpoint itself. Reads `telemetry_snapshots`.
- Requires the remote telemetry collection described in 3.6 — without it, this endpoint returns 404 for every RHEL asset regardless of any other change in this plan.
- **Collector:** `telemetry/collector.py` must be verified on RHEL 8 and RHEL 9. It needs Python 3 on the target and must run correctly under 3.6 (see 4.2).
- **SELinux (RHEL):** if the copied collector is blocked, run `restorecon -Rv /opt/linux-patch-agent`.

### 5.4 `GET /api/assets/{id}/telemetry/history`: past health readings

- No change. Reads `telemetry_snapshots` ordered by `captured_at`.
- Same dependency on 3.6 as above: needs at least two telemetry collections per RHEL asset before this returns anything.

### 5.5 `GET /api/assets/{id}/services`: running services, checked live

- **Ubuntu and RHEL 8, 9:** all use JSON mode (`systemctl --output=json`). No fallback logic is needed, since RHEL 7's systemd-219 limitation is out of scope.
- **Test:** confirm the service list for a RHEL 8 and a RHEL 9 host returns the same shape (`{unit: {status, enabled}}`) as Ubuntu.

### 5.6 `POST /api/assets/{id}/patch-check`: which updates are needed

**Current flow:** `main.py` → `discover_remote_patches()` → `ansible/patch_discovery.yml` → `patching/discover.py` → JSON fetched back → returned.

**Changes:**

1. **`ansible/patch_discovery.yml`:** branch by profile.
   - Ubuntu: existing `apt` tasks, unchanged.
   - RHEL 8, 9: `ansible.builtin.dnf` metadata refresh, then run the (profile-detecting) discovery script.
2. **`patching/discover.py`:** add a `dnf` update-check path alongside the existing `apt` path.
   - RHEL: `dnf check-update --quiet`. Exit code `100` means updates are available and is a success. Exit code `0` means none. Any other code is a failure, surfaced as an error.
   - Each line (`name.arch  version  repo`) is split so `openssl.x86_64` becomes name `openssl` with arch `x86_64` (see 4.4).
   - Current installed version is read with `rpm -q`, resolving the `installonly`/kernel ambiguity as described in 4.4.
   - Output uses the same keys as the Ubuntu path (`name`, `current_version`, `available_version`), plus `arch`, `package_manager`, `platform_profile`, `os_family`.
3. **Profile check (`main.py`):** after discovery returns, if `platform_profile` is `unsupported`, return **409** with the message "Platform not supported" instead of the normal discovery payload.
4. **Errors:** a disabled or unregistered repo makes `dnf check-update` fail outright, which is already surfaced as **502** by the existing error-handling path. Timeouts keep the existing **504** path — but see the note on timeout tuning in section 10.
5. **Response:** adds `os_family` and `platform_profile`. Other fields are unchanged.

### 5.7 `POST /api/assets/{id}/patch-jobs`: apply the chosen updates

**Current flow:** validate asset → discover → validate requested packages → insert job → `patch_execute.yml` → record result → return.

**Changes:**

1. **Validation (`main.py`):**
   - Run discovery as today, then check the returned profile; unsupported platforms are refused with **409** before the job row is created.
   - Each requested package must appear in the discovery result. Matching strips architecture on both sides (see 4.4), so `openssl` and `openssl.x86_64` both match `openssl.x86_64` in the discovery output.
   - Limit of 50 packages per request (`PatchRequest.packages`, `max_length=50`). Unchanged.
2. **`ansible/patch_execute.yml`:** branch by profile.
   - Ubuntu: existing `apt` upgrade, unchanged.
   - RHEL 8, 9: preflight (section 3.5), then `ansible.builtin.dnf` with `name: "{{ patch_packages }}"` and `state: latest`.
   - Before and after captures of kernel, uptime and failed services apply to all platforms, unchanged in structure.
3. **Reboot check:** the profile's `reboot_check` command runs after patching (section 3.4). No reboot is performed.
4. **Persist and return:**
   - Store `reboot_required` in `patch_jobs`.
   - Return `reboot_required`, `os_family` and `platform_profile` in the success response.
   - Add `reboot_required` to the `PATCH_COMPLETED` event data.
5. **Failure handling:** unchanged. Failures (including a preflight failure) are stored as `FAILED` with stdout and stderr in `failure_reason`.

---

## 6. Changes by file

| File | Action |
|---|---|
| `backend/platform_profiles.py` | **New.** Profile definitions (section 3.2). |
| `backend/main.py` | Persist detected profile on first discovery; 409 for unsupported platforms (checked after discovery, see 3.3); package name matching normalized on both sides; store and return `reboot_required` (report-only); return `os_family`/`platform_profile`; re-check/raise the discovery and job subprocess timeouts (section 10). |
| `backend/save_telemetry.py` | Parameterize hostname; add remote collection via a new playbook; add a CLI entry point (section 3.6). |
| `patching/discover.py` | Add platform detection (`/etc/os-release`) and a `dnf` update-check path and parser. Ubuntu `apt` path unchanged. |
| `telemetry/service_inventory.py` | No change needed — JSON mode already covers RHEL 8/9. |
| `telemetry/collector.py` | No change expected; verify it runs correctly under Python 3.6 on RHEL 8. |
| `ansible/patch_discovery.yml` | Branch by profile: Ubuntu (existing `apt`), RHEL 8/9 (`dnf`). |
| `ansible/patch_execute.yml` | Branch by profile for upgrade; add RHEL preflight; add the RHEL reboot check (`needs-restarting -r`). |
| `ansible/telemetry_collect.yml` | **New.** Remote telemetry collection playbook (section 3.6). |
| `ansible/discovery.yml` | Replace `apt list --upgradable` with a profile-aware listing. |
| `ansible/services_discovery.yml` | No change (copies the existing helper; already works for RHEL 8/9). |
| `ansible/inventory.ini` | Add a `[rhel_targets]` group for RHEL 8/9 hosts; include it in `patch_targets`. |
| `ansible/host_vars/<host>/vault.yml` | One encrypted file per RHEL host, as described in the existing `ansible/README.md`. |
| `database/schema.sql` | Add the new columns in place (section 7) — no separate migration framework exists in this repo today. |
| `logs/pre-patch-rhel/` | **New folder.** Pre-patch captures for RHEL hosts, same file set as the existing Ubuntu `logs/pre-patch/`. |
| `ansible/README.md`, `backend/README.md` | Add RHEL 8/9 setup, the profile table, and the reboot/telemetry behaviour described above. |

---

## 7. Database migration

There's no migration runner in this repo — `database/schema.sql` is applied once by hand. Add the new columns directly to the existing `CREATE TABLE IF NOT EXISTS` blocks so a fresh install picks them up, and apply the equivalent `ALTER TABLE` by hand against any already-running database:

```sql
-- Add to assets, alongside os_version:
--   os_family VARCHAR(20),
--   platform_profile VARCHAR(20),

-- Add to patch_jobs, alongside reboot_required:
--   package_manager VARCHAR(10),

-- For an existing database, apply by hand:
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
```

`patch_jobs.reboot_required` already exists in the schema; it only needs to be written by the code (section 3.4).

---

## 8. Implementation phases

| Phase | Work | Output | Estimate |
|---|---|---|---|
| 0. Decisions | Confirm RHEL 8/9 subscription method, Ansible control-node compatibility, unsupported-platform behaviour (section 11) | Signed-off decisions | 1 day |
| 1. Test hosts | Provision one RHEL 8 and one RHEL 9 host with subscriptions or a local mirror. Confirm Python 3 version, `dnf-utils` presence, `dnf check-update` exit codes and output format on each. | Working test hosts; profile values confirmed | 2 days |
| 2. Profiles and schema | `platform_profiles.py`, schema changes, profile detection and persistence, `GET /api/assets` fields | Endpoint 5.2 working | 1–2 days |
| 3. Telemetry | Remote telemetry collection (`telemetry_collect.yml`, `save_telemetry.py` refactor); verify collector and service inventory on both RHEL hosts | Endpoints 5.3–5.5 working on all platforms | 2–3 days |
| 4. Discovery | `dnf` discovery path and parser in `discover.py`; `patch_discovery.yml` branch; kernel/installonly version handling | Endpoint 5.6 working | 2–3 days |
| 5. Patching | `dnf` upgrade branch; preflight; reboot check; symmetric package-name matching; validation | Endpoint 5.7 working | 2–3 days |
| 6. Validation | Full test matrix (section 9) across Ubuntu, RHEL 8, RHEL 9 | Test report | 2 days |
| 7. Documentation | READMEs, runbook, RHEL pre-patch logs | Docs merged | 1 day |

**Total estimate:** about 13–17 working days for one engineer, once RHEL 8 and RHEL 9 test hosts are available.

---

## 9. Test plan

### 9.1 Test matrix

| Test | Ubuntu 24.04 | RHEL 8 | RHEL 9 |
|---|---|---|---|
| `GET /health` | Required | Required | Required |
| `GET /api/assets` returns profile fields | Required | Required | Required |
| `GET telemetry` (after at least one collection) | Required | Required | Required |
| `GET telemetry/history` | Required | Required | Required |
| `GET services` | Required | Required | Required |
| `POST patch-check` returns updates | Required | Required | Required |
| `POST patch-check` with no updates | Required | Required | Required |
| `POST patch-check` with repo disabled (clear error) | Optional | Required | Required |
| `POST patch-jobs` with valid packages (bare name) | Required | Required | Required |
| `POST patch-jobs` with valid packages (name.arch form) | N/A | Required | Required |
| `POST patch-jobs` with unknown package (400) | Required | Required | Required |
| `POST patch-jobs` with 51 packages (422) | Required | Required | Required |
| `POST patch-jobs` on an asset with an unsupported profile (409) | Required | Required | Required |
| Patch job with kernel update; `reboot_required` true, no reboot performed | Required | Required | Required |
| Patch check on unreachable host (504 or 502) | Required | Required | Required |

### 9.2 Specific checks

- `openssl` and `openssl.x86_64` both match `openssl.x86_64` in discovery results.
- A kernel update reports a sensible `current_version` even with multiple kernel versions installed (section 4.4).
- `reboot_required` is stored in `patch_jobs` and returned by the API; no reboot ever actually happens.
- Scripts run correctly under Python 3.6 (RHEL 8 default) without errors.
- Telemetry rows appear for a RHEL asset after running the new collection path, not just for the local host.
- No credentials appear in `logs/api.log`.
- The Vault files under `ansible/host_vars/` are excluded from Git (already in `.gitignore`).
- An asset detected as RHEL 7 or RHEL 10 (if one is accidentally pointed at) is marked `unsupported` and refused with 409, not silently run through the `dnf` branch.

---

## 10. Risks and mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| No RHEL 8/9 test hosts available | Nothing in this plan can be verified | Resolve in Phase 0/1 before any other work starts |
| `dnf check-update` exit codes or output format differ from assumption | Discovery silently wrong | Confirm on real hosts in Phase 1 before relying on the parser |
| Kernel/`installonly` packages report ambiguous current version | Misleading patch-check output for the package most likely to need a reboot | Explicit newest-version resolution, tested against a host with multiple kernels installed |
| RHEL 8 default Python 3.6 | Newer syntax in shared scripts breaks silently | Write scripts to the 3.6 floor; test on RHEL 8 specifically, not just RHEL 9 |
| Architecture suffix breaks matching in only one direction | Valid packages rejected when requested with an arch suffix | Normalize both the discovered and requested package lists the same way |
| Remote telemetry not implemented | Telemetry endpoints return 404 for every RHEL asset regardless of other progress | Build the remote collection path (3.6) as part of this phase, not deferred |
| Discovery/patch timeouts too short once preflight is added | Spurious 504s unrelated to the actual platform work | Re-tune `discover_remote_patches()`'s 180s and the patch-job timeout once RHEL preflight steps are measured |
| No migration mechanism in the repo | Schema drift between environments if changes aren't applied consistently | Document the exact `ALTER TABLE` statements (section 7) and apply them by hand to every environment the same way |
| Unsupported platform (RHEL 7, RHEL 10, or anything else) accepted by mistake | Unpredictable failures if a `dnf` command is run against an incompatible host | Profile detection defaults to `unsupported`; only the three listed profiles are accepted |
| Two RHEL versions still drift apart from Ubuntu over time | Future bugs isolated to one platform | One codebase; shared test matrix; identical JSON shapes across profiles |

---

## 11. Rollout

1. Deploy to the test environment with RHEL 8 and RHEL 9.
2. Run the full test matrix on each platform, including the Ubuntu regression rows.
3. Enable RHEL hosts in `ansible/inventory.ini` one at a time, starting with a non-production host per version.
4. Reboots stay manual: administrators act on the `reboot_required` flag returned by the API.
5. For the first two weeks, watch `logs/api.log` for `patch_discovery_failed` and patch job failures, grouped by platform.
6. Revisit RHEL 7 and RHEL 10 as a separate, later plan once 8 and 9 are stable in production.

---

## 12. Open questions

1. **RHEL subscriptions:** are RHEL 8 and 9 hosts registered directly with Red Hat, through Satellite, or through a local mirror? This determines the exact preflight check in section 3.5.
2. **Ansible control node:** which Ansible version runs on the API host? Confirm it manages RHEL 8/9 targets correctly with `ansible.builtin.dnf`.
3. **Unattended upgrades on Ubuntu:** is `unattended-upgrades` enabled on the Ubuntu hosts? If it is, it may patch servers outside this system — unrelated to RHEL, but worth confirming while this area of the system is being touched.
4. **Unsupported platform behaviour:** should a patch job be refused (409, current plan) or only warned about, for an asset detected as RHEL 7, RHEL 10, or anything else not in the supported list?
5. **Telemetry collection schedule:** should remote telemetry collection (section 3.6) run on a fixed interval via cron/systemd timer, or only on demand? This affects how "fresh" `GET telemetry` data is for RHEL assets.

---

## 13. Appendix: command reference

| Purpose | Ubuntu 24.04 | RHEL 8, 9 |
|---|---|---|
| Refresh metadata | `apt update` | `dnf makecache` |
| List upgradable packages | `apt list --upgradable` | `dnf check-update --quiet` (exit 100 = updates) |
| Upgrade one package | `apt install --only-upgrade <pkg>` | `dnf upgrade <pkg>` |
| Reboot needed? | `test -f /var/run/reboot-required` | `needs-restarting -r` (exit 1 = yes) |
| Services needing restart | Not implemented | `needs-restarting -s` |
| Security updates only | Not implemented | `dnf updateinfo list security --quiet` |
| Repo status | Not implemented | `dnf repolist`, `subscription-manager status` |
| Running services (JSON) | `systemctl list-units --type=service --state=running --output=json` | Same as Ubuntu |
| Default `python3` | 3.12 | 3.6 (RHEL 8), 3.9 (RHEL 9) |
