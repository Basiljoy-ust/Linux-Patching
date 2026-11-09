# API logs

The API writes rotating request and patch-discovery logs to `logs/api.log` in
the project directory. It keeps five rotated files of up to 5 MiB each.
Requests log their method, path, status, and duration. Patch discovery also
logs the selected inventory hostname, result timestamp, and number of
available packages. Passwords and Vault contents are not logged.
Live service discovery logs the selected hostname and number of running
systemd services found.

Run these commands from the project directory:

```bash
tail -f logs/api.log
grep 'patch_discovery_' logs/api.log
```

For a patch check, find the `patch_check_requested` and
`patch_discovery_completed` entries. The `target` field is the inventory
hostname Ansible was asked to check. For `GET /services`, look for
`service_discovery_completed`. The API process account needs write permission
to the project's `logs/` directory.

## Multi-platform support (Ubuntu, RHEL 8, RHEL 9)

`platform_profiles.py` defines the supported profiles. `patch-check` and
`patch-jobs` always run discovery first, store the detected `os_family` /
`platform_profile` on the asset, and return **409 "Platform not supported"** for
anything else (including RHEL 7 and RHEL 10).

- `GET /api/assets` also returns `os_family`, `platform_profile`, `package_manager`.
- RPM architecture suffixes are stripped from both discovered and requested
  package names, so `openssl` and `openssl.x86_64` are equivalent.
- `POST patch-jobs` stores `reboot_required` (NULL if the playbook could not
  report it) and returns it with `os_family` and `platform_profile`.
- Timeouts can be tuned with `PATCH_DISCOVERY_TIMEOUT` (default 180s) and
  `PATCH_JOB_TIMEOUT` (default 900s).

Existing databases: apply `database/alter_platform_profiles.sql` by hand.

Remote telemetry (run from cron or a systemd timer):

```bash
python save_telemetry.py --host <hostname>
python save_telemetry.py --all      # every ACTIVE asset
```
