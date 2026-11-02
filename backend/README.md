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
