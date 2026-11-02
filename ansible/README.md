# Remote server credentials

Remote SSH and sudo passwords are stored in Ansible Vault, not in the database,
inventory, API arguments, or plaintext project files. Each host has a separate
encrypted file, so adding servers does not require sharing one password across
the fleet.

## One-time setup on the master

Create a Vault password file readable only by the account that runs the API:
run these commands as that OS account:

```bash
install -d -m 700 ~/.config/linux-patching
umask 077
openssl rand -base64 48 > ~/.config/linux-patching/vault-password
```

Create the encrypted credentials for `linux-server1`:

```bash
mkdir -p ansible/host_vars/linux-server1
ansible-vault create \
  --vault-password-file ~/.config/linux-patching/vault-password \
  ansible/host_vars/linux-server1/vault.yml
```

In the editor that opens, add the SSH password and sudo password:

```yaml
ansible_password: "SSH_LOGIN_PASSWORD"
ansible_become_password: "SUDO_PASSWORD"
```

If the account can sudo without a password, omit `ansible_become_password`.
Ansible reads this encrypted host-vars file automatically. Subsequent patch
checks and patch jobs do not prompt for either password.

Confirm and trust the server's SSH host-key fingerprint before the first
connection. Host-key checking is enabled; do not disable it to bypass a
verification error.

For another inventory host, create a corresponding encrypted file under
`ansible/host_vars/<inventory-hostname>/vault.yml`. The Vault password file
must be available to the OS account running the API; if the API runs as a
service user, provision the file for that user with mode `0600` and set
`ANSIBLE_VAULT_PASSWORD_FILE` to its path.

Do not commit `vault.yml` or the Vault password file. The repository ignores
the per-host `vault.yml` files. Protect and back up the Vault password file
separately: encrypted credentials cannot be recovered without it.

## Test remote patch discovery

After confirming the server's SSH host key and configuring its credentials:

```bash
ansible-playbook -i ansible/inventory.ini \
  ansible/patch_discovery.yml \
  --vault-password-file ~/.config/linux-patching/vault-password \
  --limit linux-server1 \
  -e patch_discovery_output_dir=/tmp
```

The inventory keeps localhost and remote machines available as patch targets.
The application selects the asset's inventory hostname as its `--limit`, so a
patch check or job targets only that selected host. Do not run a patch playbook
without `--limit`.

## List running services

The API endpoint `GET /api/assets/{asset_id}/services` queries the selected
asset live and returns all currently running systemd services, including each
unit's active state. Enabled state is reported as `unknown` because checking
unit-file enablement separately can block on slow systemd hosts. It no longer
depends on the old
`telemetry/critical-services.txt` allowlist or previously saved service
snapshots.

Telemetry collection also discovers all running services. Its Ansible
playbooks copy `telemetry/service_inventory.py` alongside the collector.
