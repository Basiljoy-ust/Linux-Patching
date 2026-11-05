import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

from database import get_connection


BASE_DIR = Path(__file__).resolve().parent.parent
COLLECTOR_PATH = BASE_DIR / "telemetry" / "collector.py"
ANSIBLE_DIR = BASE_DIR / "ansible"
ANSIBLE_INVENTORY = ANSIBLE_DIR / "inventory.ini"
# Keep in sync with LOCAL_INVENTORY_HOSTS in main.py
LOCAL_INVENTORY_HOSTS = {"localhost", "Linux-patching1"}
DEFAULT_HOST = "Linux-patching1"
REMOTE_TIMEOUT_SECONDS = 120
ANSIBLE_VAULT_PASSWORD_FILE = Path(
    os.environ.get(
        "ANSIBLE_VAULT_PASSWORD_FILE",
        str(Path.home() / ".config" / "linux-patching" / "vault-password"),
    )
)


def get_asset_id(hostname=DEFAULT_HOST):
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id
                FROM assets
                WHERE hostname = %s
                """,
                (hostname,),
            )

            row = cursor.fetchone()

            if row is None:
                raise RuntimeError(
                    f"{hostname} is not registered in assets"
                )

            return row[0]

    finally:
        connection.close()


def get_active_hostnames():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT hostname
                FROM assets
                WHERE UPPER(status) = 'ACTIVE'
                ORDER BY hostname
                """
            )
            return [row[0] for row in cursor.fetchall()]

    finally:
        connection.close()


def collect_local_telemetry():
    result = subprocess.run(
        [
            "/usr/bin/python3",
            str(COLLECTOR_PATH),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return json.loads(result.stdout)


def collect_remote_telemetry(hostname):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", hostname):
        raise RuntimeError(f"Invalid hostname: {hostname}")

    credentials_file = ANSIBLE_DIR / "host_vars" / hostname / "vault.yml"

    if not ANSIBLE_VAULT_PASSWORD_FILE.is_file():
        raise RuntimeError("Ansible Vault password file is not configured")

    if not credentials_file.is_file():
        raise RuntimeError(f"No encrypted credentials for {hostname}")

    with TemporaryDirectory(prefix="linux-patching-telemetry-") as output_dir:
        result = subprocess.run(
            [
                "/usr/bin/ansible-playbook",
                "-i",
                str(ANSIBLE_INVENTORY),
                str(ANSIBLE_DIR / "telemetry_collect.yml"),
                "--vault-password-file",
                str(ANSIBLE_VAULT_PASSWORD_FILE),
                "--limit",
                hostname,
                "-e",
                f"telemetry_output_dir={output_dir}",
            ],
            capture_output=True,
            text=True,
            timeout=REMOTE_TIMEOUT_SECONDS,
            check=False,
            cwd=BASE_DIR,
        )

        if result.returncode != 0:
            raise RuntimeError(
                f"Remote telemetry collection failed for {hostname}: "
                f"{(result.stderr.strip() or result.stdout.strip())[-2000:]}"
            )

        output_file = Path(output_dir) / f"telemetry-{hostname}.json"

        return json.loads(output_file.read_text())


def collect_telemetry(hostname=DEFAULT_HOST):
    if hostname in LOCAL_INVENTORY_HOSTS:
        return collect_local_telemetry()

    return collect_remote_telemetry(hostname)


def save_telemetry(data, asset_id):
    connection = get_connection()

    try:
        with connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    INSERT INTO telemetry_snapshots (
                        asset_id,
                        captured_at,
                        cpu_usage_percent,
                        memory_total_mb,
                        memory_used_mb,
                        memory_available_mb,
                        memory_usage_percent,
                        load_1m,
                        load_5m,
                        load_15m,
                        disk_total_gb,
                        disk_used_gb,
                        disk_free_gb,
                        disk_usage_percent,
                        network_data
                    )
                    VALUES (
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s,
                        %s
                    )
                    """,
                    (
                        asset_id,
                        data["timestamp"],
                        data["cpu"]["usage_percent"],
                        data["memory"]["total_mb"],
                        data["memory"]["used_mb"],
                        data["memory"]["available_mb"],
                        data["memory"]["usage_percent"],
                        data["load"]["1m"],
                        data["load"]["5m"],
                        data["load"]["15m"],
                        data["disk"]["total_gb"],
                        data["disk"]["used_gb"],
                        data["disk"]["free_gb"],
                        data["disk"]["usage_percent"],
                        json.dumps(data["network"]),
                    ),
                )

                for service_name, service_data in data["services"].items():

                    cursor.execute(
                        """
                        INSERT INTO service_snapshots (
                            asset_id,
                            captured_at,
                            service_name,
                            status,
                            enabled
                        )
                        VALUES (
                            %s,
                            %s,
                            %s,
                            %s,
                            %s
                        )
                        """,
                        (
                            asset_id,
                            data["timestamp"],
                            service_name,
                            service_data["status"],
                            service_data["enabled"],
                        ),
                    )

    finally:
        connection.close()


def collect_and_save(hostname):
    asset_id = get_asset_id(hostname)

    save_telemetry(
        collect_telemetry(hostname),
        asset_id,
    )

    print("Telemetry saved successfully.")
    print("Host:", hostname)
    print("Asset:", asset_id)


def main():
    parser = argparse.ArgumentParser(
        description="Collect and store telemetry for one or all assets."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Asset hostname (default: {DEFAULT_HOST})",
    )
    group.add_argument(
        "--all",
        action="store_true",
        help="Collect for every ACTIVE asset",
    )
    args = parser.parse_args()

    if not args.all:
        collect_and_save(args.host)
        return

    failures = 0

    for hostname in get_active_hostnames():
        try:
            collect_and_save(hostname)
        except Exception as exc:  # keep going; report at the end
            failures += 1
            print(f"FAILED {hostname}: {exc}", file=sys.stderr)

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
