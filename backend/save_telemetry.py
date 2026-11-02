import json
import subprocess
from pathlib import Path

from database import get_connection


BASE_DIR = Path(__file__).resolve().parent.parent
COLLECTOR_PATH = BASE_DIR / "telemetry" / "collector.py"


def get_asset_id():
    connection = get_connection()

    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id
                FROM assets
                WHERE hostname = %s
                """,
                ("Linux-patching1",),
            )

            row = cursor.fetchone()

            if row is None:
                raise RuntimeError(
                    "Linux-patching1 is not registered in assets"
                )

            return row[0]

    finally:
        connection.close()


def collect_telemetry():
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


def main():
    asset_id = get_asset_id()

    telemetry = collect_telemetry()

    save_telemetry(
        telemetry,
        asset_id,
    )

    print("Telemetry saved successfully.")
    print("Asset:", asset_id)


if __name__ == "__main__":
    main()
