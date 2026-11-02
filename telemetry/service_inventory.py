#!/usr/bin/env python3

import json
import subprocess


def systemd_json(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    data = json.loads(result.stdout)
    if not isinstance(data, list):
        raise ValueError("systemctl did not return a JSON list")
    return data


def get_services():
    running_units = systemd_json([
        "systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--output=json",
        "--no-pager",
    ])

    return {
        unit["unit"]: {
            "status": unit["active"],
            "enabled": "unknown",
        }
        for unit in running_units
        if "unit" in unit and "active" in unit
    }


if __name__ == "__main__":
    print(json.dumps(get_services(), indent=2))
