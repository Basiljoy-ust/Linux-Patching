#!/usr/bin/env python3
# Must run on Python 3.6 (RHEL 8 default).

import json
import subprocess


LIST_UNITS = [
    "systemctl",
    "list-units",
    "--type=service",
    "--state=running",
    "--no-pager",
]


def run_checked(command):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    stdout, stderr = process.communicate(timeout=15)

    if process.returncode != 0:
        raise subprocess.CalledProcessError(
            process.returncode, command, stdout, stderr
        )

    return stdout


def systemd_json(command):
    data = json.loads(run_checked(command))
    if not isinstance(data, list):
        raise ValueError("systemctl did not return a JSON list")
    return data


def parse_plain_units(output):
    """Parse `systemctl list-units --plain --no-legend` (UNIT LOAD ACTIVE SUB ...)."""
    units = []

    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0].endswith(".service"):
            units.append({"unit": fields[0], "active": fields[2]})

    return units


def get_running_units():
    try:
        return systemd_json(LIST_UNITS + ["--output=json"])
    except (subprocess.CalledProcessError, ValueError):
        # systemd < 246 (RHEL 8 ships 239) has no JSON output for list-units
        return parse_plain_units(
            run_checked(LIST_UNITS + ["--plain", "--no-legend"])
        )


def get_services():
    return {
        unit["unit"]: {
            "status": unit["active"],
            "enabled": "unknown",
        }
        for unit in get_running_units()
        if "unit" in unit and "active" in unit
    }


if __name__ == "__main__":
    print(json.dumps(get_services(), indent=2))
