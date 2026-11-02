#!/usr/bin/env python3

import json
import subprocess
from datetime import datetime, timezone


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    return {
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def parse_packages(output):
    packages = []

    for line in output.splitlines():

        line = line.strip()

        if not line:
            continue

        if line.startswith("Listing"):
            continue

        if "/" not in line:
            continue

        package_part = line.split("/", 1)

        package_name = package_part[0]

        if " [upgradable from: " not in line:
            continue

        old_version = line.split(
            "[upgradable from: ",
            1
        )[1].rstrip("]")

        package_version = line.split()[1]

        packages.append(
            {
                "name": package_name,
                "current_version": old_version,
                "available_version": package_version,
            }
        )

    return packages


def main():
    result = run_command(
        [
            "apt",
            "list",
            "--upgradable",
        ]
    )

    packages = parse_packages(
        result["stdout"]
    )

    response = {
        "checked_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "package_manager": "apt",

        "package_count": len(packages),

        "packages": packages,
    }

    print(
        json.dumps(
            response,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
