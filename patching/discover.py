#!/usr/bin/env python3
# Runs on managed hosts; must work on Python 3.6 (RHEL 8 default).

import json
import re
import subprocess
from datetime import datetime, timezone


SUPPORTED = {
    ("ubuntu", "24.04"): ("ubuntu-24.04", "Debian", "apt"),
    ("rhel", "9"): ("rhel-9", "RedHat", "dnf"),
    ("rhel", "8"): ("rhel-8", "RedHat", "dnf"),
}


def run_command(command):
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    stdout, stderr = process.communicate()

    return {
        "returncode": process.returncode,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
    }


def read_os_release(path="/etc/os-release"):
    values = {}

    try:
        with open(path, "r") as handle:
            for line in handle:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key] = value.strip().strip('"').strip("'")
    except OSError:
        pass

    return values


def detect_platform(os_release=None):
    """Return (profile, os_family, package_manager). Unknown -> unsupported."""
    if os_release is None:
        os_release = read_os_release()

    distro = os_release.get("ID", "").lower()
    version = os_release.get("VERSION_ID", "")

    if distro == "rhel":
        version = version.split(".")[0]

    match = SUPPORTED.get((distro, version))

    if match is None:
        return "unsupported", None, None

    return match


# ---------------------------------------------------------------- apt


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


# ---------------------------------------------------------------- dnf


def parse_dnf_check_update(output):
    """Parse `dnf check-update --quiet` into (name, arch, version) tuples.

    Lines look like 'openssl.x86_64   1:3.0.7-27.el9   baseos'. Long names
    can wrap, so tokens are accumulated until a full triplet is seen.
    Parsing stops at the 'Obsoleting Packages' section.
    """
    updates = []
    tokens = []

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        if line.startswith("Obsoleting Packages"):
            break

        if line.startswith(("Last metadata", "Security:")):
            continue

        tokens.extend(line.split())

        while len(tokens) >= 3:
            name_arch, version = tokens[0], tokens[1]
            tokens = tokens[3:]

            if "." not in name_arch:
                continue

            name, arch = name_arch.rsplit(".", 1)
            updates.append((name, arch, version))

    return updates


def version_key(version):
    """Rough rpmvercmp-style sort key (digits compare numerically)."""
    parts = re.findall(r"\d+|[A-Za-z]+", version)
    return [
        (1, int(part), "") if part.isdigit() else (0, 0, part)
        for part in parts
    ]


def installed_versions(name, arch):
    result = run_command(
        [
            "rpm",
            "-q",
            "--qf",
            "%{VERSION}-%{RELEASE}\\n",
            "{0}.{1}".format(name, arch),
        ]
    )

    if result["returncode"] != 0:
        return []

    return [
        line.strip()
        for line in result["stdout"].splitlines()
        if line.strip()
    ]


def discover_dnf():
    result = run_command(["dnf", "check-update", "--quiet"])

    # 0 = nothing to update, 100 = updates available, anything else = error
    if result["returncode"] not in (0, 100):
        raise RuntimeError(
            "dnf check-update failed (exit {0}): {1}".format(
                result["returncode"],
                result["stderr"] or result["stdout"],
            )
        )

    packages = []

    for name, arch, available in parse_dnf_check_update(result["stdout"]):
        versions = installed_versions(name, arch)
        entry = {
            "name": name,
            "arch": arch,
            "current_version": None,
            "available_version": available,
        }

        if versions:
            entry["current_version"] = max(versions, key=version_key)

        if len(versions) > 1:
            # installonly packages (kernel): older versions stay installed
            entry["installonly"] = True
            entry["installed_versions"] = sorted(versions, key=version_key)
            entry["note"] = (
                "Newest installed version shown; older versions remain "
                "installed."
            )

        packages.append(entry)

    return packages


# ---------------------------------------------------------------- main


def main():
    profile, os_family, package_manager = detect_platform()

    packages = []

    if package_manager == "apt":
        result = run_command(["apt", "list", "--upgradable"])
        packages = parse_packages(result["stdout"])
    elif package_manager == "dnf":
        packages = discover_dnf()

    response = {
        "checked_at": datetime.now(
            timezone.utc
        ).isoformat(),

        "platform_profile": profile,

        "os_family": os_family,

        "package_manager": package_manager,

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
