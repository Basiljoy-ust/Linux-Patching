"""Platform profiles: the single place that describes how each supported
operating system is patched. Anything not listed here is "unsupported".

Ubuntu is supported as a family, not pinned to one release: any Ubuntu
version matches the "ubuntu" profile. 24.04 is simply the version the test
host happened to run when this was built, not a restriction in the code.
RHEL is gated to specific major versions (8, 9) because that distinction
drives real behaviour differences (default Python, systemd version)."""

import re

UNSUPPORTED = "unsupported"

PLATFORM_PROFILES = {
    "ubuntu": {
        "family": "Debian",
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
    # systemd 239 cannot emit JSON for list-units (added in v246);
    # service_inventory.py falls back to text parsing automatically.
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

_ARCH_SUFFIX = re.compile(
    r"\.(x86_64|i[3-6]86|aarch64|ppc64le|s390x|noarch|src)$"
)


def is_supported(profile):
    return profile in PLATFORM_PROFILES


def normalize_profile(profile):
    """Anything that is not a known profile becomes 'unsupported'."""
    return profile if is_supported(profile) else UNSUPPORTED


def profile_info(profile):
    """Return (os_family, package_manager) for a profile, or (None, None)."""
    data = PLATFORM_PROFILES.get(profile)
    if data is None:
        return None, None
    return data["family"], data["package_manager"]


def normalize_package_name(name, package_manager=None):
    """Strip an RPM architecture suffix ('openssl.x86_64' -> 'openssl').

    Applied to both discovered and requested names. Debian package names
    are left untouched (a '.' there is part of the real name).
    """
    name = name.strip()
    if package_manager == "apt":
        return name
    return _ARCH_SUFFIX.sub("", name)
