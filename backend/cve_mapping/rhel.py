"""RHEL package -> CVE mapping from `dnf updateinfo list --with-cve`.

The raw output is collected on the managed host during patch discovery
(patching/discover.py puts it in the discovery JSON as "updateinfo_cve")
and parsed here on the control node. Typical lines:

    CVE-2024-2961   Important/Sec. glibc-2.34-100.el9_4.2.x86_64
    CVE-2026-46300  Critical/Sec.  kernel-5.14.0-503.14.1.el9_5.x86_64

Lines that do not start with a CVE id (advisory ids, headers) are skipped.
"""

import re

# name-version-release.arch: version starts at the first "-<digit>"
_NEVRA = re.compile(
    r"^(?P<name>.+?)-(?P<version>\d[^-]*-[^.]+(?:\.[^.]+)*?)\.(?P<arch>[A-Za-z0-9_]+)$"
)
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SEVERITY = re.compile(r"^(?P<severity>[A-Za-z]+)/Sec\.?$")

# Red Hat advisory severities -> the CVSS-style scale the rest of the
# system uses (zeroday_cves.severity, risk.SEVERITY_RANK).
_SEVERITY_MAP = {
    "critical": "critical",
    "important": "high",
    "moderate": "medium",
    "low": "low",
}


def _split_nevra(nevra: str) -> tuple[str, str | None]:
    """'glibc-2.34-100.el9_4.2.x86_64' -> ('glibc', '2.34-100.el9_4.2')."""
    match = _NEVRA.match(nevra)
    if match:
        return match.group("name"), match.group("version")

    # Fallback: split at the first "-<digit>" and drop a trailing arch.
    parts = re.split(r"-(?=\d)", nevra, maxsplit=1)
    name = parts[0]
    version = parts[1] if len(parts) > 1 else None
    if version:
        version = re.sub(
            r"\.(x86_64|i[3-6]86|aarch64|ppc64le|s390x|noarch|src)$", "", version
        )
    return name, version


def parse_updateinfo(text: str) -> list[dict]:
    """Parse updateinfo output into
    [{cve_id, package, fixed_version, distro_severity}].
    """
    rows = []

    for line in (text or "").splitlines():
        tokens = line.split()
        if len(tokens) < 3:
            continue
        if not _CVE.match(tokens[0]):
            continue

        severity_match = _SEVERITY.match(tokens[1])
        severity = None
        if severity_match:
            severity = _SEVERITY_MAP.get(
                severity_match.group("severity").lower()
            )

        package, fixed_version = _split_nevra(tokens[2])

        rows.append(
            {
                "cve_id": tokens[0],
                "package": package,
                "fixed_version": fixed_version,
                "distro_severity": severity,
            }
        )

    return rows
