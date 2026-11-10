"""Ubuntu package -> CVE mapping via OSV.dev.

Zero-Day Radar knows CVEs by vendor product names ("Sudo", "Linux
Kernel"), not by distro packages, and its /item records often have no
package versions at all. The authoritative link between an Ubuntu
package upgrade and the CVEs it fixes is the distro's own data; OSV.dev
republishes the Ubuntu security tracker in a queryable API.

We ask: which known vulnerabilities affect the *installed* version of
each pending package? Those are (a superset of) the CVEs the pending
upgrade addresses.
"""

import os

import requests

from core.config import api_logger

OSV_BASE = os.environ.get("OSV_BASE_URL", "https://api.osv.dev").rstrip("/")
TIMEOUT_SECONDS = 30
BATCH_SIZE = 100  # OSV querybatch page size (its own cap is 1000)
# How many non-CVE vuln ids to resolve to aliases per call, to bound latency.
MAX_DETAIL_LOOKUPS = 25


def _cve_ids_from(vuln_ids: list[str]) -> tuple[set[str], list[str]]:
    """Split OSV vuln ids into CVE ids and ids that need an alias lookup."""
    cves: set[str] = set()
    unresolved: list[str] = []
    for vuln_id in vuln_ids:
        if vuln_id.startswith("CVE-"):
            cves.add(vuln_id)
        elif vuln_id.startswith("UBUNTU-CVE-"):
            cves.add(vuln_id[len("UBUNTU-"):])
        else:
            unresolved.append(vuln_id)
    return cves, unresolved


def _resolve_aliases(vuln_id: str) -> set[str]:
    """Fetch one OSV record and pull CVE ids out of its aliases."""
    try:
        response = requests.get(
            f"{OSV_BASE}/v1/vulns/{vuln_id}", timeout=TIMEOUT_SECONDS
        )
        if response.status_code != 200:
            return set()
        aliases = response.json().get("aliases") or []
    except (requests.RequestException, ValueError):
        return set()
    return {alias for alias in aliases if alias.startswith("CVE-")}


def map_packages(packages: list[dict]) -> dict[str, set[str]]:
    """{package_name: {cve_id, ...}} for Ubuntu packages.

    `packages` are discovery entries: {name, current_version, ...}.
    Packages OSV knows nothing about simply come back with an empty set.
    """
    queries = []
    names = []
    for package in packages:
        version = package.get("current_version")
        if not version:
            continue
        names.append(package["name"])
        queries.append(
            {
                "package": {"ecosystem": "Ubuntu", "name": package["name"]},
                "version": version,
            }
        )

    mapping: dict[str, set[str]] = {name: set() for name in names}
    detail_budget = MAX_DETAIL_LOOKUPS

    for start in range(0, len(queries), BATCH_SIZE):
        chunk = queries[start:start + BATCH_SIZE]
        try:
            response = requests.post(
                f"{OSV_BASE}/v1/querybatch",
                json={"queries": chunk},
                timeout=TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            results = response.json().get("results") or []
        except (requests.RequestException, ValueError) as exc:
            api_logger.warning("osv_querybatch_failed error=%s", exc)
            continue

        for index, result in enumerate(results):
            name = names[start + index]
            vuln_ids = [v["id"] for v in (result.get("vulns") or []) if v.get("id")]
            cves, unresolved = _cve_ids_from(vuln_ids)

            for vuln_id in unresolved:
                if detail_budget <= 0:
                    break
                detail_budget -= 1
                cves |= _resolve_aliases(vuln_id)

            mapping[name] |= cves

    return mapping
