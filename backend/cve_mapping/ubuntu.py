"""Ubuntu package -> CVE mapping via OSV.dev.

Zero-Day Radar knows CVEs by vendor product names ("Sudo", "Linux
Kernel"), not by distro packages, and it only tracks exploited/recent
CVEs. The authoritative link between an Ubuntu package and its CVEs is
the distro's own data; OSV.dev republishes the Ubuntu security tracker
in a queryable API.

We ask: which known vulnerabilities affect the *installed* version of
each pending package? Those are (a superset of) the CVEs the pending
upgrade addresses. For each one we also take the Ubuntu advisory
severity and a one-line description, so CVEs that Zero-Day Radar does
not track still render meaningfully in the UI.
"""

import os

import requests

from core.config import api_logger

OSV_BASE = os.environ.get("OSV_BASE_URL", "https://api.osv.dev").rstrip("/")
TIMEOUT_SECONDS = 30
BATCH_SIZE = 100          # OSV querybatch page size (its own cap is 1000)
DETAIL_BUDGET = 60        # full-record fetches per call, to bound latency

SEVERITIES = {"low", "medium", "high", "critical"}


def _fetch_vuln(vuln_id: str) -> tuple[set[str], str | None, str | None]:
    """One OSV record -> (cve_ids, title, severity)."""
    try:
        response = requests.get(
            f"{OSV_BASE}/v1/vulns/{vuln_id}", timeout=TIMEOUT_SECONDS
        )
        if response.status_code != 200:
            return set(), None, None
        record = response.json()
    except (requests.RequestException, ValueError):
        return set(), None, None

    cves = {a for a in (record.get("aliases") or []) if a.startswith("CVE-")}
    if vuln_id.startswith("UBUNTU-CVE-"):
        cves.add(vuln_id[len("UBUNTU-"):])
    elif vuln_id.startswith("CVE-"):
        cves.add(vuln_id)

    title = (record.get("summary") or "").strip()
    if not title:
        details = (record.get("details") or "").strip()
        title = details.split("\n")[0][:200] if details else ""

    # Ubuntu's own advisory rating rides along in the severity array:
    # {"type": "Ubuntu", "score": "medium"}
    severity = None
    for entry in record.get("severity") or []:
        score = str(entry.get("score", "")).lower()
        if entry.get("type") == "Ubuntu" and score in SEVERITIES:
            severity = score
            break

    return cves, title or None, severity


def _cve_from_id(vuln_id: str) -> str | None:
    """CVE id derivable from the OSV id alone, without a record fetch."""
    if vuln_id.startswith("CVE-"):
        return vuln_id
    if vuln_id.startswith("UBUNTU-CVE-"):
        return vuln_id[len("UBUNTU-"):]
    return None


def map_packages(packages: list[dict]) -> dict[str, dict[str, dict]]:
    """{package: {cve_id: {"title": str|None, "severity": str|None}}}.

    `packages` are discovery entries: {name, current_version, ...}.
    Packages OSV knows nothing about come back with an empty dict.
    Beyond DETAIL_BUDGET record fetches, CVE ids are still captured
    (derived from the OSV id) but without title/severity; the sync
    loop's next pass fills them in.
    """
    queries, names = [], []
    for package in packages:
        version = package.get("current_version")
        if not version:
            continue
        names.append(package["name"])
        queries.append(
            {"package": {"ecosystem": "Ubuntu", "name": package["name"]},
             "version": version}
        )

    mapping: dict[str, dict[str, dict]] = {name: {} for name in names}
    budget = DETAIL_BUDGET

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
            entry = mapping[name]
            for vuln in result.get("vulns") or []:
                vuln_id = vuln.get("id")
                if not vuln_id:
                    continue
                if budget > 0:
                    budget -= 1
                    cves, title, severity = _fetch_vuln(vuln_id)
                    for cve in cves:
                        known = entry.setdefault(cve, {"title": None, "severity": None})
                        known["title"] = known["title"] or title
                        known["severity"] = known["severity"] or severity
                else:
                    cve = _cve_from_id(vuln_id)
                    if cve:
                        entry.setdefault(cve, {"title": None, "severity": None})

    return mapping
