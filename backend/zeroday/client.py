"""HTTP client for the Zero-Day Radar API.

The only module that talks to Zero-Day. Always server-side, over the
internal address (ZERODAY_BASE_URL), never from the browser.

Every successful Zero-Day response wraps its payload in
{"status_code", "message", "data"}; this client unwraps it and returns
just the data. Errors (404, 422) are NOT wrapped — see docs/API.md in
the Zero_day Radar repo.
"""

import os

import requests

from core.config import api_logger

# Default assumes Zero-Day is reachable through the local reverse proxy,
# as deployed (nginx serves it under /zero-day on the same host).
BASE_URL = os.environ.get(
    "ZERODAY_BASE_URL", "http://127.0.0.1/zero-day"
).rstrip("/")
API = f"{BASE_URL}/api/v1/zeroday"
TIMEOUT_SECONDS = int(os.environ.get("ZERODAY_HTTP_TIMEOUT", "30"))


class ZeroDayUnavailable(Exception):
    """Zero-Day Radar could not be reached or answered with an error."""


def _get(path: str, params: dict | None = None) -> dict | list:
    url = f"{API}{path}"
    try:
        response = requests.get(url, params=params, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        raise ZeroDayUnavailable(f"GET {url}: {exc}") from exc

    if response.status_code != 200:
        raise ZeroDayUnavailable(
            f"GET {url}: HTTP {response.status_code}: {response.text[:500]}"
        )

    try:
        return response.json()["data"]
    except (ValueError, KeyError) as exc:
        raise ZeroDayUnavailable(f"GET {url}: invalid response body") from exc


def feed(
    since: str | None = None,
    limit: int = 1000,
    offset: int = 0,
    sort: str = "recent",
) -> dict:
    """One page of /feed: {generated_at, server_time, total, items}.

    `since` must be a server_time value returned by a previous call,
    passed back verbatim (it is compared as text by the API).
    """
    params: dict = {"limit": limit, "offset": offset, "sort": sort}
    if since:
        params["since"] = since
    return _get("/feed", params)


def item(cve_id: str) -> dict | None:
    """Full record for one CVE, or None when Zero-Day does not track it."""
    url = f"{API}/item/{cve_id}"
    try:
        response = requests.get(url, timeout=TIMEOUT_SECONDS)
    except requests.RequestException as exc:
        raise ZeroDayUnavailable(f"GET {url}: {exc}") from exc

    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise ZeroDayUnavailable(
            f"GET {url}: HTTP {response.status_code}: {response.text[:500]}"
        )

    try:
        return response.json()["data"]
    except (ValueError, KeyError) as exc:
        raise ZeroDayUnavailable(f"GET {url}: invalid response body") from exc


def sources() -> list:
    """Health of each intelligence feed."""
    return _get("/sources")


def metrics() -> dict:
    """Radar-wide counters; used for generated_at and attributions."""
    return _get("/metrics")


def signals() -> list:
    """Pre-CVE zero-day chatter, one cluster per vendor."""
    return _get("/signals")


def health() -> bool:
    """True when the Zero-Day process answers its root health check."""
    try:
        response = requests.get(f"{BASE_URL}/", timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        api_logger.warning("zeroday_health_check_failed base=%s", BASE_URL)
        return False
