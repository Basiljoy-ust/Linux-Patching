"""Database access for the synced Zero-Day data.

Writes are done by the sync loop (zeroday/sync.py); reads by the routers.
"""

import json
from datetime import datetime, timezone

from database import get_connection


# ---------------------------------------------------------------- CVEs


def _extract_row(record: dict) -> tuple:
    """Flatten one /feed record into the zeroday_cves columns."""
    exploit = record.get("exploit") or {}
    kev = record.get("kev") or {}
    cvss = record.get("cvss") or {}
    epss = record.get("epss") or {}
    priority = record.get("priority") or {}
    guard = record.get("guard") or {}
    urgency = (guard.get("urgency") or {}).get("level")

    return (
        record["id"],
        record.get("title"),
        record.get("vendor"),
        record.get("severity") or "unknown",
        cvss.get("score"),
        epss.get("score"),
        epss.get("percentile"),
        priority.get("score"),
        record.get("confidence"),
        exploit.get("maturity") or "none",
        bool(exploit.get("confirmed_in_the_wild")),
        bool(exploit.get("ransomware")),
        bool(exploit.get("true_zero_day")),
        bool(exploit.get("public_poc")),
        bool(kev),
        kev.get("due_date"),
        urgency,
        record.get("first_seen"),
        record.get("last_updated"),
        json.dumps(record),
    )


UPSERT_CVE = """
    INSERT INTO zeroday_cves (
        cve_id, title, vendor, severity, cvss_score, epss_score,
        epss_percentile, priority_score, confidence, maturity, exploited,
        ransomware, true_zero_day, public_poc, kev, kev_due_date, urgency,
        first_seen, last_updated, record, synced_at
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, NOW())
    ON CONFLICT (cve_id) DO UPDATE SET
        title = EXCLUDED.title,
        vendor = EXCLUDED.vendor,
        severity = EXCLUDED.severity,
        cvss_score = EXCLUDED.cvss_score,
        epss_score = EXCLUDED.epss_score,
        epss_percentile = EXCLUDED.epss_percentile,
        priority_score = EXCLUDED.priority_score,
        confidence = EXCLUDED.confidence,
        maturity = EXCLUDED.maturity,
        exploited = EXCLUDED.exploited,
        ransomware = EXCLUDED.ransomware,
        true_zero_day = EXCLUDED.true_zero_day,
        public_poc = EXCLUDED.public_poc,
        kev = EXCLUDED.kev,
        kev_due_date = EXCLUDED.kev_due_date,
        urgency = EXCLUDED.urgency,
        first_seen = EXCLUDED.first_seen,
        last_updated = EXCLUDED.last_updated,
        record = EXCLUDED.record,
        synced_at = NOW()
"""


def upsert_cves(records: list[dict]) -> int:
    if not records:
        return 0

    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                for record in records:
                    if not record.get("id"):
                        continue
                    cursor.execute(UPSERT_CVE, _extract_row(record))
        return len(records)
    finally:
        connection.close()


def delete_cves_not_in(keep_ids: set[str]) -> int:
    """After a FULL sync: drop CVEs Zero-Day no longer returns (retention)."""
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT cve_id FROM zeroday_cves")
                stale = [row[0] for row in cursor.fetchall() if row[0] not in keep_ids]
                if stale:
                    cursor.execute(
                        "DELETE FROM zeroday_cves WHERE cve_id = ANY(%s)",
                        (stale,),
                    )
                return len(stale)
    finally:
        connection.close()


# ---------------------------------------------------------------- sync state


def get_sync_state() -> dict:
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT server_time, last_sync_at, last_full_sync_at, last_error
                FROM zd_sync_state WHERE id
                """
            )
            row = cursor.fetchone()
            if row is None:
                return {
                    "server_time": None,
                    "last_sync_at": None,
                    "last_full_sync_at": None,
                    "last_error": None,
                }
            return {
                "server_time": row[0],
                "last_sync_at": row[1],
                "last_full_sync_at": row[2],
                "last_error": row[3],
            }
    finally:
        connection.close()


def set_sync_state(
    server_time: str | None = None,
    full: bool = False,
    error: str | None = None,
) -> None:
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO zd_sync_state (id, server_time, last_sync_at,
                                               last_full_sync_at, last_error)
                    VALUES (TRUE, %(server_time)s,
                            CASE WHEN %(error)s IS NULL THEN NOW() END,
                            CASE WHEN %(full)s THEN NOW() END,
                            %(error)s)
                    ON CONFLICT (id) DO UPDATE SET
                        server_time = COALESCE(%(server_time)s, zd_sync_state.server_time),
                        last_sync_at = CASE WHEN %(error)s IS NULL
                                            THEN NOW()
                                            ELSE zd_sync_state.last_sync_at END,
                        last_full_sync_at = CASE WHEN %(full)s
                                                 THEN NOW()
                                                 ELSE zd_sync_state.last_full_sync_at END,
                        last_error = %(error)s
                    """,
                    {"server_time": server_time, "full": full, "error": error},
                )
    finally:
        connection.close()


# ---------------------------------------------------------------- cache


def cache_put(key: str, payload) -> None:
    connection = get_connection()
    try:
        with connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO zd_cache (key, payload, fetched_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE SET
                        payload = EXCLUDED.payload,
                        fetched_at = NOW()
                    """,
                    (key, json.dumps(payload)),
                )
    finally:
        connection.close()


def cache_get(key: str, max_age_seconds: int | None = None):
    """Return (payload, fetched_at) or (None, None) when missing/stale."""
    connection = get_connection()
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT payload, fetched_at FROM zd_cache WHERE key = %s",
                (key,),
            )
            row = cursor.fetchone()
    finally:
        connection.close()

    if row is None:
        return None, None

    payload, fetched_at = row
    if max_age_seconds is not None and fetched_at is not None:
        age = (datetime.now(timezone.utc) - fetched_at).total_seconds()
        if age > max_age_seconds:
            return None, fetched_at
    return payload, fetched_at
