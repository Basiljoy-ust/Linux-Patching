"""Risk scoring and presentation helpers for fleet CVEs.

One implementation, mirrored by the wireframe's window.ZD:
    score = (exploited ? 100 : reported ? 60 : 0)
            + severity_rank * 10
            + zero_day_priority / 10
so confirmed exploitation always outranks severity, and Zero-Day's own
0-100 priority is the tie-breaker.
"""

from datetime import date

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

# exploit.maturity values that mean "attackers are using it right now"
EXPLOITED_MATURITIES = {"weaponized", "in_the_wild"}

URGENCY_LABELS = {
    "act_now": "Act now",
    "this_week": "Patch this week",
    "normal": "Normal cycle",
}


def exploitation_of(row: dict) -> str:
    """'exploited' | 'reported' | 'poc' | 'none' | 'unknown' (distro-only)."""
    if row.get("source") == "distro":
        return "unknown"
    if row.get("exploited") or row.get("maturity") in EXPLOITED_MATURITIES:
        return "exploited"
    if row.get("maturity") == "reported":
        return "reported"
    if row.get("maturity") == "poc" or row.get("public_poc"):
        return "poc"
    return "none"


def score(row: dict) -> float:
    exploitation = exploitation_of(row)
    base = 100 if exploitation == "exploited" else 60 if exploitation == "reported" else 0
    rank = SEVERITY_RANK.get((row.get("severity") or "unknown").lower(), 0)
    priority = float(row.get("priority_score") or 0)
    return base + rank * 10 + priority / 10


def badges(row: dict) -> dict:
    exploitation = exploitation_of(row)
    return {
        "exploited": exploitation == "exploited",
        "kev": bool(row.get("kev")),
        "ransomware": bool(row.get("ransomware")),
        "zero_day": bool(row.get("true_zero_day")),
        "reported": exploitation == "reported",
        "poc": bool(row.get("public_poc")) or row.get("maturity") == "poc",
    }


def days_left(due_date) -> int | None:
    """Days until the KEV deadline; negative when overdue; None without one."""
    if due_date is None:
        return None
    if isinstance(due_date, str):
        try:
            due_date = date.fromisoformat(due_date)
        except ValueError:
            return None
    return (due_date - date.today()).days


def urgency_label(level: str | None) -> str | None:
    if level is None:
        return None
    return URGENCY_LABELS.get(level, level)
