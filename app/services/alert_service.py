"""Centralized security alert management service."""

from __future__ import annotations

from typing import Optional
from app.extensions import db
from app.models.alert import SecurityAlert
from app.utils.helpers import generate_unique_id, utc_now

VALID_STATUSES = {"Open", "Reviewed", "Resolved"}
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def create_alert(
    *,
    user_id: int,
    title: str,
    category: str,
    severity: str,
    source_module: str,
    description: str,
    source_ip: Optional[str] = None,
    target: Optional[str] = None,
    recommended_action: Optional[str] = None,
    is_demo: bool = False,
    commit: bool = False,
) -> SecurityAlert:
    """Create and persist a centralized security alert with a unique NEX ID."""
    normalized_sev = severity if severity in VALID_SEVERITIES else "Low"
    alert = SecurityAlert(
        alert_uid=generate_unique_id("NEX"),
        user_id=user_id,
        title=title[:200],
        category=category[:60],
        severity=normalized_sev,
        status="Open",
        source_module=source_module[:50],
        source_ip=source_ip[:64] if source_ip else None,
        target=target[:120] if target else None,
        description=description,
        recommended_action=recommended_action or "Investigate the event details and apply appropriate containment controls.",
        is_demo=is_demo,
    )
    db.session.add(alert)
    if commit:
        db.session.commit()
    return alert


def update_alert_status(
    alert: SecurityAlert,
    new_status: str,
    reviewer_user_id: int,
    notes: Optional[str] = None,
) -> tuple[bool, str]:
    """Transition alert status and persist audit timestamps."""
    if new_status not in VALID_STATUSES:
        return False, f"Invalid alert status '{new_status}'."

    now = utc_now()
    alert.status = new_status
    alert.reviewed_by_id = reviewer_user_id

    if new_status == "Reviewed":
        alert.reviewed_at = now
    elif new_status == "Resolved":
        if not alert.reviewed_at:
            alert.reviewed_at = now
        alert.resolved_at = now
    elif new_status == "Open":
        alert.resolved_at = None

    if notes is not None:
        alert.notes = notes.strip()[:1000]

    db.session.commit()
    return True, f"Alert {alert.alert_uid} marked as {new_status}."
