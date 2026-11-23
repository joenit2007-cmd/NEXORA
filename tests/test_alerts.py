"""Centralized Alert Management tests."""

from app.extensions import db
from app.models import SecurityAlert
from app.services.alert_service import create_alert


def test_alert_creation_status_transitions_filtering_and_export(auth_client, app, admin_user):
    with app.app_context():
        a1 = create_alert(
            user_id=admin_user.id,
            title="Brute-Force Attack from 203.0.113.8",
            category="Brute-Force Attack",
            severity="Critical",
            source_module="Log Analyzer",
            source_ip="203.0.113.8",
            description="10 failed SSH logins in 2 minutes.",
            commit=True,
        )
        a2 = create_alert(
            user_id=admin_user.id,
            title="Low Risk Audit Note",
            category="Audit",
            severity="Low",
            source_module="Network Monitor",
            description="Routine local scan completed.",
            commit=True,
        )
        assert a1.alert_uid.startswith("NEX-")
        assert a1.alert_uid != a2.alert_uid
        a1_id = a1.id

    # Severity filtering
    crit_page = auth_client.get("/alerts?severity=Critical")
    assert crit_page.status_code == 200
    assert b"Brute-Force Attack from 203.0.113.8" in crit_page.data
    assert b"Low Risk Audit Note" not in crit_page.data

    # Mark Reviewed via form POST
    rev_resp = auth_client.post(
        f"/alerts/{a1_id}/status",
        data={"status": "Reviewed"},
        follow_redirects=True,
    )
    assert rev_resp.status_code == 200
    with app.app_context():
        refreshed = db.session.get(SecurityAlert, a1_id)
        assert refreshed.status == "Reviewed"
        assert refreshed.reviewed_at is not None

    # Mark Resolved via JSON API
    res_json = auth_client.post(
        f"/alerts/{a1_id}/status",
        json={"status": "Resolved", "notes": "Blocked offending IP at firewall."},
    )
    assert res_json.status_code == 200
    payload = res_json.get_json()
    assert payload["success"] is True
    assert payload["alert"]["status"] == "Resolved"
    with app.app_context():
        refreshed = db.session.get(SecurityAlert, a1_id)
        assert refreshed.status == "Resolved"
        assert refreshed.resolved_at is not None
        assert "Blocked offending IP" in refreshed.notes

    # CSV export
    csv_resp = auth_client.get("/alerts/export")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.content_type
    assert b"Brute-Force Attack from 203.0.113.8" in csv_resp.data
