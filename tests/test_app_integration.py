"""End-to-end application routes, security headers, health, demo data, and settings tests."""

from app.models import SecurityAlert, User


def test_health_endpoint_and_security_headers(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "healthy"
    assert data["application"] == "NEXORA"
    assert data["database"] == "connected"

    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in resp.headers


def test_all_authenticated_pages_render_cleanly(auth_client):
    pages = [
        "/dashboard",
        "/logs",
        "/network",
        "/vulnerabilities",
        "/phishing",
        "/alerts",
        "/reports",
        "/history",
        "/settings",
        "/about",
    ]
    for route in pages:
        resp = auth_client.get(route)
        assert resp.status_code == 200, f"Route {route} returned {resp.status_code}"
        assert b"NEXORA" in resp.data


def test_dashboard_demo_load_api_stats_and_clear(auth_client, app):
    # Initially zero alerts
    initial = auth_client.get("/api/dashboard/stats").get_json()
    assert initial["kpis"]["critical_alerts"] == 0

    # Load demo dataset
    load_resp = auth_client.post("/dashboard/load-demo", follow_redirects=True)
    assert load_resp.status_code == 200

    loaded = auth_client.get("/api/dashboard/stats?days=30").get_json()
    assert loaded["kpis"]["total_events"] > 0
    assert loaded["kpis"]["detected_vulnerabilities"] > 0
    assert loaded["kpis"]["phishing_attempts"] >= 1
    assert loaded["has_demo_data"] is True

    # Clear demo dataset
    clear_resp = auth_client.post("/dashboard/clear-demo", follow_redirects=True)
    assert clear_resp.status_code == 200
    with app.app_context():
        assert SecurityAlert.query.filter_by(is_demo=True).count() == 0


def test_settings_thresholds_and_password_update(auth_client, app, admin_user):
    resp = auth_client.post(
        "/settings/thresholds",
        data={"brute_force_threshold": "7", "brute_force_window_minutes": "15"},
        follow_redirects=True,
    )
    assert resp.status_code == 200

    with app.app_context():
        u = User.query.filter_by(username="soc_admin").first()
        assert u.brute_force_threshold == 7
        assert u.brute_force_window_minutes == 15

    pwd_resp = auth_client.post(
        "/settings/password",
        data={
            "current_password": "AdminPass123",
            "new_password": "UpdatedPass456",
            "confirm_password": "UpdatedPass456",
        },
        follow_redirects=True,
    )
    assert pwd_resp.status_code == 200
    with app.app_context():
        u = User.query.filter_by(username="soc_admin").first()
        assert u.check_password("UpdatedPass456") is True


def test_custom_404_page(auth_client):
    resp = auth_client.get("/nonexistent-nexora-route")
    assert resp.status_code == 404
    assert b"404" in resp.data
