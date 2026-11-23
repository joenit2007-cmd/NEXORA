"""Authentication, password hashing, session protection, and RBAC tests."""

from app.models import SecurityEvent, User


def test_registration_and_password_hashing(client, app):
    resp = client.post(
        "/register",
        data={
            "username": "first_admin",
            "email": "first@nexora.test",
            "password": "StrongPassword123",
            "confirm_password": "StrongPassword123",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"Account created successfully" in resp.data

    with app.app_context():
        user = User.query.filter_by(username="first_admin").first()
        assert user is not None
        assert user.role == "admin"
        assert user.password_hash != "StrongPassword123"
        assert "StrongPassword123" not in user.password_hash
        assert user.check_password("StrongPassword123") is True
        assert user.check_password("WrongPass123") is False


def test_second_registered_user_is_analyst(client, app, admin_user):
    resp = client.post(
        "/register",
        data={
            "username": "new_analyst",
            "email": "new@nexora.test",
            "password": "AnalystPassword9",
            "confirm_password": "AnalystPassword9",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        user = User.query.filter_by(username="new_analyst").first()
        assert user is not None
        assert user.role == "analyst"


def test_weak_password_and_duplicate_registration_rejected(client, admin_user):
    weak = client.post(
        "/register",
        data={
            "username": "weakuser",
            "email": "weak@nexora.test",
            "password": "short",
            "confirm_password": "short",
        },
    )
    assert weak.status_code == 400

    dup = client.post(
        "/register",
        data={
            "username": "soc_admin",
            "email": "admin@nexora.test",
            "password": "ValidPassword123",
            "confirm_password": "ValidPassword123",
        },
    )
    assert dup.status_code == 409


def test_login_logout_and_invalid_credentials(client, app, admin_user):
    # Invalid password returns 401 and logs a Failed Login security event
    bad = client.post(
        "/login",
        data={"username": "soc_admin", "password": "WrongPassword99"},
    )
    assert bad.status_code == 401
    with app.app_context():
        ev = SecurityEvent.query.filter_by(event_type="Failed Login", username="soc_admin").first()
        assert ev is not None

    # Valid login via email succeeds
    ok = client.post(
        "/login",
        data={"username": "admin@nexora.test", "password": "AdminPass123"},
        follow_redirects=True,
    )
    assert ok.status_code == 200
    assert b"Security Operations Dashboard" in ok.data

    # Logout clears session
    out = client.post("/logout", follow_redirects=True)
    assert out.status_code == 200
    assert b"Sign In to SOC" in out.data


def test_unauthorized_access_redirects_to_login(client):
    for route in ["/dashboard", "/logs", "/network", "/vulnerabilities", "/phishing", "/alerts", "/reports", "/history", "/settings", "/about"]:
        resp = client.get(route, follow_redirects=False)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


def test_rbac_blocks_analyst_from_admin_role_endpoint(analyst_client, admin_user):
    resp = analyst_client.post(
        f"/settings/users/{admin_user.id}/role",
        data={"role": "analyst"},
    )
    assert resp.status_code == 403


def test_csrf_protection_enforced_when_enabled():
    from app import create_app

    csrf_app = create_app("development")
    csrf_app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with csrf_app.app_context():
        from app.extensions import db

        db.create_all()
        c = csrf_app.test_client()
        resp = c.post(
            "/register",
            data={
                "username": "csrf_test",
                "email": "csrf@nexora.test",
                "password": "Password123",
                "confirm_password": "Password123",
            },
        )
        assert resp.status_code == 400

