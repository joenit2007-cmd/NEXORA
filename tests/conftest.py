"""Pytest fixtures for NEXORA test suite."""

from __future__ import annotations

import pytest
from app import create_app
from app.extensions import db
from app.models import User


@pytest.fixture()
def app(tmp_path):
    application = create_app("testing")
    application.config.update(
        UPLOAD_FOLDER=tmp_path / "uploads",
        REPORTS_FOLDER=tmp_path / "reports",
    )
    (tmp_path / "uploads").mkdir(parents=True, exist_ok=True)
    (tmp_path / "reports").mkdir(parents=True, exist_ok=True)

    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def admin_user(app):
    user = User(username="soc_admin", email="admin@nexora.test", role="admin")
    user.set_password("AdminPass123")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def analyst_user(app, admin_user):
    user = User(username="soc_analyst", email="analyst@nexora.test", role="analyst")
    user.set_password("AnalystPass123")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture()
def auth_client(client, admin_user):
    resp = client.post(
        "/login",
        data={"username": "soc_admin", "password": "AdminPass123"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    return client


@pytest.fixture()
def analyst_client(app, analyst_user):
    c = app.test_client()
    resp = c.post(
        "/login",
        data={"username": "soc_analyst", "password": "AnalystPass123"},
        follow_redirects=True,
    )
    assert resp.status_code == 200
    return c
