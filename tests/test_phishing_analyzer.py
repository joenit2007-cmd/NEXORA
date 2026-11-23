"""Phishing Analyzer ML + Rule-based tests."""

from pathlib import Path
from app.models import PhishingAnalysis, SecurityAlert
from app.services.phishing_detector import PhishingClassifierEngine, analyze_phishing_email


def test_normal_legitimate_email_is_low_risk():
    res = analyze_phishing_email(
        sender="engineering@company-internal.org",
        subject="Sprint Planning Notes",
        content=(
            "Hi everyone, please review the sprint backlog before Tuesday's meeting. "
            "Notes from yesterday's retrospective are now available on the internal wiki."
        ),
    )
    assert res["success"] is True
    assert res["risk_level"] == "Low Risk"
    assert res["risk_score"] < 35.0
    assert "explanation" in res and res["explanation"]


def test_high_risk_phishing_email_and_explanations():
    res = analyze_phishing_email(
        sender="alerts@paypal-verify-account.xyz",
        subject="URGENT: Account suspended within 24 hours",
        extra_urls="http://198.51.100.55/paypal-login/verify",
        content=(
            "Dear customer, unauthorized login detected on your PayPal account. "
            "Act immediately and verify your password using http://198.51.100.55/paypal-login/verify "
            "within 24 hours or your account will be closed. Open invoice.zip and enable macros."
        ),
    )
    assert res["success"] is True
    assert res["risk_level"] == "High Risk"
    assert res["risk_score"] >= 65.0
    assert len(res["indicators"]) >= 3
    categories = {ind["category"] for ind in res["indicators"]}
    assert "Suspicious URL Pattern" in categories
    assert "Brand Impersonation" in categories


def test_suspicious_email_and_url_obfuscation():
    res = analyze_phishing_email(
        sender="helpdesk-notices@gmail.com",
        subject="IT Helpdesk: Mailbox quota exceeded",
        extra_urls="https://bit.ly/3xQuotaReset, http://secure@xn--paypl-4ve.xyz/login",
        content="Your mailbox quota exceeded 98%. Click the link below to validate your mailbox today.",
    )
    assert res["success"] is True
    assert res["risk_level"] in {"Suspicious", "High Risk"}
    assert any("Obfuscation" in ind["category"] for ind in res["indicators"])


def test_ml_metrics_real_and_rule_fallback_when_dataset_missing(tmp_path):
    # Real bundled dataset trains cleanly and exposes genuine evaluation metrics
    real_engine = PhishingClassifierEngine()
    assert real_engine.model_ready is True
    assert real_engine.metrics["total_samples"] >= 100
    assert 0.0 <= real_engine.metrics["accuracy"] <= 1.0
    assert 0.0 <= real_engine.metrics["f1_score"] <= 1.0

    # Missing dataset falls back gracefully to transparent rule-based scoring
    missing_engine = PhishingClassifierEngine(dataset_path=Path(tmp_path / "nonexistent.csv"))
    assert missing_engine.model_ready is False
    fallback_res = analyze_phishing_email(
        sender="security@paypal-check.xyz",
        subject="Urgent: Account Suspended",
        content="Verify your password immediately at http://203.0.113.10/login within 24 hours.",
        engine=missing_engine,
    )
    assert fallback_res["success"] is True
    assert fallback_res["detection_method"] == "Rule-Based Scoring"
    assert fallback_res["ml_probability"] is None
    assert fallback_res["risk_level"] == "High Risk"


def test_phishing_route_validation_and_persistence(auth_client, app):
    # Empty input rejected
    empty = auth_client.post("/phishing/analyze", data={"sender": "", "subject": "", "content": "", "urls": ""})
    assert empty.status_code == 400

    # High risk email persists record + generates SecurityAlert
    resp = auth_client.post(
        "/phishing/analyze",
        data={
            "sender": "notice@microsoft-security-reset.xyz",
            "subject": "Final Notice: Verify Office 365 Password",
            "urls": "http://198.51.100.20/office-login",
            "content": "Act immediately! Unauthorized login detected. Verify your password within 24 hours.",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    with app.app_context():
        rec = PhishingAnalysis.query.first()
        assert rec is not None
        assert rec.risk_level in {"Suspicious", "High Risk"}
        assert SecurityAlert.query.filter_by(source_module="Phishing Analyzer").count() == 1
