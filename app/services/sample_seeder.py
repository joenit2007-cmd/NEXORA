"""Clearly marked demonstration sample dataset loader.

Populates realistic demonstration data by running NEXORA's ACTUAL analysis
engines over bundled sample logs, safe lab port configurations, and sample
phishing emails—marking every seeded record with is_demo=True so it is
transparently distinguished from production telemetry.
"""

from __future__ import annotations

from pathlib import Path

from app.extensions import db
from app.models import (
    LogAnalysis,
    NetworkScan,
    PhishingAnalysis,
    SecurityAlert,
    SecurityEvent,
    VulnerabilityAssessment,
    VulnerabilityFinding,
)
from app.services.alert_service import create_alert
from app.services.log_analyzer import analyze_log_content
from app.services.phishing_detector import analyze_phishing_email
from app.services.vuln_assessor import evaluate_discovered_services
from app.utils.helpers import safe_json_dumps


def load_demo_sample_data(user_id: int, sample_dir: Path) -> dict[str, int]:
    """Run actual NEXORA engines on sample data and persist clearly tagged demo records."""
    counts = {"events": 0, "alerts": 0, "scans": 0, "findings": 0, "phishing": 0}

    # 1. Run real Log Analyzer on bundled sample_data/auth_sample.log
    sample_log_path = sample_dir / "auth_sample.log"
    if sample_log_path.is_file():
        raw_bytes = sample_log_path.read_bytes()
        result = analyze_log_content(raw_bytes, sample_log_path.name, brute_force_threshold=5, window_minutes=10)
        log_job = LogAnalysis(
            user_id=user_id,
            original_filename="[DEMO] auth_sample.log",
            stored_filename="demo_auth_sample.log",
            file_size=len(raw_bytes),
            file_format="log",
            total_lines=result["summary"]["total_lines"],
            parsed_events=result["summary"]["parsed_events"],
            failed_logins=result["summary"]["failed_logins"],
            brute_force_count=result["summary"]["brute_force_count"],
            unusual_activity_count=result["summary"]["unusual_activity_count"],
            suspicious_ips_json=safe_json_dumps(result["suspicious_ips"]),
            threshold_config_json=safe_json_dumps(result["threshold_config"]),
            summary_json=safe_json_dumps(result["summary"]),
            status="Completed",
            is_demo=True,
        )
        db.session.add(log_job)
        db.session.flush()

        for ev in result["events"]:
            db.session.add(
                SecurityEvent(
                    user_id=user_id,
                    log_analysis_id=log_job.id,
                    timestamp=ev["timestamp"],
                    source_ip=ev["source_ip"],
                    username=ev["username"],
                    event_type=ev["event_type"],
                    severity=ev["severity"],
                    source_module="Log Analyzer",
                    raw_message=ev["raw_message"],
                    detection_reason=ev["detection_reason"],
                    recommended_action=ev["recommended_action"],
                    is_demo=True,
                )
            )
            counts["events"] += 1

        for alert_payload in result["alerts"]:
            create_alert(
                user_id=user_id,
                title=f"[DEMO] {alert_payload['title']}",
                category=alert_payload["category"],
                severity=alert_payload["severity"],
                source_module="Log Analyzer",
                source_ip=alert_payload["source_ip"],
                target=alert_payload["target"],
                description=alert_payload["description"],
                recommended_action=alert_payload["recommended_action"],
                is_demo=True,
            )
            counts["alerts"] += 1

    # 2. Sample private lab network scan + transparent vulnerability assessment (evaluated by real rules!)
    demo_ports = [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH 8.9 (Demo Lab Profile)", "banner": ""},
        {"port": 23, "protocol": "tcp", "state": "open", "service": "telnet", "version": "Legacy Lab Telnetd (Demo Profile)", "banner": ""},
        {"port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "Lab HTTP Service (Demo Profile)", "banner": ""},
        {"port": 445, "protocol": "tcp", "state": "open", "service": "microsoft-ds", "version": "Samba SMB Service (Demo Profile)", "banner": ""},
        {"port": 3306, "protocol": "tcp", "state": "open", "service": "mysql", "version": "MySQL 8.0 (Demo Profile)", "banner": ""},
    ]
    demo_scan = NetworkScan(
        user_id=user_id,
        target="192.168.56.101",
        scan_type="service_version",
        port_spec="21,22,23,80,443,445,3306,8080",
        tool_used="demo_lab_profile",
        nmap_available=True,
        authorized_confirmed=True,
        host_status="up",
        open_ports_count=len(demo_ports),
        open_ports_json=safe_json_dumps(demo_ports),
        summary="[DEMO] Sample authorized private lab host (192.168.56.101) scan illustrating multi-service exposure.",
        raw_output="[DEMO] Simulated private lab profile for demonstration purposes.",
        status="Completed",
        is_demo=True,
    )
    db.session.add(demo_scan)
    counts["scans"] += 1

    demo_findings = evaluate_discovered_services(
        target="192.168.56.101",
        open_ports=demo_ports,
        perform_http_checks=False,
    )
    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in demo_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    demo_assessment = VulnerabilityAssessment(
        user_id=user_id,
        target="192.168.56.101",
        port_spec="21,22,23,80,443,445,3306,8080",
        tool_used="demo_lab_profile",
        authorized_confirmed=True,
        open_ports_count=len(demo_ports),
        findings_count=len(demo_findings),
        critical_count=sev_counts["Critical"],
        high_count=sev_counts["High"],
        medium_count=sev_counts["Medium"],
        low_count=sev_counts["Low"],
        info_count=sev_counts["Informational"],
        services_json=safe_json_dumps(demo_ports),
        summary=f"[DEMO] Sample private lab assessment of 192.168.56.101 yielded {len(demo_findings)} evidence-based findings.",
        status="Completed",
        is_demo=True,
    )
    db.session.add(demo_assessment)
    db.session.flush()

    for f in demo_findings:
        db.session.add(
            VulnerabilityFinding(
                assessment_id=demo_assessment.id,
                user_id=user_id,
                title=f"[DEMO] {f['title']}",
                affected_host=f["affected_host"],
                port_service=f["port_service"],
                severity=f["severity"],
                description=f["description"],
                evidence=f["evidence"],
                potential_impact=f["potential_impact"],
                recommended_remediation=f["recommended_remediation"],
                is_demo=True,
            )
        )
        counts["findings"] += 1
        if f["severity"] in {"Critical", "High"}:
            create_alert(
                user_id=user_id,
                title=f"[DEMO] {f['title']} on {f['affected_host']}",
                category="Vulnerability Finding",
                severity=f["severity"],
                source_module="Vulnerability Assessment",
                source_ip=f["affected_host"],
                target=f["port_service"],
                description=f["description"],
                recommended_action=f["recommended_remediation"],
                is_demo=True,
            )
            counts["alerts"] += 1

    # 3. Run real Phishing Detector on 3 representative sample emails (High Risk, Suspicious, Low Risk)
    demo_emails = [
        {
            "sender": "security-alert@paypal-verify-account.xyz",
            "subject": "[DEMO] URGENT: Your PayPal account will be closed within 24 hours",
            "content": (
                "Dear customer, we detected an unauthorized login on your PayPal account. "
                "Act immediately and verify your password using http://198.51.100.44/paypal-login/verify "
                "within 24 hours or your account will be suspended immediately. Open the attached invoice.zip and enable macros."
            ),
            "urls": "http://198.51.100.44/paypal-login/verify",
        },
        {
            "sender": "it-support-team@gmail.com",
            "subject": "[DEMO] IT Helpdesk: Mailbox quota exceeded - validate now",
            "content": (
                "Hello, your corporate mailbox quota exceeded 98%. Please click the link below to validate your mailbox "
                "before the end of the day: https://bit.ly/3xMailQuotaCheck"
            ),
            "urls": "https://bit.ly/3xMailQuotaCheck",
        },
        {
            "sender": "notifications@company-engineering.org",
            "subject": "[DEMO] Q4 Sprint Retrospective Notes",
            "content": (
                "Hi team, thanks for joining today's sprint retrospective. The meeting notes and next sprint action items "
                "have been posted to our internal project wiki. Let me know if you have any agenda additions for Monday."
            ),
            "urls": "",
        },
    ]

    for sample in demo_emails:
        ph_res = analyze_phishing_email(
            content=sample["content"],
            sender=sample["sender"],
            subject=sample["subject"],
            extra_urls=sample["urls"],
        )
        if ph_res.get("success"):
            db.session.add(
                PhishingAnalysis(
                    user_id=user_id,
                    sender=ph_res["sender"],
                    subject=ph_res["subject"],
                    urls_json=safe_json_dumps(ph_res["urls"]),
                    content_preview=ph_res["content_preview"],
                    risk_level=ph_res["risk_level"],
                    risk_score=ph_res["risk_score"],
                    detection_method=ph_res["detection_method"],
                    ml_probability=ph_res["ml_probability"],
                    rule_score=ph_res["rule_score"],
                    indicators_json=safe_json_dumps(ph_res["indicators"]),
                    explanation=ph_res["explanation"],
                    recommended_action=ph_res["recommended_action"],
                    is_demo=True,
                )
            )
            counts["phishing"] += 1
            if ph_res["risk_level"] in {"High Risk", "Suspicious"}:
                create_alert(
                    user_id=user_id,
                    title=f"[DEMO] {ph_res['risk_level']} Phishing Email Detected",
                    category="Phishing Attempt",
                    severity="High" if ph_res["risk_level"] == "High Risk" else "Medium",
                    source_module="Phishing Analyzer",
                    target=ph_res["sender"],
                    description=ph_res["explanation"],
                    recommended_action=ph_res["recommended_action"],
                    is_demo=True,
                )
                counts["alerts"] += 1

    db.session.commit()
    return counts


def clear_demo_sample_data(user_id: int) -> int:
    """Remove all records marked is_demo=True for a user."""
    removed = 0
    for model in (SecurityEvent, LogAnalysis, NetworkScan, VulnerabilityFinding, VulnerabilityAssessment, PhishingAnalysis, SecurityAlert):
        deleted = model.query.filter_by(user_id=user_id, is_demo=True).delete()
        removed += deleted
    db.session.commit()
    return removed
