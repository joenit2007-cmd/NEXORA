"""Log Analyzer unit and endpoint tests."""

import io
from app.models import LogAnalysis, SecurityAlert
from app.services.log_analyzer import analyze_log_content


def test_brute_force_and_failed_login_detection():
    sample_log = "\n".join(
        [
            "2026-11-20 03:00:01 host sshd[100]: Failed password for root from 203.0.113.50 port 50001 ssh2",
            "2026-11-20 03:00:15 host sshd[101]: Failed password for root from 203.0.113.50 port 50002 ssh2",
            "2026-11-20 03:00:30 host sshd[102]: Failed password for invalid user admin from 203.0.113.50 port 50003 ssh2",
            "2026-11-20 03:00:45 host sshd[103]: Failed password for root from 203.0.113.50 port 50004 ssh2",
            "2026-11-20 03:01:00 host sshd[104]: Failed password for root from 203.0.113.50 port 50005 ssh2",
            "2026-11-20 03:02:00 host sshd[105]: Accepted publickey for devops from 192.168.1.10 port 51000 ssh2",
        ]
    ).encode("utf-8")

    result = analyze_log_content(sample_log, "auth.log", brute_force_threshold=5, window_minutes=10)
    assert result["summary"]["failed_logins"] == 5
    assert result["summary"]["brute_force_count"] == 1
    assert any(ip["ip"] == "203.0.113.50" and ip["classification"] == "Brute-Force Source" for ip in result["suspicious_ips"])
    assert any(a["category"] == "Brute-Force Attack" for a in result["alerts"])


def test_valid_log_and_csv_uploads_and_export(auth_client, app):
    csv_data = (
        "timestamp,source_ip,username,event_type,severity,message\n"
        "2026-11-20 10:00:00,198.51.100.10,admin,Failed Login,Medium,Invalid password\n"
        "2026-11-20 10:00:10,198.51.100.10,admin,Failed Login,Medium,Invalid password\n"
        "2026-11-20 10:00:20,198.51.100.10,admin,Failed Login,Medium,Invalid password\n"
        "2026-11-20 10:00:30,203.0.113.7,web,HTTP Request,High,GET /?q=<script>alert(1)</script>\n"
    ).encode("utf-8")

    resp = auth_client.post(
        "/logs/upload",
        data={
            "log_file": (io.BytesIO(csv_data), "events.csv"),
            "brute_force_threshold": "3",
            "window_minutes": "5",
        },
        content_type="multipart/form-data",
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"events.csv" in resp.data

    with app.app_context():
        job = LogAnalysis.query.filter_by(original_filename="events.csv").first()
        assert job is not None
        assert job.failed_logins == 3
        assert job.brute_force_count == 1
        assert SecurityAlert.query.count() >= 1
        job_id = job.id

    csv_resp = auth_client.get(f"/logs/{job_id}/export")
    assert csv_resp.status_code == 200
    assert "text/csv" in csv_resp.content_type
    assert b"Timestamp,IP Address,Username" in csv_resp.data


def test_invalid_and_empty_uploads_rejected(auth_client):
    # Unsupported extension
    bad_ext = auth_client.post(
        "/logs/upload",
        data={"log_file": (io.BytesIO(b"print('hi')"), "script.py")},
        content_type="multipart/form-data",
    )
    assert bad_ext.status_code == 400

    # Empty file
    empty = auth_client.post(
        "/logs/upload",
        data={"log_file": (io.BytesIO(b"   \n "), "empty.log")},
        content_type="multipart/form-data",
    )
    assert empty.status_code == 400

    # Binary executable disguised as .log
    binary = auth_client.post(
        "/logs/upload",
        data={"log_file": (io.BytesIO(b"MZ\x90\x00\x03\x00fakepe"), "malware.log")},
        content_type="multipart/form-data",
    )
    assert binary.status_code == 400


def test_malformed_log_handled_gracefully():
    malformed = b"%%%not a standard log line\n\xff\xfegarbage binary-ish utf8\nrandom text without date"
    result = analyze_log_content(malformed, "weird.txt")
    assert result["summary"]["total_lines"] == 3
    assert isinstance(result["events"], list)
