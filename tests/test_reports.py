"""PDF (ReportLab) and CSV report generation tests."""

from app.models import Report
from app.services.report_service import REPORT_TYPES
from app.services.sample_seeder import load_demo_sample_data


def test_generate_download_and_delete_pdf_and_csv_reports(auth_client, app, admin_user):
    # Populate real analyzed sample data so reports contain genuine database telemetry
    with app.app_context():
        load_demo_sample_data(admin_user.id, app.config["SAMPLE_DATA_DIR"])

    for rtype in REPORT_TYPES:
        for fmt in ("pdf", "csv"):
            resp = auth_client.post(
                "/reports/generate",
                data={"report_type": rtype, "report_format": fmt},
                follow_redirects=True,
            )
            assert resp.status_code == 200

    with app.app_context():
        reports = Report.query.all()
        assert len(reports) == len(REPORT_TYPES) * 2
        pdf_report = next(r for r in reports if r.report_format == "pdf" and r.report_type == "overall_summary")
        csv_report = next(r for r in reports if r.report_format == "csv" and r.report_type == "log_analysis")
        pdf_id, csv_id = pdf_report.id, csv_report.id

    # Verify PDF starts with valid %PDF magic bytes
    pdf_dl = auth_client.get(f"/reports/{pdf_id}/download")
    assert pdf_dl.status_code == 200
    assert "application/pdf" in pdf_dl.content_type
    assert pdf_dl.data.startswith(b"%PDF-")
    assert len(pdf_dl.data) > 1500

    # Verify CSV contains real log telemetry
    csv_dl = auth_client.get(f"/reports/{csv_id}/download")
    assert csv_dl.status_code == 200
    assert "text/csv" in csv_dl.content_type
    assert b"Timestamp,Source IP,Username" in csv_dl.data
    assert b"203.0.113.45" in csv_dl.data

    # Delete report
    del_resp = auth_client.post(f"/reports/{pdf_id}/delete", follow_redirects=True)
    assert del_resp.status_code == 200
    with app.app_context():
        assert Report.query.filter_by(id=pdf_id).first() is None
