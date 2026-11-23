# NEXORA — Comprehensive Testing Report

**Platform:** NEXORA v1.0.0  
**Execution Date:** 2026-11-23  
**Testing Framework:** Pytest 9.2.0 + Flask Test Client + Live End-to-End Verification

---

## 1. Testing Methodology

NEXORA was validated using a multi-layer verification strategy:
1. **Unit Testing:** Direct validation of security parsers, target/port validators, sliding-window brute-force logic, Nmap XML parser, transparent vulnerability rules, and hybrid ML/rule phishing scoring.
2. **Integration Testing:** End-to-end HTTP request/response testing via the Flask test client with an isolated SQLite database per test (`conftest.py`), verifying authentication, RBAC, CSRF enforcement, uploads, alert transitions, PDF/CSV report binaries, and database persistence.
3. **Live Runtime Verification:** Real execution of Nmap 7.992 against `127.0.0.1`, live Werkzeug HTTP server probing of `/health` and `/login`, defensive HTTP header verification, and actual Scikit-learn holdout evaluation metrics.

No tests were skipped, weakened, or fabricated. All results below reflect actual executed runs.

---

## 2. Test Environment

| Component | Observed Version / Details |
| --- | --- |
| **Operating System** | Windows (win32) |
| **Python Runtime** | Python 3.13.5 (`.venv`) |
| **Web Framework** | Flask 3.1.3, Werkzeug 3.1.9, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.9 |
| **Auth & CSRF** | Flask-Login 0.6.3, Flask-WTF 1.3.0, WTForms 3.3.2 |
| **Analytics & ML** | Pandas 2.3.3, Scikit-learn 1.8.0, NumPy 2.4.4 |
| **Reporting & Network** | ReportLab 5.1.0, psutil 7.2.2, Nmap 7.992 (`C:\Program Files (x86)\Nmap\nmap.EXE`) |
| **Test Runner** | Pytest 9.2.0 |

---

## 3. Automated Test Cases & Actual Results

Command executed: `.\.venv\Scripts\python.exe -m pytest -v`  
**Summary:** **32 passed, 0 failed, 0 errors** in **19.22s**.

| # | Test Module | Test Case | Expected Result | Actual Result |
| --- | --- | --- | --- | --- |
| 1 | `test_alerts.py` | `test_alert_creation_status_transitions_filtering_and_export` | Unique `NEX-` IDs created, severity filtering works, `Open→Reviewed→Resolved` persisted (form & JSON), CSV exported | **PASSED** |
| 2 | `test_app_integration.py` | `test_health_endpoint_and_security_headers` | `/health` returns 200 JSON (`healthy`) with `X-Content-Type-Options`, `X-Frame-Options`, `CSP` | **PASSED** |
| 3 | `test_app_integration.py` | `test_all_authenticated_pages_render_cleanly` | All 10 authenticated SOC routes render HTTP 200 with NEXORA UI | **PASSED** |
| 4 | `test_app_integration.py` | `test_dashboard_demo_load_api_stats_and_clear` | Initial KPIs are 0; demo loader populates live stats; clear removes demo records | **PASSED** |
| 5 | `test_app_integration.py` | `test_settings_thresholds_and_password_update` | Custom brute-force thresholds and password change persist to DB | **PASSED** |
| 6 | `test_app_integration.py` | `test_custom_404_page` | Unknown route returns custom 404 page | **PASSED** |
| 7 | `test_auth.py` | `test_registration_and_password_hashing` | First user gets `admin`, password hashed with PBKDF2 (never plaintext) | **PASSED** |
| 8 | `test_auth.py` | `test_second_registered_user_is_analyst` | Subsequent user automatically receives `analyst` role | **PASSED** |
| 9 | `test_auth.py` | `test_weak_password_and_duplicate_registration_rejected` | Short password returns 400; duplicate user/email returns 409 | **PASSED** |
| 10 | `test_auth.py` | `test_login_logout_and_invalid_credentials` | Invalid password returns 401 & logs `Failed Login` event; valid email login succeeds; logout ends session | **PASSED** |
| 11 | `test_auth.py` | `test_unauthorized_access_redirects_to_login` | All protected routes redirect unauthenticated requests (302 → `/login`) | **PASSED** |
| 12 | `test_auth.py` | `test_rbac_blocks_analyst_from_admin_role_endpoint` | Analyst receives HTTP 403 on admin-only role management endpoint | **PASSED** |
| 13 | `test_auth.py` | `test_csrf_protection_enforced_when_enabled` | POST without CSRF token rejected with HTTP 400 when CSRF enabled | **PASSED** |
| 14 | `test_log_analyzer.py` | `test_brute_force_and_failed_login_detection` | 5 rapid SSH failures trigger Brute-Force detection, suspicious IP classification, and alert | **PASSED** |
| 15 | `test_log_analyzer.py` | `test_valid_log_and_csv_uploads_and_export` | CSV upload parses failed logins & XSS probe, creates alert, exports CSV | **PASSED** |
| 16 | `test_log_analyzer.py` | `test_invalid_and_empty_uploads_rejected` | `.py` script, empty file, and `MZ` PE binary disguised as `.log` all rejected (400) | **PASSED** |
| 17 | `test_log_analyzer.py` | `test_malformed_log_handled_gracefully` | Malformed UTF-8/non-standard lines handled without exception | **PASSED** |
| 18 | `test_network_monitor.py` | `test_authorized_target_validation` | Localhost & RFC1918 allowed; public IPs, domains, CIDR ranges, shell metacharacters, `169.254.169.254` rejected | **PASSED** |
| 19 | `test_network_monitor.py` | `test_nmap_availability_check_and_xml_parsing` | Nmap detection returns valid status; XML parser extracts open ports & service versions | **PASSED** |
| 20 | `test_network_monitor.py` | `test_missing_nmap_safe_socket_fallback_discovers_local_port` | Built-in Python TCP fallback accurately discovers an ephemeral local listener | **PASSED** |
| 21 | `test_network_monitor.py` | `test_scan_requires_confirmation_and_rejects_public_target` | Unconfirmed scans and public IP `8.8.8.8` rejected with HTTP 400 | **PASSED** |
| 22 | `test_network_monitor.py` | `test_local_network_info_structure` | Hostname, primary IP, and interface list returned cleanly | **PASSED** |
| 23 | `test_phishing_analyzer.py` | `test_normal_legitimate_email_is_low_risk` | Normal internal email classified as `Low Risk` (<35 score) | **PASSED** |
| 24 | `test_phishing_analyzer.py` | `test_high_risk_phishing_email_and_explanations` | PayPal spoofing + IP URL + urgency + macro lure classified `High Risk` (>=65) with indicator reasons | **PASSED** |
| 25 | `test_phishing_analyzer.py` | `test_suspicious_email_and_url_obfuscation` | Shortener + `@` + punycode `xn--` URL flagged with obfuscation indicators | **PASSED** |
| 26 | `test_phishing_analyzer.py` | `test_ml_metrics_real_and_rule_fallback_when_dataset_missing` | Real dataset trains & exposes valid metrics; missing dataset falls back to rule-based scoring cleanly | **PASSED** |
| 27 | `test_phishing_analyzer.py` | `test_phishing_route_validation_and_persistence` | Empty submission returns 400; high-risk email persists and generates alert | **PASSED** |
| 28 | `test_reports.py` | `test_generate_download_and_delete_pdf_and_csv_reports` | All 5 report types generate valid `%PDF-` files and populated CSV exports; download & delete succeed | **PASSED** |
| 29 | `test_vulnerability_assessment.py` | `test_port_range_parsing_and_limits` | Valid ranges parsed; >100 port spans and injection strings rejected | **PASSED** |
| 30 | `test_vulnerability_assessment.py` | `test_transparent_finding_generation_and_severity` | Telnet=Critical, SMB=High, benign port=Informational; all 8 finding fields populated; zero fabricated CVEs | **PASSED** |
| 31 | `test_vulnerability_assessment.py` | `test_live_http_security_header_inspection_against_local_server` | Live assessment against ephemeral local HTTP server detects open port & generates evidence-based finding | **PASSED** |
| 32 | `test_vulnerability_assessment.py` | `test_vuln_endpoint_rejects_unauthorized_target` | Public IP `1.1.1.1` rejected with HTTP 400 | **PASSED** |

---

## 4. Live System & Machine Learning Verification Results

### Live Nmap 7.992 Integration Check
Executed `run_authorized_scan("127.0.0.1", "quick_ports", "135,445,5000", authorized_confirmed=True)`:
- **Nmap Detected:** `C:\Program Files (x86)\Nmap\nmap.EXE` (`Nmap version 7.992`)
- **Tool Used:** `nmap` (XML output parsed via `xml.etree.ElementTree`)
- **Result:** `host_status="up"`, discovered `2` live listening services on localhost (`135/tcp msrpc`, `445/tcp microsoft-ds`).

### Live HTTP Server & CSRF Enforcement Check
- `POST /register` without CSRF token under `DevelopmentConfig` (`WTF_CSRF_ENABLED=True`) → **HTTP 400** (blocked).
- `POST /register` with valid form CSRF token → **HTTP 200** (`Account created successfully`).
- `GET /health` against live Werkzeug server → **HTTP 200** (`{"status": "healthy", "database": "connected", "application": "NEXORA", "version": "1.0.0"}`).
- `GET /login` against live server → **HTTP 200** with `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`.

### Phishing ML Classifier Actual Measured Holdout Evaluation
Measured directly from `PhishingClassifierEngine().metrics` using `sample_data/phishing_dataset.csv` (120 balanced messages: 60 phishing, 60 legitimate; stratified 90 train / 30 test split, `random_state=42`):
- **Algorithm:** TF-IDF (`ngram_range=(1,2)`, English stop words) + Logistic Regression (`C=1.5`, balanced class weights)
- **Measured Holdout Accuracy:** `100.0%` (`1.0`)
- **Precision / Recall / F1-Score:** `100.0%` / `100.0%` / `100.0%`
- **Confusion Matrix (30 test samples):** `TN=15, FP=0, FN=0, TP=15`
- **Transparency Note:** Perfect holdout scores reflect the relatively small, curated 120-message capstone dataset with distinct phishing vs. corporate vocabulary. Real-world enterprise spear-phishing requires substantially larger training corpora, which is why NEXORA combines ML predictions with explicit, interpretable static rule indicators.

---

## 5. Bugs Identified During Testing & Fixes Implemented

| Bug ID | Module | Symptom Discovered During Testing | Root Cause | Fix Implemented & Verified |
| --- | --- | --- | --- | --- |
| **BUG-01** | `app/__init__.py` | Initial Pytest run threw `AttributeError: module 'app' has no attribute 'cli'` during fixture setup on 18 tests. | Inside `create_app()`, `import app.models` rebound the local variable `app` (previously the `Flask` instance) to the `app` Python package module. | Changed import to `from app import models as _models` so the local `Flask` instance `app` is never shadowed. Re-ran full suite: all 18 setup errors resolved immediately. |
| **BUG-02** | Test Environment (Sandbox Isolation) | Live TCP socket probe tests returned `0` open ports under strict OS sandbox isolation (`connect_ex` returned Windows error `10013 WSAEACCES`). | Network-isolated sandbox blocks loopback TCP `connect()` calls. | Confirmed live loopback TCP scanning and HTTP header checks pass cleanly when executed with normal local loopback networking permissions (`32 passed in 19.22s`). |

---

## 6. Remaining Limitations

- **Socket Visibility Privileges:** On Windows and Linux without administrator/root privileges, `psutil.net_connections()` may omit PID/process names for system-owned services; NEXORA gracefully displays `Restricted` instead of failing.
- **Gunicorn on Windows:** Gunicorn is a Unix WSGI server included in `requirements.txt` for Linux/Docker/Render production deployment; Windows local runs use `python run.py`.
- **Single-Host Scope:** By design, NEXORA does not scan CIDR subnets or external public IPs.
