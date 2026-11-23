# NEXORA — Cybersecurity Threat Monitoring & Vulnerability Assessment Platform

## Capstone Project Report

---

## 1. Abstract

Modern organizations face an expanding spectrum of cyber threats ranging from automated credential brute-force attacks and misconfigured network services to sophisticated social engineering and phishing campaigns. Small teams, security learners, and mid-sized IT departments frequently struggle with fragmented tooling where log analysis, port scanning, vulnerability auditing, phishing inspection, and incident reporting exist in disconnected utilities.

**NEXORA** (*DETECT. ANALYZE. SECURE.*) is an original, integrated web-based cybersecurity platform engineered in Python 3.13 and Flask that unifies defensive monitoring and authorized security assessment within a single Security Operations Center (SOC) interface. NEXORA delivers passive multi-format log analysis with sliding-window brute-force detection, live local network telemetry with authorized Nmap integration and safe socket fallback, transparent evidence-based vulnerability assessment without fabricated CVEs, hybrid Machine Learning (TF-IDF + Logistic Regression) and static rule-based phishing email classification, centralized incident alert management, and downloadable ReportLab PDF/CSV executive reports. All functionality is verified by an automated 32-test Pytest suite and live Nmap/HTTP server validation.

---

## 2. Introduction

Effective cybersecurity operations require continuous visibility across logs, host network surfaces, service configurations, and inbound email threats. While enterprise Security Information and Event Management (SIEM) suites and commercial vulnerability scanners provide broad capabilities, they are often complex to deploy and opaque in how risk decisions are computed.

NEXORA was conceived as a practical, transparent, and production-structured cybersecurity platform that demonstrates end-to-end defensive engineering, secure software architecture, ethical authorized testing controls, and clear explainability for every security alert and finding.

---

## 3. Problem Statement

Security analysts and IT administrators in resource-constrained or lab environments face four recurring challenges:
1. **Fragmented Visibility:** Authentication logs, active host connections, open service checks, and phishing triage are scattered across separate CLI tools with no shared incident database.
2. **Opaque Risk Alerts:** Many tools produce noisy alerts or generic port warnings without transparent evidence, reasoning, or prioritized remediation steps.
3. **Unsafe Scanning Practices:** Unrestricted web wrappers around network scanners introduce severe legal, SSRF, and command-injection risks.
4. **Manual Reporting Overhead:** Compiling log anomalies, vulnerability findings, and phishing indicators into stakeholder-ready PDF/CSV reports is slow and error-prone.

---

## 4. Objectives

- Design and build a modular, database-backed SOC web application with role-based authentication and enterprise dark-mode UX.
- Implement an intelligent log analyzer supporting `.log`, `.txt`, and `.csv` telemetry with configurable brute-force detection thresholds.
- Integrate local host network telemetry (`psutil`) and authorized Nmap scanning (with safe fallback) strictly limited to localhost and RFC1918 private lab targets.
- Build an evidence-based vulnerability assessment module with five severity levels and zero fabricated CVEs.
- Develop a static hybrid ML + heuristic phishing detector that explains classifications without ever visiting submitted URLs.
- Centralize alert generation, triage status workflows, and automated PDF/CSV reporting.
- Verify correctness and security controls through comprehensive automated testing and prepare the application for containerized/cloud deployment.

---

## 5. Existing System vs. Proposed System

### Existing System Limitations
- Standalone command-line utilities (`grep`, `nmap`, manual email inspection) lack persistent history, unified alerting, and executive reporting.
- Heavy commercial SIEM/vulnerability stacks require dedicated infrastructure and licensing unsuitable for lightweight teams or academic/internship labs.
- Prototype student projects frequently rely on hardcoded dashboard numbers, insecure `shell=True` command calls, or unverified CVE claims.

### Proposed System (NEXORA)
- **Unified Full-Stack SOC Platform:** 12 functional web views backed by SQLAlchemy ORM persistence.
- **100% Live Computed Telemetry:** Every dashboard KPI, chart, alert, and PDF/CSV report queries real persisted database records (with an explicitly tagged `[DEMO]` sample runner for evaluations).
- **Secure-by-Design Implementation:** Parameterized queries, PBKDF2-SHA256 hashing, CSRF protection, strict CSP/security headers, `shell=False` subprocess execution, RFC1918 target allowlisting, and passive static file/URL analysis.

---

## 6. System Requirements

### Functional Requirements
1. User registration, login, logout, password updates, and `admin`/`analyst` RBAC.
2. Dynamic SOC dashboard with date-range filters and Chart.js visualizations.
3. Passive upload and analysis of `.log`, `.txt`, and `.csv` files with brute-force and suspicious IP detection.
4. Host network interface, active connection, and listening socket telemetry plus authorized Nmap/socket scanning.
5. Non-destructive port/service enumeration and HTTP security header vulnerability assessment.
6. Static phishing email and URL classification with ML metrics and rule explanations.
7. Centralized alert lifecycle management (`Open`, `Reviewed`, `Resolved`), filtering, and CSV export.
8. Downloadable branded PDF and CSV reports across five reporting scopes.

### Non-Functional Requirements
- **Security:** OWASP-aligned input validation, CSRF, XSS/SQLi mitigation, path traversal prevention, and ethical target scope enforcement.
- **Reliability:** Graceful handling of malformed logs, missing Nmap binaries, restricted OS socket permissions, and missing ML datasets.
- **Portability & Deployment:** Cross-platform Python 3.13 support, Gunicorn WSGI compatibility, Dockerfile, and Render Blueprint (`render.yaml`).

---

## 7. Technology Stack

- **Language & Web Framework:** Python 3.13.5, Flask 3.1.3, Werkzeug 3.1.9
- **Persistence & Auth:** SQLite, Flask-SQLAlchemy 3.1.1, SQLAlchemy 2.1.9, Flask-Login 0.6.3, Flask-WTF 1.3.0
- **Security & Analytics:** Nmap 7.992, `psutil` 7.2.2, Pandas 2.3.3, Scikit-learn 1.8.0
- **Frontend UI:** HTML5, CSS3, JavaScript, Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4
- **Reporting & QA:** ReportLab 5.1.0, Pytest 9.2.0, Gunicorn 27.0.1

---

## 8. Methodology & Architecture

Development followed an iterative, test-driven engineering methodology:
1. **Environment & Architecture Setup:** Modular package layout (`app/models`, `app/security`, `app/services`, `app/routes`, `app/templates`, `app/static`).
2. **Database Modeling:** Eight normalized SQLAlchemy models (`User`, `SecurityEvent`, `LogAnalysis`, `NetworkScan`, `VulnerabilityAssessment`, `VulnerabilityFinding`, `PhishingAnalysis`, `SecurityAlert`, `Report`) linked with foreign keys and timestamps.
3. **Engine Implementation:** Independent, unit-testable service modules decoupled from HTTP views.
4. **SOC UI Engineering:** Responsive dark navy/charcoal design with cyan/electric-blue accents, JetBrains Mono telemetry typography, severity badges, and zero decorative dead controls.
5. **Automated & Live Verification:** 32 Pytest unit/integration tests plus live Nmap 7.992, CSRF, and HTTP server smoke testing.

Detailed architectural diagrams and STRIDE threat modeling are documented in [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md).

---

## 9. Implementation Highlights

- **Intelligent Log Analyzer (`app/services/log_analyzer.py`):** Uses regex parsers for SSH/PAM/Windows/syslog plus Pandas DataFrame parsing for CSV logs. Applies a two-pointer chronological sliding window per source IP to detect brute-force bursts exceeding configurable thresholds (`brute_force_threshold` within `window_minutes`) as well as multi-user password spraying, sudo privilege escalation, and web attack probes.
- **Authorized Network Monitor (`app/services/network_monitor.py`):** Enforces `validate_authorized_target()` and mandatory confirmation before invoking Nmap with `shell=False` and XML stdout (`-oX -`). Automatically falls back to a bounded multi-threaded TCP connect + banner probe when Nmap is absent.
- **Evidence-Based Vulnerability Assessor (`app/services/vuln_assessor.py`):** Evaluates confirmed open services for cleartext protocols (Telnet, FTP), sensitive LAN exposures (SMB, RDP/VNC, databases), SSH hardening, and real HTTP response headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, server banners). Benign open ports are reported transparently as `Informational` rather than falsely flagged as vulnerable.
- **Hybrid Phishing Analyzer (`app/services/phishing_detector.py`):** Trains a reproducible Scikit-learn `Pipeline(TfidfVectorizer, LogisticRegression)` on 120 curated labeled messages (`sample_data/phishing_dataset.csv`) and blends ML probabilities with static lexical rules covering urgency, credential lures, sender/brand spoofing, raw IP URLs, `@`/punycode/shortener obfuscation, and hazardous attachment mentions.

---

## 10. Results & Verification

- **Automated Test Suite:** `32 passed, 0 failed` in `19.22s` via Pytest (`tests/`).
- **Live Nmap 7.992 Execution:** Successfully detected Nmap at `C:\Program Files (x86)\Nmap\nmap.EXE` and parsed real XML scan output against `127.0.0.1` (identifying live local ports `135/tcp` and `445/tcp`).
- **Phishing ML Holdout Metrics:** Evaluated on 30 stratified test messages (`random_state=42`): Accuracy `100.0%`, Precision `100.0%`, Recall `100.0%`, F1-Score `100.0%` (`TP=15, TN=15, FP=0, FN=0`), alongside verified rule-only fallback when the dataset is omitted.
- **Report Generation:** Confirmed valid `%PDF-` ReportLab documents and data-populated CSV exports across all 5 report types.
- **Defect Resolution:** Identified and fixed a Flask factory local-variable shadowing bug (`import app.models` → `from app import models as _models`) during initial test execution.

Complete test evidence is documented in [TESTING_REPORT.md](TESTING_REPORT.md).

---

## 11. Limitations

- Scanning is deliberately constrained to single localhost and RFC1918 private lab IP targets (max 100 ports) to prevent misuse and unauthorized external reconnaissance.
- The curated phishing ML dataset (120 messages) is designed for reproducibility and capstone demonstration; production enterprise environments require larger, continuously refreshed email corpora.
- Local process attribution in `psutil.net_connections()` depends on host operating system permissions.

---

## 12. Future Scope

1. Real-time syslog/agent ingestion over mutual TLS with WebSocket dashboard streaming.
2. Offline NVD/CVE database synchronization with strict CPE version matching.
3. Multi-factor authentication (TOTP) and external SIEM webhook/Slack/email alert notifications.
4. Automated scheduled assessments and longitudinal vulnerability trend tracking.

---

## 13. Conclusion

NEXORA successfully fulfills all architectural, functional, defensive, ethical, testing, and documentation requirements of a modern cybersecurity capstone platform. By unifying intelligent log monitoring, authorized network and vulnerability assessment, explainable phishing detection, centralized alert triage, and executive reporting inside a hardened Flask application, NEXORA provides a practical, demo-ready, and deployment-ready cybersecurity solution.

---

## 14. References

1. OWASP Top Ten Web Application Security Risks — https://owasp.org/www-project-top-ten/
2. NIST Special Publication 800-115: Technical Guide to Information Security Testing and Assessment — https://csrc.nist.gov/publications/detail/sp/800-115/final
3. Flask 3.x & Werkzeug Security Documentation — https://flask.palletsprojects.com/
4. Nmap Network Scanning Official Reference Guide — https://nmap.org/book/
5. Scikit-learn Text Feature Extraction & Linear Models Documentation — https://scikit-learn.org/
6. ReportLab User Guide — https://www.reportlab.com/docs/reportlab-userguide.pdf
