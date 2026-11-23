# NEXORA

**Cybersecurity Threat Monitoring & Vulnerability Assessment Platform**  
*DETECT. ANALYZE. SECURE.*

---

## 1. Project Overview

**NEXORA** is an integrated defensive and authorized offensive cybersecurity web platform designed for Security Operations Center (SOC) monitoring, log analysis, local network visibility, authorized vulnerability assessment, phishing email detection, centralized incident alert management, and executive PDF/CSV reporting.

Built with **Python 3.13**, **Flask 3.x**, **SQLAlchemy**, **Pandas**, **Scikit-learn**, **ReportLab**, **psutil**, and **Nmap**, NEXORA delivers genuine security workflows backed by a relational SQLite database and an enterprise dark-mode SOC interface—with zero hardcoded fake dashboard statistics, zero fabricated CVEs, and strict authorized-target guardrails.

---

## 2. Core Objectives

1. Provide a unified, original cybersecurity monitoring and assessment platform suitable for capstone evaluation and portfolio deployment.
2. Demonstrate practical defensive engineering (log intelligence, brute-force detection, phishing classification, alert triage, defensive web headers, CSRF/RBAC) alongside safe, authorized offensive assessment (localhost/RFC1918 Nmap port & service enumeration, evidence-based misconfiguration checks).
3. Enforce strict ethical and technical safety boundaries (passive file parsing, zero automatic URL fetching, server-side target allowlisting, explicit authorization confirmation).
4. Deliver complete security architecture, automated Pytest verification, technical documentation, and production deployment readiness.

---

## 3. Implemented Features

- **Dynamic Security Dashboard**: Live KPI metrics (events, Critical/High/Medium/Low alerts, failed logins, suspicious IPs, vulnerabilities, phishing attempts, network scans), interactive Chart.js activity timeline and severity distribution, date-range filtering (`24h`, `7d`, `30d`, `All`, custom date range), and one-click `[DEMO]` sample data loader/clearer.
- **Intelligent Log Analyzer**: Passive read-only ingestion of `.log`, `.txt`, and `.csv` files (5 MB limit, binary/executable rejection). Detects failed logins, sliding-window brute-force attacks, password spraying, suspicious privilege escalation (`sudo`), web attack probes (SQLi/XSS/path traversal), suspicious IP aggregation, configurable detection thresholds, analysis history, and CSV export.
- **Network Monitor & Nmap Integration**: Displays local hostname, primary IP, network interfaces, listening services, and active connections via `psutil`. Auto-detects Nmap (`-sT`, `-sV`, safe XML parsing) with an automatic safe Python TCP socket fallback when Nmap is absent. Enforces localhost/RFC1918 private lab target validation and explicit user confirmation.
- **Vulnerability Assessment Engine**: Performs safe port and service enumeration plus live non-intrusive HTTP security header checks (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, server version disclosure) and transparent risky-service evaluation (Telnet, FTP, SMB, RDP/VNC, exposed databases, SSH hardening). Never fabricates CVEs or flags an open port as vulnerable without evidence.
- **Phishing Email Analyzer**: Static hybrid **Scikit-learn TF-IDF + Logistic Regression** classifier trained reproducibly on `sample_data/phishing_dataset.csv` combined with transparent rule-based heuristics (urgency, credential lures, brand impersonation, sender anomalies, raw IP URLs, `@`/punycode/shortener obfuscation, macro/executable attachment cues). Never visits or fetches submitted URLs.
- **Centralized Security Alerts**: Automatic alert generation with unique `NEX-YYYYMMDD-XXXXXX` IDs, severity classification, `Open → Reviewed → Resolved` triage lifecycle persisted in SQLite, multi-facet filtering, search, and CSV export.
- **PDF & CSV Reporting**: Branded ReportLab PDF and structured CSV generation across 5 scopes (`overall_summary`, `log_analysis`, `network_assessment`, `vulnerability_assessment`, `phishing_analysis`), populated strictly from live database records.
- **Unified Scan History & Settings**: Chronological activity audit log across all modules, customizable brute-force thresholds, secure password updates, environment diagnostics, and Admin-only Role-Based Access Control (RBAC).

---

## 4. Technology Stack

| Layer | Technologies |
| --- | --- |
| **Backend** | Python 3.13, Flask 3.1, Flask-SQLAlchemy, Flask-Login, Flask-WTF, Werkzeug |
| **Database** | SQLite, SQLAlchemy 2.x ORM |
| **Cybersecurity & ML** | Nmap (subprocess XML), `psutil`, `socket`, Pandas, Scikit-learn (TF-IDF + Logistic Regression) |
| **Frontend** | HTML5, CSS3 (Custom SOC Dark Theme), JavaScript, Bootstrap 5.3, Bootstrap Icons, Chart.js 4.4 |
| **Reporting** | ReportLab (PDF), Python `csv` module |
| **Testing & Deployment** | Pytest 9.x, Flask Test Client, Gunicorn, Docker, Render Blueprint (`render.yaml`) |

---

## 5. Project Structure

```text
NEXORA/
├── app/
│   ├── __init__.py          # Flask application factory, error handlers, security headers, CLI
│   ├── config.py            # Environment-driven configuration (dev/test/prod)
│   ├── extensions.py        # SQLAlchemy, Flask-Login, CSRFProtect instances
│   ├── models/              # SQLAlchemy ORM models (Users, Events, Logs, Scans, Vulns, Phishing, Alerts, Reports)
│   ├── routes/              # 11 Flask blueprints powering all 12 SOC pages & APIs
│   ├── security/            # Target allowlist validators, RBAC decorators, HTTP security headers
│   ├── services/            # Log analyzer, network monitor, vuln assessor, ML phishing detector, reports, demo seeder
│   ├── utils/               # Sanitization, formatting, severity helpers
│   ├── static/              # Custom SOC dark CSS, Chart.js scripts, SVG logo
│   └── templates/           # Responsive Jinja2 SOC templates + custom error pages
├── sample_data/             # Bundled sample logs (.log/.csv/.txt) & labeled phishing ML dataset
├── tests/                   # Comprehensive 32-test Pytest unit & integration suite
├── documentation/           # Production deployment guide
├── migrations/              # Standalone database schema initialization utility
├── instance/                # Local runtime SQLite DB & uploads (excluded via .gitignore)
├── reports/                 # Generated PDF/CSV reports (excluded via .gitignore)
├── .env.example             # Environment variable template (no real secrets)
├── .gitignore               # Exclusion rules for venv, DB, caches, secrets, reports, videos
├── Dockerfile               # Production container image (Python 3.13 + Nmap + Gunicorn)
├── render.yaml              # Render deployment blueprint
├── requirements.txt         # Python dependencies
├── run.py                   # Local development server entry point
├── wsgi.py                  # Production WSGI entry point
├── SECURITY_ARCHITECTURE.md # Architecture diagrams, controls, ER schema, STRIDE threat model
├── TESTING_REPORT.md        # Automated & live verification report
├── PROJECT_REPORT.md        # Complete capstone project report
└── LICENSE                  # MIT License
```

---

## 6. Installation & Configuration

### Prerequisites
- Python 3.13+ (or Python 3.11+)
- Optional (recommended): [Nmap](https://nmap.org/download.html) installed on your system (NEXORA automatically falls back to its built-in Python TCP socket scanner if Nmap is unavailable).

### Setup Steps

```bash
# 1. Navigate to the project directory
cd NEXORA

# 2. Create and activate a virtual environment
python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables
cp .env.example .env
# Edit .env and set a strong SECRET_KEY for production
```

---

## 7. Startup Instructions

### Local Development
```bash
python run.py
```
Open your browser at `http://127.0.0.1:5000`.

### Production WSGI (Linux / Docker)
```bash
gunicorn --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 120 wsgi:app
```

Health check endpoint: `GET /health`

---

## 8. Usage Walkthrough

1. **Create Account**: Navigate to `/register`. The first registered account automatically receives the `admin` role; subsequent accounts receive `analyst`.
2. **Optional Demo Data**: On `/dashboard`, click **Load Demo Dataset** to execute NEXORA's actual engines against bundled sample data (records are tagged `[DEMO]` and removable via **Clear Demo**).
3. **Log Analyzer (`/logs`)**: Upload a `.log`, `.txt`, or `.csv` file (or run a bundled sample in one click) and adjust brute-force thresholds.
4. **Network Monitor (`/network`)**: Inspect local interfaces/sockets and launch an authorized Nmap scan against `127.0.0.1` or an authorized RFC1918 private lab host after checking the authorization confirmation box.
5. **Vulnerability Assessment (`/vulnerabilities`)**: Run non-destructive service and HTTP header checks against an authorized target and inspect structured findings with evidence and remediation.
6. **Phishing Analyzer (`/phishing`)**: Paste email headers/body/URLs (or click a sample preset) to review ML + rule risk scores and triggered indicators.
7. **Security Alerts (`/alerts`)**: Filter, search, review, resolve, and export centralized alerts.
8. **Reports (`/reports`)**: Generate and download branded PDF or CSV reports from live telemetry.

---

## 9. Running Tests

```bash
pytest -v
```

See [TESTING_REPORT.md](TESTING_REPORT.md) for full test cases, execution output, bug tracking, and verification details.

---

## 10. Demo Video

A full local demonstration walkthrough of NEXORA has been recorded and will be linked here once published:

- **Demo Video Link:** _[Add published demonstration video URL here — e.g., YouTube / Loom / Google Drive link]_

---

## 11. Documentation Index

- [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) — System architecture, data flows, ER schema, threat model, and defensive controls.
- [TESTING_REPORT.md](TESTING_REPORT.md) — Automated and live verification results, identified bugs, and fixes.
- [PROJECT_REPORT.md](PROJECT_REPORT.md) — Complete academic/capstone project report.
- [documentation/DEPLOYMENT_GUIDE.md](documentation/DEPLOYMENT_GUIDE.md) — Docker, Gunicorn, and Render deployment guide.

---

## 12. Known Limitations & Future Enhancements

### Current Limitations
- Network scans are intentionally restricted to single `localhost` or RFC1918 private lab hosts (max 100 ports per scan) to uphold ethical and legal safety boundaries.
- The bundled ML phishing dataset contains 120 curated labeled messages for deterministic local training; production accuracy benefits from continuously updated enterprise email corpora.
- OS-level process names for system sockets on Windows/Linux may show `Restricted` when running without elevated privileges.

### Future Enhancements
- Real-time syslog/SIEM streaming ingestion over TLS and scheduled background log polling.
- PostgreSQL high-availability clustering with Alembic schema migrations.
- Multi-factor authentication (TOTP) and OIDC/SAML enterprise single sign-on.
- Expanded passive CVE enrichment via official offline NVD feeds (with exact CPE matching rather than port assumptions).
