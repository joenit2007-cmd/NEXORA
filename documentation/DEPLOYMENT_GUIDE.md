# NEXORA Deployment Guide

This guide covers deploying **NEXORA — Cybersecurity Threat Monitoring & Vulnerability Assessment Platform** locally, in Docker, and on cloud platforms such as Render.

## 1. Environment Variables

Create a `.env` file (never commit `.env` to version control) based on `.env.example`:

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `FLASK_ENV` | Yes (prod) | `development` | Set to `production` for live deployments |
| `SECRET_KEY` | Yes (prod) | Random per start | Long cryptographically random hex string (`python -c "import secrets; print(secrets.token_hex(32))"`) |
| `DATABASE_URL` | Recommended | `sqlite:///instance/nexora.db` | SQLite path or PostgreSQL URI (`postgresql://...`) |
| `SESSION_COOKIE_SECURE` | Yes (HTTPS) | `false` (`true` in prod) | Enforce HTTPS-only session cookies |
| `WTF_CSRF_ENABLED` | Yes | `true` | Keep enabled in all non-test environments |
| `MAX_CONTENT_LENGTH` | Optional | `5242880` | Max upload size in bytes (5 MB) |
| `NMAP_PATH` | Optional | Auto-detected | Explicit path to `nmap` binary if outside `PATH` |

## 2. Production WSGI Entry Point

NEXORA exposes a standard WSGI object at `wsgi:app`:

```bash
gunicorn --bind 0.0.0.0:8000 --workers 2 --threads 4 --timeout 120 wsgi:app
```

> **Note:** Gunicorn runs on Linux/macOS/Docker. On Windows local development, start with `python run.py`.

## 3. Docker Deployment

Build and run the container locally:

```bash
docker build -t nexora:latest .
docker run -d \
  --name nexora \
  -p 8000:8000 \
  -e FLASK_ENV=production \
  -e SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  -e SESSION_COOKIE_SECURE=false \
  -v nexora_instance:/app/instance \
  -v nexora_reports:/app/reports \
  nexora:latest
```

Verify container health:

```bash
curl http://127.0.0.1:8000/health
```

## 4. Render Deployment (Blueprint)

A ready-to-use `render.yaml` blueprint is included at the repository root:

1. Push the approved repository to GitHub.
2. In the Render dashboard, select **New → Blueprint** and connect the repository.
3. Render reads `render.yaml`, builds the `Dockerfile` (which includes Nmap), generates a secure `SECRET_KEY`, attaches a persistent `/var/data` disk for SQLite storage, and monitors `/health`.
4. After deployment, register the first account via `/register` — it automatically receives the `admin` role.

## 5. Persistent Storage & Production Considerations

- **SQLite Persistence:** Cloud containers use ephemeral filesystems by default. Mount a persistent disk (`/var/data` on Render or Docker volumes) or set `DATABASE_URL` to a managed PostgreSQL database.
- **Network Scan Scope in Cloud Containers:** NEXORA strictly restricts scanning to `localhost` (`127.0.0.1`, `::1`) and private RFC1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`). On hosted cloud environments, users should target `127.0.0.1` or an authorized private VPC lab host.
- **HTTPS & HSTS:** Serve NEXORA behind TLS termination (Render provides managed HTTPS automatically). When `FLASK_ENV=production`, `Strict-Transport-Security` and `Secure` cookies are enforced.
