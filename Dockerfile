# NEXORA Production Container Image
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    PORT=8000

WORKDIR /app

# Install Nmap and minimal runtime utilities for authorized network assessment
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create non-root runtime user and ensure writable runtime directories
RUN useradd --create-home --shell /bin/bash nexora && \
    mkdir -p /app/instance/uploads /app/reports && \
    chown -R nexora:nexora /app

USER nexora

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT}/health || exit 1

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} --workers 2 --threads 4 --timeout 120 wsgi:app"]
