"""Production WSGI entry point for Gunicorn / Render / Docker."""

import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "production"))
