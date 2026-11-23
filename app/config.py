"""NEXORA Application Configuration."""

import os
import secrets
from datetime import timedelta
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class BaseConfig:
    """Shared base configuration for NEXORA."""

    APP_NAME = "NEXORA"
    APP_TAGLINE = "DETECT. ANALYZE. SECURE."
    APP_VERSION = "1.0.0"

    SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

    INSTANCE_DIR = BASE_DIR / "instance"
    UPLOAD_FOLDER = INSTANCE_DIR / "uploads"
    REPORTS_FOLDER = BASE_DIR / "reports"
    SAMPLE_DATA_DIR = BASE_DIR / "sample_data"

    _default_db = f"sqlite:///{(INSTANCE_DIR / 'nexora.db').as_posix()}"
    _env_db = os.environ.get("DATABASE_URL", "")
    if _env_db.startswith("postgres://"):
        _env_db = _env_db.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _env_db or _default_db
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Upload security
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 5 * 1024 * 1024))  # 5 MB
    ALLOWED_LOG_EXTENSIONS = {".log", ".txt", ".csv"}

    # Session & CSRF security
    WTF_CSRF_ENABLED = _as_bool(os.environ.get("WTF_CSRF_ENABLED"), True)
    WTF_CSRF_TIME_LIMIT = 3600
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # Detection defaults
    LOG_BRUTE_FORCE_THRESHOLD = int(os.environ.get("LOG_BRUTE_FORCE_THRESHOLD", 5))
    LOG_BRUTE_FORCE_WINDOW_MINUTES = int(os.environ.get("LOG_BRUTE_FORCE_WINDOW_MINUTES", 10))
    NMAP_PATH = os.environ.get("NMAP_PATH", "").strip()


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    TESTING = False


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    SESSION_COOKIE_SECURE = False
    SECRET_KEY = "nexora-testing-secret-key-not-for-production"


class ProductionConfig(BaseConfig):
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), True)
    REMEMBER_COOKIE_SECURE = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), True)


CONFIG_MAP = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
}
