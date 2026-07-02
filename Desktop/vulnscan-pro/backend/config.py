"""Application configuration loaded from environment variables with secure defaults."""

import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-key-change-in-production")
    DEBUG = False
    TESTING = False

    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL",
        f"sqlite:///{os.path.join(BASE_DIR, 'sentinelscan.db')}",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Scanning
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "30"))   # seconds per HTTP request
    MAX_SCAN_SIZE = int(os.environ.get("MAX_SCAN_SIZE", "1000"))  # MB for repos

    # Rate limiting (simple in-memory; swap for Redis in production)
    RATE_LIMIT_SCANS = int(os.environ.get("RATE_LIMIT_SCANS", "10"))  # per hour per IP

    # External APIs
    NVD_API_KEY = os.environ.get("NVD_API_KEY")
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

    # CORS
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")

    # Reports output directory
    REPORTS_DIR = os.environ.get("REPORTS_DIR", os.path.join(BASE_DIR, "reports"))

    # OSV.dev public vulnerability API
    OSV_API_URL = "https://api.osv.dev/v1"

    # Logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    DEBUG = True


class ProductionConfig(Config):
    pass  # SECRET_KEY must be set via environment variable before starting in production


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"


_env_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
}


def get_config():
    env = os.environ.get("FLASK_ENV", "development")
    return _env_map.get(env, DevelopmentConfig)
