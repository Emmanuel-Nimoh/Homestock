"""Flask application factory for SentinelScan."""

import logging
import logging.handlers
import os

from flask import Flask
from flask_cors import CORS

from config import get_config
from database import init_db
from routes import api


def create_app(config_override=None) -> Flask:
    app = Flask(__name__)

    # Load config
    cfg = config_override or get_config()
    app.config.from_object(cfg)

    # Logging
    _setup_logging(app)

    # CORS
    CORS(app, origins=app.config.get("CORS_ORIGINS", ["*"]))

    # Database
    init_db(app)

    # Register blueprints
    app.register_blueprint(api)

    logger = logging.getLogger(__name__)
    logger.info("SentinelScan started in %s mode", os.environ.get("FLASK_ENV", "development"))

    return app


def _setup_logging(app: Flask) -> None:
    level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"), logging.INFO)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    root.addHandler(ch)

    # Rotating file handler
    log_file = app.config.get("LOG_FILE", "sentinelscan.log")
    try:
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=10 * 1024 * 1024, backupCount=5
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)
    except OSError:
        pass  # can't write log file — console-only is fine
