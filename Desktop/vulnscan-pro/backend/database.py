"""SQLAlchemy instance and initialisation helper."""

import logging
import os

from flask import Flask
from flask_sqlalchemy import SQLAlchemy

logger = logging.getLogger(__name__)

db = SQLAlchemy()


def init_db(app: Flask) -> None:
    """Bind SQLAlchemy to *app* and create all tables."""
    db.init_app(app)
    with app.app_context():
        import models  # noqa: F401 – registers models with SQLAlchemy
        db.create_all()
        os.makedirs(app.config.get("REPORTS_DIR", "reports"), exist_ok=True)
        logger.info("Database ready: %s", app.config["SQLALCHEMY_DATABASE_URI"])
