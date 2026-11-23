"""Standalone database initialization utility for NEXORA."""

from app import create_app
from app.extensions import db


def init_database(config_name: str = "development") -> None:
    app = create_app(config_name)
    with app.app_context():
        db.create_all()
        print("NEXORA SQLite schema initialized successfully.")


if __name__ == "__main__":
    init_database()
