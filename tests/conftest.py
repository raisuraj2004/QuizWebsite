import os
from pathlib import Path

import pytest


@pytest.fixture()
def app(tmp_path, monkeypatch):
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("FLASK_ENV", "development")
    monkeypatch.setenv("SQLITE_DB_PATH", str(db_path))
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("REDIS_URL", raising=False)

    from app import app as flask_app
    from utils.migrations import run_migrations

    run_migrations()
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


def set_csrf(client, token="test-csrf-token"):
    with client.session_transaction() as sess:
        sess["_csrf_token"] = token
    return token
