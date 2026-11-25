import os
import tempfile

# Must be set before the app is imported.
_tmp = tempfile.mkdtemp(prefix="cyberlabs-test-")
os.environ["DATABASE_PATH"] = os.path.join(_tmp, "test.db")
os.environ["SECRET_KEY"] = "test-secret-key-test-secret-key-test-secret"
os.environ["RATE_LIMIT_ENABLED"] = "false"

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.db import get_db


@pytest.fixture()
def client():
    with TestClient(app) as c:
        with get_db() as db:
            db.execute("DELETE FROM scan_logs")
            db.execute("DELETE FROM users")
        yield c


def make_user(client, name="alice", pw="correct-horse-battery"):
    r = client.post("/api/auth/register", json={"username": name, "password": pw})
    assert r.status_code == 201, r.text
    return r


@pytest.fixture()
def authed(client):
    make_user(client)
    return client


def run(client, tool, **params):
    return client.post(f"/api/tools/{tool}", json={"params": params})
