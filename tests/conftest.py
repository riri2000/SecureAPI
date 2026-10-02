"""Shared fixtures: a dedicated SQLite test database (temp file, recreated
on every run), injected in place of the real one via FastAPI's dependency
override.
"""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.rate_limit import limiter


@pytest.fixture()
def client():
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db

    # The limiter is a singleton shared across the whole test session.
    # Without this reset, a test that trips the rate limit would leave
    # later tests stuck at 429, since TestClient always uses the same
    # "testclient" address as the limiting key.
    limiter.reset()

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()
    os.close(db_fd)
    os.remove(db_path)


VALID_PASSWORD = "Str0ngPassw0rd!"


def register_and_login(client, username="alice"):
    client.post(
        "/auth/register",
        json={"username": username, "email": f"{username}@example.com", "password": VALID_PASSWORD},
    )
    resp = client.post("/auth/login", json={"username": username, "password": VALID_PASSWORD})
    return resp.json()
