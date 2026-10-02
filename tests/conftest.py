"""
Fixtures partagées : une base SQLite dédiée aux tests (fichier temporaire,
recréée à chaque run), injectée à la place de la base réelle via override
de dépendance FastAPI.
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

    # Le limiter est un singleton partagé par toute la session de tests
    # (même objet importé par app.main à chaque test). Sans ce reset, un
    # test qui déclenche le rate limit (ex: test_rate_limit.py) laisse les
    # tests suivants bloqués à 429, puisque TestClient utilise toujours la
    # même adresse "testclient" comme clé de limitation.
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
