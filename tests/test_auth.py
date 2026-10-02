"""Tests du parcours d'authentification standard (happy path + erreurs de base)."""
from tests.conftest import VALID_PASSWORD, register_and_login


def test_register_creates_user(client):
    resp = client.post(
        "/auth/register",
        json={"username": "bob", "email": "bob@example.com", "password": VALID_PASSWORD},
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["username"] == "bob"
    assert "password" not in body
    assert "hashed_password" not in body


def test_register_duplicate_username_rejected(client):
    client.post(
        "/auth/register",
        json={"username": "bob", "email": "bob@example.com", "password": VALID_PASSWORD},
    )
    resp = client.post(
        "/auth/register",
        json={"username": "bob", "email": "different@example.com", "password": VALID_PASSWORD},
    )
    assert resp.status_code == 409


def test_login_with_correct_credentials_returns_tokens(client):
    tokens = register_and_login(client, "carol")
    assert "access_token" in tokens
    assert "refresh_token" in tokens


def test_login_with_wrong_password_rejected(client):
    client.post(
        "/auth/register",
        json={"username": "dave", "email": "dave@example.com", "password": VALID_PASSWORD},
    )
    resp = client.post("/auth/login", json={"username": "dave", "password": "WrongPassword1"})
    assert resp.status_code == 401


def test_protected_route_requires_token(client):
    resp = client.get("/notes")
    assert resp.status_code in (401, 403)


def test_protected_route_works_with_valid_token(client):
    tokens = register_and_login(client, "erin")
    resp = client.get("/notes", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert resp.status_code == 200
    assert resp.json() == []


def test_refresh_token_rotation(client):
    tokens = register_and_login(client, "frank")
    old_refresh = tokens["refresh_token"]

    resp = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert resp.status_code == 200
    new_tokens = resp.json()
    assert new_tokens["refresh_token"] != old_refresh

    # Le vieux refresh token, une fois utilisé, doit être révoqué (rotation).
    replay = client.post("/auth/refresh", json={"refresh_token": old_refresh})
    assert replay.status_code == 401


def test_logout_revokes_refresh_token(client):
    tokens = register_and_login(client, "grace")
    client.post("/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    resp = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert resp.status_code == 401
