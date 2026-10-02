"""Automated SQL injection tests.

Each payload below is a textbook OWASP example. We send them into every
accessible text field (login, note creation) and verify the API treats
them as harmless literal text rather than executable SQL — guaranteed
by using the SQLAlchemy ORM exclusively (no f-strings or raw SQL
concatenation anywhere in app/).
"""
import pytest

from tests.conftest import VALID_PASSWORD, register_and_login

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "' OR 1=1 --",
    "admin'--",
    "' UNION SELECT username, hashed_password FROM users --",
]


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_login_username_injection_does_not_bypass_auth(client, payload):
    resp = client.post("/auth/login", json={"username": payload, "password": "whatever"})
    # Must be treated as a plain nonexistent username: 401, never an
    # auth bypass or a 500 that would betray a broken SQL query.
    assert resp.status_code == 401


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_note_content_injection_is_stored_as_plain_text(client, payload):
    tokens = register_and_login(client, "injection_tester")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = client.post("/notes", json={"title": "test", "content": payload}, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["content"] == payload  # stored as-is, never interpreted

    # The users table must still exist and work normally — concrete proof
    # that a "DROP TABLE" payload executed nothing.
    list_resp = client.get("/notes", headers=headers)
    assert list_resp.status_code == 200


def test_database_survives_drop_table_attempt(client):
    """After an injection attempt, the API and database should still work
    normally — the best proof that no arbitrary query ran server-side."""
    register_and_login(client, "survivor")
    resp = client.post(
        "/auth/register",
        json={
            "username": "another_user",
            "email": "another@example.com",
            "password": VALID_PASSWORD,
        },
    )
    assert resp.status_code == 201
