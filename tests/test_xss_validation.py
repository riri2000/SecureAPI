"""XSS and input validation tests.

The API never renders HTML (it returns JSON), so a classic "reflected"
XSS doesn't apply here. The real risk for a REST API is stored XSS: a
malicious payload stored as-is and later returned to a frontend that
renders it unescaped. These tests verify that:
1. The payload is stored and returned exactly as sent (no server-side
   execution or transformation);
2. Pydantic validation rejects structurally invalid input (too long,
   empty) before it ever reaches the database.
"""
import pytest

from tests.conftest import register_and_login

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(document.cookie)",
    "<svg/onload=alert(1)>",
]


@pytest.mark.parametrize("payload", XSS_PAYLOADS)
def test_xss_payload_stored_as_literal_text(client, payload):
    tokens = register_and_login(client, "xss_tester")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = client.post("/notes", json={"title": "note", "content": payload}, headers=headers)
    assert resp.status_code == 201
    # Content comes back identical: neither executed nor silently altered.
    # Escaping on render is the consumer frontend's job (separate
    # concern), but the API itself should never trust what it stores.
    assert resp.json()["content"] == payload


def test_empty_note_content_rejected(client):
    tokens = register_and_login(client, "validator_tester")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    resp = client.post("/notes", json={"title": "note", "content": ""}, headers=headers)
    assert resp.status_code == 422


def test_oversized_note_content_rejected(client):
    tokens = register_and_login(client, "oversize_tester")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    resp = client.post(
        "/notes", json={"title": "note", "content": "A" * 10_001}, headers=headers
    )
    assert resp.status_code == 422


def test_weak_password_rejected_at_registration(client):
    resp = client.post(
        "/auth/register",
        json={"username": "weakpass", "email": "weak@example.com", "password": "123"},
    )
    assert resp.status_code == 422


def test_username_with_invalid_characters_rejected(client):
    resp = client.post(
        "/auth/register",
        json={
            "username": "<script>alert(1)</script>",
            "email": "hacker@example.com",
            "password": "Str0ngPassw0rd!",
        },
    )
    assert resp.status_code == 422
