"""
Tests XSS et validation d'entrées.

L'API ne fait jamais de rendu HTML (elle retourne du JSON), donc un XSS
classique "réfléchi dans le navigateur" ne s'applique pas ici. Le vrai
risque côté API REST est le "stored XSS" : un payload malveillant stocké
tel quel et renvoyé un jour à un frontend qui l'afficherait sans
l'échapper. Ces tests vérifient que :
1. Le payload est stocké et retourné strictement tel quel (aucune
   exécution ni transformation côté serveur) ;
2. La validation Pydantic rejette les entrées structurellement invalides
   (trop longues, vides) avant même d'atteindre la base de données.
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
    # Le contenu revient identique : ni exécuté, ni altéré silencieusement.
    # C'est au frontend consommateur d'échapper à l'affichage (responsabilité
    # séparée), mais l'API elle-même ne doit jamais faire confiance à ce
    # qu'elle stocke.
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
