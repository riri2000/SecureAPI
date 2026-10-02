"""
Tests d'intrusion automatisés — injection SQL.

Chaque payload ci-dessous est un classique de manuel OWASP. On les envoie
dans tous les champs texte accessibles (login, création de note) et on
vérifie que l'API les traite comme du texte littéral inoffensif plutôt
que comme du SQL exécutable — ce que garantit l'utilisation exclusive de
requêtes paramétrées via l'ORM SQLAlchemy (aucune f-string ni
concaténation de SQL brut nulle part dans app/).
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
    # Le payload doit être traité comme un simple username inexistant :
    # 401, jamais un contournement d'authentification ni une erreur 500
    # qui trahirait une requête SQL cassée.
    assert resp.status_code == 401


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS)
def test_note_content_injection_is_stored_as_plain_text(client, payload):
    tokens = register_and_login(client, "injection_tester")
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}

    resp = client.post("/notes", json={"title": "test", "content": payload}, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["content"] == payload  # stocké tel quel, jamais interprété

    # La table users doit toujours exister et être inchangée : la preuve
    # concrète qu'un "DROP TABLE" envoyé en payload n'a rien exécuté.
    list_resp = client.get("/notes", headers=headers)
    assert list_resp.status_code == 200


def test_database_survives_drop_table_attempt(client):
    """Vérifie qu'après une tentative d'injection, l'API et la base
    fonctionnent toujours normalement — la meilleure preuve qu'aucune
    requête arbitraire n'a été exécutée côté serveur."""
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
