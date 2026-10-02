"""
Test du rate limiting sur /auth/login. On dépasse volontairement la
limite (5/minute) pour vérifier qu'une réponse 429 (Too Many Requests)
finit par apparaître — la mitigation principale contre le brute-force
de mots de passe.
"""
from tests.conftest import VALID_PASSWORD


def test_login_rate_limit_blocks_excessive_attempts(client):
    client.post(
        "/auth/register",
        json={
            "username": "ratelimit_target",
            "email": "ratelimit@example.com",
            "password": VALID_PASSWORD,
        },
    )

    statuses = []
    for _ in range(10):
        resp = client.post(
            "/auth/login",
            json={"username": "ratelimit_target", "password": "WrongPassword1"},
        )
        statuses.append(resp.status_code)

    assert 429 in statuses, f"Aucune réponse 429 reçue sur 10 tentatives : {statuses}"
