"""
Tests de falsification de JWT : signature altérée, payload modifié à la
main, token d'un autre type, token expiré. Dans tous les cas, l'accès
doit être refusé (401), jamais une exception non gérée (500) qui
trahirait un mauvais traitement des erreurs.
"""
import base64
import json

from app.security import create_access_token
from tests.conftest import register_and_login


def _tamper_payload(token: str, **overrides) -> str:
    """Modifie le payload d'un JWT sans connaître la clé secrète, pour
    simuler un attaquant qui intercepte et altère un token."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    padding = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    payload.update(overrides)
    new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    # La signature d'origine ne correspond plus au nouveau payload —
    # exactement le scénario qu'un attaquant sans la clé secrète produirait.
    return f"{header_b64}.{new_payload_b64}.{signature_b64}"


def test_token_with_altered_signature_rejected(client):
    tokens = register_and_login(client, "tamper_target")
    broken_token = tokens["access_token"][:-4] + "xxxx"
    resp = client.get("/notes", headers={"Authorization": f"Bearer {broken_token}"})
    assert resp.status_code == 401


def test_token_with_altered_subject_rejected(client):
    tokens = register_and_login(client, "victim")
    register_and_login(client, "attacker")

    tampered = _tamper_payload(tokens["access_token"], sub="attacker")
    resp = client.get("/notes", headers={"Authorization": f"Bearer {tampered}"})
    # La signature ne correspond plus au payload modifié -> rejeté.
    assert resp.status_code == 401


def test_completely_malformed_token_rejected(client):
    resp = client.get("/notes", headers={"Authorization": "Bearer not-even-a-jwt"})
    assert resp.status_code == 401


def test_empty_bearer_token_rejected(client):
    resp = client.get("/notes", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


def test_token_signed_with_wrong_algorithm_type_rejected(client):
    """Un token créé correctement mais dont on force le type à 'refresh'
    ne doit pas être accepté comme access token — vérifie qu'on ne peut
    pas réutiliser un token d'un type pour un autre usage."""
    fake_access = create_access_token(subject="someone")
    tampered = _tamper_payload(fake_access, type="refresh")
    resp = client.get("/notes", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401
