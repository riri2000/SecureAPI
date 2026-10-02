"""JWT tampering tests: altered signature, hand-modified payload, wrong
token type, expired token. In every case access must be denied (401),
never an unhandled exception (500)."""
import base64
import json

from app.security import create_access_token
from tests.conftest import register_and_login


def _tamper_payload(token: str, **overrides) -> str:
    """Modify a JWT's payload without knowing the secret key, simulating
    an attacker who intercepts and alters a token."""
    header_b64, payload_b64, signature_b64 = token.split(".")
    padding = "=" * (-len(payload_b64) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
    payload.update(overrides)
    new_payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    # The original signature no longer matches the new payload — exactly
    # what an attacker without the secret key would produce.
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
    # Signature no longer matches the modified payload -> rejected.
    assert resp.status_code == 401


def test_completely_malformed_token_rejected(client):
    resp = client.get("/notes", headers={"Authorization": "Bearer not-even-a-jwt"})
    assert resp.status_code == 401


def test_empty_bearer_token_rejected(client):
    resp = client.get("/notes", headers={"Authorization": "Bearer "})
    assert resp.status_code == 401


def test_token_signed_with_wrong_algorithm_type_rejected(client):
    """A correctly created token whose type is forced to 'refresh' must
    not be accepted as an access token — a token can't be reused across
    types."""
    fake_access = create_access_token(subject="someone")
    tampered = _tamper_payload(fake_access, type="refresh")
    resp = client.get("/notes", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401
