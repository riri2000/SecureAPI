"""Rate limit test on /auth/login. We deliberately exceed the limit
(5/minute) to verify a 429 (Too Many Requests) eventually shows up —
the main mitigation against password brute-forcing."""
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

    assert 429 in statuses, f"No 429 received across 10 attempts: {statuses}"
