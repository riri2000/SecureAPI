# SecureAPI

A REST API (FastAPI) built to demonstrate, concretely and with tests, mitigations against the most common vulnerabilities in the [OWASP Top 10](https://owasp.org/www-project-top-ten/). Rather than just listing best practices, each protection comes with a test that actively tries to break it.

## Why this project

Most security demos just say "we validate input" or "we use JWT" and leave it at that. Here, every mitigation is paired with a test that concretely tries to defeat it: SQL injection sent into the login and note-creation fields, a hand-tampered JWT with no access to the secret key, a deliberate rate-limit overflow. The goal is to prove the protection holds, not just claim it.

## Features

- **Authentication**: register, login, refresh, and logout, with short-lived JWTs (15 min) and rotating refresh tokens (each use invalidates the previous one).
- **Rate limiting**: `/auth/login` capped at 5 attempts/minute per IP to slow down brute-forcing.
- **Strict input validation** (Pydantic): username, password, and note content are all validated before ever reaching the database.
- **IDOR protection**: each user can only see or modify their own notes.
- **HTTP security headers**: CSP, X-Frame-Options, HSTS, etc.
- **Automated vulnerability scanning** in CI (Bandit for code, Safety for dependencies).

## Stack

Python 3.12, FastAPI, SQLAlchemy (SQLite by default), Pydantic v2, python-jose (JWT), passlib/bcrypt, slowapi (rate limiting).

## Quick start

```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

pip install -r requirements-dev.txt
cp .env.example .env      # set a real SECRET_KEY before any real use

uvicorn app.main:app --reload
```

The API is then available at `http://localhost:8000`, with interactive docs at `http://localhost:8000/docs`.

## Running tests

```bash
pytest -v
```

33 tests, including 15 attack tests (`tests/test_injection_attacks.py`, `tests/test_jwt_tampering.py`, `tests/test_xss_validation.py`, `tests/test_rate_limit.py`) that actively try to defeat each protection rather than just checking the happy path.

## Security scanning

```bash
bandit -r app/ -ll
safety check -r requirements.txt
```

Both also run automatically in CI (`.github/workflows/ci.yml`) on every push.

## Project structure

```
app/
├── main.py           # Entrypoint, middleware, security headers
├── config.py          # Environment-based configuration
├── database.py         # SQLAlchemy connection
├── models.py           # Data models (User, RefreshToken, Note)
├── schemas.py           # Pydantic input/output validation
├── security.py          # Password hashing, JWT creation/validation
├── auth.py              # get_current_user dependency (JWT extraction)
├── rate_limit.py          # Rate limiter configuration
└── routers/
    ├── auth.py            # /auth/register, /login, /refresh, /logout
    └── notes.py            # Notes CRUD (sample protected resource)

tests/
├── test_auth.py                 # Standard auth flow
├── test_injection_attacks.py     # SQL injection attempts
├── test_jwt_tampering.py          # Token tampering
├── test_xss_validation.py          # XSS payloads and input validation
└── test_rate_limit.py               # Deliberate rate limit overflow
```

See [SECURITY.md](./SECURITY.md) for a detailed breakdown of each mitigation and design choice.

## Known limitations

This is a learning/demo project, not a production deployment. In particular:
- In-memory rate limiting only works on a single instance; a real production deployment behind a load balancer would need Redis (`RATE_LIMIT_STORAGE_URI`).
- No email confirmation on registration.
- No per-account login attempt limit (only per IP).
