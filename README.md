# SecureAPI

API REST (FastAPI) construite pour démontrer, de façon concrète et testée, des mitigations contre les vulnérabilités les plus courantes de l'[OWASP Top 10](https://owasp.org/www-project-top-ten/). Plutôt qu'une simple liste de bonnes pratiques, chaque protection est accompagnée d'un test qui tente activement de la contourner.

## Pourquoi ce projet

La plupart des démonstrations de sécurité se contentent de dire "on valide les entrées" ou "on utilise JWT". Ici, chaque mitigation est accompagnée d'un test qui essaie concrètement de la casser : injection SQL envoyée dans les champs de connexion et de création de note, JWT altéré à la main sans la clé secrète, dépassement volontaire du rate limit. Le but est de prouver que la protection tient, pas seulement de l'affirmer.

## Fonctionnalités

- **Authentification** : inscription, connexion, rafraîchissement et déconnexion, avec JWT à courte durée de vie (15 min) et refresh tokens à rotation (chaque utilisation invalide l'ancien token).
- **Rate limiting** : `/auth/login` limité à 5 tentatives/minute par adresse IP pour ralentir le brute-force.
- **Validation stricte des entrées** (Pydantic) : nom d'utilisateur, mot de passe et contenu des notes sont validés avant même d'atteindre la base de données.
- **Protection contre l'IDOR** : chaque utilisateur ne peut voir ou modifier que ses propres notes.
- **Headers de sécurité HTTP** : CSP, X-Frame-Options, HSTS, etc.
- **Scan de vulnérabilités automatisé** en CI (Bandit pour le code, Safety pour les dépendances).

## Stack technique

Python 3.12, FastAPI, SQLAlchemy (SQLite par défaut), Pydantic v2, python-jose (JWT), passlib/bcrypt, slowapi (rate limiting).

## Démarrage rapide

```bash
python -m venv venv
source venv/bin/activate  # Windows : venv\Scripts\activate

pip install -r requirements-dev.txt
cp .env.example .env      # ajuster SECRET_KEY avant tout usage réel

uvicorn app.main:app --reload
```

L'API est alors disponible sur `http://localhost:8000`, avec documentation interactive sur `http://localhost:8000/docs`.

## Lancer les tests

```bash
pytest -v
```

33 tests, dont 15 tests d'attaque (`tests/test_injection_attacks.py`, `tests/test_jwt_tampering.py`, `tests/test_xss_validation.py`, `tests/test_rate_limit.py`) qui tentent activement de contourner chaque protection plutôt que de simplement vérifier le "happy path".

## Scan de sécurité

```bash
bandit -r app/ -ll
safety check -r requirements.txt
```

Les deux sont aussi exécutés automatiquement en CI (`.github/workflows/ci.yml`) à chaque push.

## Structure du projet

```
app/
├── main.py           # Point d'entrée, middlewares, headers de sécurité
├── config.py          # Configuration via variables d'environnement
├── database.py         # Connexion SQLAlchemy
├── models.py           # Modèles de données (User, RefreshToken, Note)
├── schemas.py           # Validation Pydantic des entrées/sorties
├── security.py          # Hachage de mots de passe, génération/validation JWT
├── auth.py              # Dépendance get_current_user (extraction du JWT)
├── rate_limit.py          # Configuration du rate limiter
└── routers/
    ├── auth.py            # /auth/register, /login, /refresh, /logout
    └── notes.py            # CRUD de notes (ressource protégée de démonstration)

tests/
├── test_auth.py                 # Parcours d'authentification standard
├── test_injection_attacks.py     # Tentatives d'injection SQL
├── test_jwt_tampering.py          # Falsification de tokens
├── test_xss_validation.py          # Payloads XSS et validation d'entrées
└── test_rate_limit.py               # Dépassement volontaire du rate limit
```

Voir [SECURITY.md](./SECURITY.md) pour le détail des mitigations et des choix de conception.

## Limites connues

Ce projet est une démonstration pédagogique, pas un déploiement en production. En particulier :
- Le rate limiting en mémoire ne fonctionne que sur une seule instance ; une vraie mise en production derrière un load balancer nécessiterait Redis (`RATE_LIMIT_STORAGE_URI`).
- Pas de confirmation d'email à l'inscription.
- Pas de limite de tentatives de connexion par compte (seulement par IP).
