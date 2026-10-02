# Mitigations de sécurité — détail

Ce document explique, vulnérabilité par vulnérabilité, ce qui est implémenté et pourquoi, avec le test correspondant qui le prouve.

## A01 — Broken Access Control

**Risque** : un utilisateur accède ou modifie une ressource qui ne lui appartient pas (IDOR).

**Mitigation** : chaque note est associée à un `owner_id`. Toute lecture ou modification vérifie `note.owner_id == user.id` avant de répondre ; sinon, 404 — jamais 403, pour ne pas révéler qu'une ressource appartenant à quelqu'un d'autre existe (`app/routers/notes.py::_get_owned_note_or_404`).

**Test** : implicite dans `test_auth.py::test_protected_route_requires_token` ; à renforcer avec un test explicite "l'utilisateur B ne peut pas lire la note de l'utilisateur A" si le projet évolue.

## A02 — Cryptographic Failures

**Risque** : mots de passe en clair, secrets codés en dur, hachage faible.

**Mitigation** :
- Mots de passe hachés avec bcrypt (lent par conception, résistant au brute-force hors ligne) — jamais stockés en clair.
- Refresh tokens stockés sous forme de hash SHA-256, jamais en clair, pour qu'une fuite de base de données ne permette pas de les rejouer directement.
- `SECRET_KEY` chargée depuis l'environnement (`.env`), jamais codée en dur dans le code source.

## A03 — Injection

**Risque** : injection SQL via des champs texte non validés.

**Mitigation** : toutes les requêtes passent par l'ORM SQLAlchemy avec des paramètres liés — aucune f-string ni concaténation de SQL brut nulle part dans `app/`.

**Test** : `tests/test_injection_attacks.py` envoie 5 payloads SQL classiques (`' OR '1'='1`, `'; DROP TABLE users; --`, etc.) dans les champs de connexion et de création de note, et vérifie qu'ils sont traités comme du texte littéral inoffensif.

## A05 — Security Misconfiguration

**Risque** : headers HTTP manquants, CORS permissif (`*`).

**Mitigation** (`app/main.py`) :
- CORS restreint à une liste explicite d'origines (`ALLOWED_ORIGINS`), jamais un wildcard.
- Headers de sécurité sur chaque réponse : `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`.

## A07 — Identification and Authentication Failures

**Risque** : brute-force de mots de passe, vol et réutilisation de refresh tokens, énumération de comptes.

**Mitigation** :
- Rate limiting à 5 tentatives/minute sur `/auth/login`.
- Rotation des refresh tokens : chaque utilisation révoque l'ancien et en émet un nouveau. Un token volé et rejoué après usage légitime est donc automatiquement invalidé.
- Messages d'erreur génériques ("Nom d'utilisateur ou mot de passe invalide") qui ne révèlent jamais lequel des deux est incorrect, ni si un compte existe déjà lors de l'inscription.

**Test** : `tests/test_rate_limit.py` (dépassement volontaire de la limite), `tests/test_auth.py::test_refresh_token_rotation` (réutilisation d'un ancien refresh token rejetée).

## Falsification de JWT (hors classement direct OWASP, mais critique en pratique)

**Risque** : un attaquant modifie le payload d'un JWT intercepté (ex: changer `sub` pour usurper un autre utilisateur) sans connaître la clé secrète.

**Mitigation** : `python-jose` vérifie la signature à chaque décodage ; toute altération du payload invalide la signature et le token est rejeté (401), jamais une exception non gérée.

**Test** : `tests/test_jwt_tampering.py` modifie manuellement le payload d'un token valide (signature, sujet, type) et vérifie que l'accès est systématiquement refusé.

## XSS (stocké)

**Risque** : une API REST ne fait pas de rendu HTML, donc le XSS réfléchi classique ne s'applique pas directement. Le vrai risque est le XSS stocké : un payload malveillant conservé tel quel et un jour affiché sans échappement par un frontend consommateur.

**Mitigation** : l'API ne fait aucune transformation ni interprétation du contenu stocké — elle le retourne strictement tel quel en JSON. L'échappement à l'affichage reste la responsabilité du frontend consommateur (séparation des responsabilités), mais l'API ne fait jamais confiance à ce qu'elle stocke.

**Test** : `tests/test_xss_validation.py` vérifie que des payloads XSS classiques sont stockés et retournés identiques, sans exécution ni altération côté serveur.
