"""
Cœur de la sécurité applicative : hachage des mots de passe et gestion
des JWT.

Choix clés :
- bcrypt pour le hachage des mots de passe (lent par conception, donc
  résistant au brute-force hors ligne — contrairement à un simple
  sha256, voir OWASP A02).
- Access token court (15 min par défaut) + refresh token long (7 jours),
  stocké côté serveur sous forme de hash pour permettre la révocation
  (déconnexion réelle, pas seulement "oublier le token côté client").
- Rotation de refresh token : chaque utilisation d'un refresh token le
  révoque et en émet un nouveau. Si un refresh token volé est rejoué
  après avoir déjà été utilisé par le vrai utilisateur, la rotation le
  rend invalide, ce qui limite la fenêtre d'exploitation d'un vol de
  token (voir OWASP A07 - Identification and Authentication Failures).
"""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
from passlib.context import CryptContext

from app.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode = {"sub": subject, "exp": expire, "type": "access"}
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> str | None:
    """Retourne le sujet (username) du token si valide, sinon None.

    Toute anomalie — signature invalide, token expiré, type incorrect,
    payload malformé — retourne None plutôt que de lever une exception
    non gérée : un tampering de token ne doit jamais faire planter l'API,
    juste être refusé (voir tests/test_jwt_tampering.py).
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        return None
    if payload.get("type") != "access":
        return None
    return payload.get("sub")


def generate_refresh_token() -> str:
    """Génère un token aléatoire cryptographiquement sûr (pas un JWT).

    Un refresh token opaque et stocké côté serveur (sous forme de hash)
    est plus facile à révoquer qu'un JWT auto-porteur, qui reste valide
    jusqu'à expiration même si on veut le tuer immédiatement.
    """
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """Hash simple (sha256) suffisant ici : contrairement à un mot de passe,
    un refresh token a une entropie très élevée (secrets.token_urlsafe),
    donc pas besoin d'un hachage lent type bcrypt pour se protéger du
    brute-force."""
    return hashlib.sha256(token.encode()).hexdigest()


def refresh_token_expiry() -> datetime:
    return datetime.now(timezone.utc) + timedelta(days=settings.refresh_token_expire_days)
