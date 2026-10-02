"""
Routes d'authentification : /register, /login, /refresh, /logout.

/login est volontairement soumis à une limite de taux plus stricte que
le reste de l'API (voir décorateur @limiter.limit) pour ralentir les
attaques par brute-force sur les mots de passe (OWASP A07).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RefreshToken, User
from app.rate_limit import limiter
from app.schemas import Token, TokenRefreshRequest, UserCreate, UserLogin, UserOut
from app.security import (
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_token,
    refresh_token_expiry,
    verify_password,
)

router = APIRouter(prefix="/auth", tags=["auth"])


def _issue_token_pair(user: User, db: Session) -> Token:
    access_token = create_access_token(subject=user.username)
    refresh_token = generate_refresh_token()

    db.add(
        RefreshToken(
            token_hash=hash_token(refresh_token),
            user_id=user.id,
            expires_at=refresh_token_expiry(),
        )
    )
    db.commit()

    return Token(access_token=access_token, refresh_token=refresh_token)


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: UserCreate, db: Session = Depends(get_db)):
    # Réponse volontairement générique : on ne révèle jamais si c'est le
    # username ou l'email qui est déjà pris, pour éviter l'énumération de
    # comptes (OWASP A01/A07).
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Un compte avec ces informations existe déjà.",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=Token)
@limiter.limit("5/minute")
def login(request: Request, payload: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()

    # Message d'erreur identique que ce soit le username ou le mot de passe
    # qui soit faux : révéler lequel est correct facilite l'énumération de
    # comptes valides pour un attaquant.
    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Nom d'utilisateur ou mot de passe invalide.",
    )

    if not user or not verify_password(payload.password, user.hashed_password):
        raise invalid_credentials

    return _issue_token_pair(user, db)


@router.post("/refresh", response_model=Token)
def refresh(payload: TokenRefreshRequest, db: Session = Depends(get_db)):
    token_hash = hash_token(payload.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()

    invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Refresh token invalide ou expiré.",
    )

    if stored is None or stored.revoked:
        raise invalid

    expires_at = stored.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < datetime.now(timezone.utc):
        raise invalid

    # Rotation : l'ancien token est révoqué immédiatement, qu'il soit
    # réutilisé ou non. S'il l'est (signe possible de vol), la nouvelle
    # tentative avec l'ancien token échouera la prochaine fois.
    stored.revoked = True
    db.commit()

    user = db.query(User).filter(User.id == stored.user_id).first()
    if user is None:
        raise invalid

    return _issue_token_pair(user, db)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: TokenRefreshRequest, db: Session = Depends(get_db)):
    token_hash = hash_token(payload.refresh_token)
    stored = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if stored:
        stored.revoked = True
        db.commit()
    return None
