"""
Modèles SQLAlchemy. Notes de sécurité :
- Les mots de passe ne sont JAMAIS stockés en clair (hashed_password
  uniquement, voir security.py pour le hachage bcrypt).
- Les refresh tokens sont stockés sous forme de hash, jamais en clair,
  pour qu'une fuite de la base de données ne permette pas de rejouer
  les tokens directement (même logique que pour les mots de passe).
- owner_id sur Note permet de vérifier l'appartenance d'une ressource
  avant d'y donner accès (protection contre l'IDOR - Insecure Direct
  Object Reference, un classique de l'OWASP A01 - Broken Access Control).
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=utcnow)

    notes = relationship("Note", back_populates="owner", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String(255), unique=True, index=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=utcnow)

    user = relationship("User", back_populates="refresh_tokens")


class Note(Base):
    """Ressource protégée arbitraire, utilisée pour démontrer le contrôle d'accès."""
    __tablename__ = "notes"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow)

    owner = relationship("User", back_populates="notes")
