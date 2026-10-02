"""
Configuration SQLAlchemy. Toutes les requêtes passent par l'ORM avec des
paramètres liés (bind parameters) plutôt que par de la concaténation de
chaînes — c'est ce qui neutralise l'injection SQL (OWASP A03), voir
SECURITY.md pour un exemple concret du problème que ça évite.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
