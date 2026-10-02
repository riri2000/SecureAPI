"""
Configuration centralisée, chargée depuis les variables d'environnement.
Aucun secret n'est codé en dur : c'est la première règle de base contre
l'exposition de données sensibles (OWASP A02 - Cryptographic Failures).
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = "dev-only-insecure-key-do-not-use-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    database_url: str = "sqlite:///./secureapi.db"

    # Vide -> stockage en mémoire (slowapi/limits). Mettre une URI redis://
    # en production pour que le rate limit soit partagé entre plusieurs
    # instances de l'API.
    rate_limit_storage_uri: str = ""

    allowed_origins: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


settings = Settings()
