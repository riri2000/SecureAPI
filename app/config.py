"""App configuration, loaded from environment variables. No secrets hardcoded."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    secret_key: str = "dev-only-insecure-key-do-not-use-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 15
    refresh_token_expire_days: int = 7

    database_url: str = "sqlite:///./secureapi.db"

    # Empty -> in-memory storage. Set a redis:// URI in production so the
    # rate limit is shared across instances.
    rate_limit_storage_uri: str = ""

    allowed_origins: str = "http://localhost:3000"

    @property
    def allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


settings = Settings()
