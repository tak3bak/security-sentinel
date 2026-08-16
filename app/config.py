import os
from functools import lru_cache

try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
    class Settings(BaseSettings):
        app_env: str = "development"
        log_level: str = "INFO"
        database_url: str = "postgresql+asyncpg://sentinel:sentinel_secret@localhost:5432/sentinel_db"
        redis_url: str = "redis://localhost:6379/0"
        sentinel_api_key: str = "dev-sentinel-api-key"
        cors_origins: str = "http://localhost:10000"
        ollama_url: str = "http://localhost:11434"
        ollama_model: str = "qwen2.5-coder:7b"
        stripe_secret_key: str = ""
        stripe_webhook_secret: str = ""
        stripe_price_starter: str = "price_starter"
        stripe_price_pro: str = "price_pro"
        stripe_price_premium: str = "price_premium"
        wazuh_shared_secret: str = ""
        osint_timeout_seconds: int = 10
        max_event_bytes: int = 262144
        model_config = SettingsConfigDict(env_file=".env", extra="ignore")
except ImportError:
    class Settings:
        def __init__(self):
            self.app_env = os.getenv("APP_ENV", "development")
            self.log_level = os.getenv("LOG_LEVEL", "INFO")
            self.database_url = os.getenv("DATABASE_URL", "postgresql+asyncpg://sentinel:sentinel_secret@localhost:5432/sentinel_db")
            self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
            self.sentinel_api_key = os.getenv("SENTINEL_API_KEY", "dev-sentinel-api-key")
            self.cors_origins = os.getenv("CORS_ORIGINS", "http://localhost:10000")
            self.ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
            self.ollama_model = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
            self.stripe_secret_key = os.getenv("STRIPE_SECRET_KEY", "")
            self.stripe_webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET", "")
            self.stripe_price_starter = os.getenv("STRIPE_PRICE_STARTER", "price_starter")
            self.stripe_price_pro = os.getenv("STRIPE_PRICE_PRO", "price_pro")
            self.stripe_price_premium = os.getenv("STRIPE_PRICE_PREMIUM", "price_premium")
            self.wazuh_shared_secret = os.getenv("WAZUH_SHARED_SECRET", "")
            self.osint_timeout_seconds = int(os.getenv("OSINT_TIMEOUT_SECONDS", "10"))
            self.max_event_bytes = int(os.getenv("MAX_EVENT_BYTES", "262144"))

@lru_cache
def settings() -> Settings:
    return Settings()
