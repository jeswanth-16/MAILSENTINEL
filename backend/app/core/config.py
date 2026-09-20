from typing import List, Optional, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "MAILSENTINEL"
    PROJECT_DESCRIPTION: str = "AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "127.0.0.1"

    # Database & Persistence
    MAILSENTINEL_DB_PATH: str = "mailsentinel.db"

    # Threat Intelligence
    ABUSEIPDB_API_KEY: Optional[str] = None
    INTELLIGENCE_CACHE_TTL: int = 21600  # 6 hours in seconds

    # Security & Authentication
    SECRET_KEY: str = "mailsentinel_secure_jwt_secret_key_sih_2026_soc_defense_token"
    AUTH_SECRET_KEY: str = "mailsentinel_secure_jwt_secret_key_sih_2026_soc_defense_token"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    PASSWORD_MIN_LENGTH: int = 8
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_MINUTES: int = 15
    
    # Feature & Hardening Toggles
    RATE_LIMIT_ENABLED: bool = True
    ALLOW_DEMO_BLOCKCHAIN: bool = True
    ALLOW_TAMPER_SIMULATION: bool = True  # Can be disabled in hardened production mode
    REQUIRE_AUTH: bool = True

    # CORS configuration
    ALLOWED_ORIGINS: Union[str, List[str]] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return []

    # Logging
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
