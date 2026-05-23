from pydantic_settings import BaseSettings
from pathlib import Path


class Settings(BaseSettings):
    APP_NAME: str = "PhishGuard AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    DATABASE_URL: str = "sqlite:///./phishguard.db"
    DATABASE_ECHO: bool = False

    MAX_EMAIL_SIZE_BYTES: int = 500_000  # 500 KB hard cap on input
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    ML_MODEL_PATH: str = str(Path(__file__).parent.parent / "ml_model.pkl")

    model_config = {"env_file": ".env"}


settings = Settings()
