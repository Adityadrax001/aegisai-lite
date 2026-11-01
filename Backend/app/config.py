from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AegisAI-Lite"
    app_env: str = "development"
    database_url: str = "postgresql+psycopg://aegis:aegis_local_dev_only@localhost:5432/aegisai"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
