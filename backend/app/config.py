from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="../.env", extra="ignore")

    database_url: str = "postgresql+psycopg://scopeguard:change_me_dev_only@127.0.0.1:5433/scopeguard"
    app_env: str = "development"


settings = Settings()
