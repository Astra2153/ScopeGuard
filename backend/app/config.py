from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file="../.env", extra="ignore")

    database_url: str = "postgresql+psycopg://scopeguard:change_me_dev_only@127.0.0.1:5433/scopeguard"
    app_env: str = "development"
    session_hours: int = 8
    cookie_secure: bool = False  # set COOKIE_SECURE=true in .env once served over HTTPS
    rate_limit_enabled: bool = True
    master_key: str = ""  # base64 of 32 random bytes, from MASTER_KEY in .env
    # Lab mode lets the scanner reach loopback/private addresses (local practice apps).
    # It is honoured only when APP_ENV=development. Link-local and cloud-metadata
    # ranges stay blocked even in lab mode.
    allow_private_targets: bool = False


settings = Settings()
