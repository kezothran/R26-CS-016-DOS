from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str
    jwt_secret: str
    jwt_expire_minutes: int = 480
    default_admin_email: str = "admin@soc.local"
    default_admin_password: str = "ChangeMe#2026"
    capture_window_secs: int = 5
    geoip_db_path: str | None = None  # optional path to a MaxMind GeoLite2-Country .mmdb file

    # Critical-incident alerting (app/notify.py) - all optional, degrades gracefully to a no-op
    # (with a one-time startup warning) if unset, same contract as geoip_db_path above.
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    alert_email_to: str | None = None  # comma-separated
    slack_webhook_url: str | None = None

    # Jira Cloud ticket integration (app/integrations/jira.py) - all four must be set, otherwise
    # tickets fall back to the simulated placeholder behaviour.
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
