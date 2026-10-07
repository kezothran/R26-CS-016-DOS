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

    # Critical-incident SMS / WhatsApp via Twilio (app/notify.py). Optional - no-ops when unset.
    # alert_phone_to is comma-separated E.164 numbers (+9477...). twilio_from is the SMS-capable
    # Twilio number; twilio_whatsapp_from is e.g. "whatsapp:+14155238886" (the Twilio sandbox).
    twilio_account_sid: str | None = None
    twilio_auth_token: str | None = None
    twilio_from: str | None = None
    twilio_whatsapp_from: str | None = None
    alert_phone_to: str | None = None

    # Telegram bot alerts (free): token from @BotFather, chat id(s) comma-separated (a user, group or channel).
    telegram_bot_token: str | None = None
    telegram_chat_id: str | None = None

    # Free WhatsApp alerts via CallMeBot (https://www.callmebot.com/blog/free-api-whatsapp-messages/):
    # comma-separated "phone:apikey" pairs, e.g. "+94771234567:123456". Each person activates their own key.
    callmebot_recipients: str | None = None

    # Official WhatsApp via Meta's Cloud API (https://developers.facebook.com/docs/whatsapp/cloud-api).
    # meta_wa_to: comma-separated numbers in international format, digits only (e.g. 94771234567).
    # Business-initiated alerts must use an approved template - "hello_world" works out of the box on
    # the test number; a custom template with ONE body variable ({{1}}) can carry the alert text.
    meta_wa_token: str | None = None
    meta_wa_phone_number_id: str | None = None
    meta_wa_to: str | None = None
    meta_wa_template: str = "hello_world"
    meta_wa_template_lang: str = "en_US"
    meta_wa_api_version: str = "v21.0"
    # Per-severity alert templates: with META_WA_TEMPLATE_PREFIX=sentrix_alert the app sends the approved
    # template "<prefix>_<tier>" (e.g. sentrix_alert_critical) with 4 variables: attack type, source IPs,
    # impact score, and a recommended first action chosen by attack type. META_WA_WABA_ID is the WhatsApp
    # Business account id (used only to read template approval status).
    meta_wa_template_prefix: str | None = None
    meta_wa_waba_id: str | None = None

    # Scheduled summary email (app/summary.py): "off" | "daily" | "weekly". Needs the SMTP_* settings
    # and summary_email_to (comma-separated; falls back to alert_email_to). Sent at summary_hour UTC.
    summary_schedule: str = "off"
    summary_hour: int = 8
    summary_email_to: str | None = None

    # Cloud mode: set LOCAL_CAPTURE=false on a server that only receives traffic from agents (no
    # packet sniffing, no Administrator/root needed). Agents count as offline after AGENT_ONLINE_SECS.
    local_capture: bool = True
    agent_online_secs: int = 90
    agent_max_body_mb: int = 8

    # Public URL of the dashboard, used for "Open incident" buttons in alert emails.
    dashboard_url: str = "http://localhost:3000"

    # Name shown in 2FA authenticator apps and on PDF reports.
    app_name: str = "Sentrix SOC"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
