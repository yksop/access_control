"""
Central configuration for the access control system.

All secrets and environment-specific values are read from environment
variables (loaded from a local .env file via python-dotenv). Nothing
sensitive is hardcoded here or committed to version control.

Copy `.env.example` to `.env` and fill in real values before running.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# --- InfluxDB ---
INFLUX_URL = os.getenv("INFLUX_URL", "http://localhost:8086")
INFLUX_TOKEN = os.getenv("INFLUX_TOKEN")
INFLUX_ORG = os.getenv("INFLUX_ORG", "Unitn")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "access_control")

# --- MQTT ---
MQTT_BROKER = os.getenv("MQTT_BROKER", "localhost")
MQTT_PORT = int(os.getenv("MQTT_PORT", "1883"))
MQTT_KEEPALIVE = int(os.getenv("MQTT_KEEPALIVE", "60"))
MQTT_CLIENT_ID = os.getenv("MQTT_CLIENT_ID", "access_control_backend")

MQTT_TOPICS = {
    "auth_request": "access/auth/request",
    "auth_response": "access/auth/response",
    "qr_generate_request": "access/qr/generate/request",
    "qr_generate_response": "access/qr/generate/response",
    "qr_validate_request": "access/qr/validate/request",
    "qr_validate_response": "access/qr/validate/response",
    "access_event": "access/event",
    "system_status": "access/system/status",
    "user_add_request": "access/user/add/request",
    "user_add_response": "access/user/add/response",
    "user_remove_request": "access/user/remove/request",
    "user_remove_response": "access/user/remove/response",
    "user_list_request": "access/user/list/request",
    "user_list_response": "access/user/list/response",
}

# --- QR / auth behaviour ---
TEMP_QR_LIFETIME_SECONDS = int(os.getenv("TEMP_QR_LIFETIME_SECONDS", "15"))
MAX_AUTH_ATTEMPTS = int(os.getenv("MAX_AUTH_ATTEMPTS", "3"))
AUTH_LOCKOUT_MINUTES = int(os.getenv("AUTH_LOCKOUT_MINUTES", "10"))

# --- Secrets (must be set in .env, no defaults on purpose) ---
MASTER_SECRET = os.getenv("MASTER_SECRET")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# --- Storage locations ---
QR_OUTPUT_DIR = os.getenv("QR_OUTPUT_DIR", "./temp_qr")
SNAPSHOT_DIR = os.getenv("SNAPSHOT_DIR", "./snapshots")


def validate_config():
    """Fail fast and loudly if required secrets are missing, instead of
    limping along with None values that surface as confusing errors later."""
    missing = [
        name
        for name in ("INFLUX_TOKEN", "MASTER_SECRET")
        if not globals().get(name)
    ]
    if missing:
        raise RuntimeError(
            "Missing required environment variables: "
            + ", ".join(missing)
            + ". Copy .env.example to .env and fill in real values."
        )
