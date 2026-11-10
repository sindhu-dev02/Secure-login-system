import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _flag(name, default="0"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes")


SECRET_KEY = os.environ.get("SECRET_KEY", "")
SMS_BACKEND = os.environ.get("SMS_BACKEND", "console").strip().lower()

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_VERIFY_SERVICE_SID = os.environ.get("TWILIO_VERIFY_SERVICE_SID", "")

COOKIE_SECURE = _flag("COOKIE_SECURE")
DEBUG = _flag("FLASK_DEBUG")

# Same place the original app kept it (next to app.py), so existing accounts carry over.
DATABASE = os.environ.get("DATABASE", str(Path(__file__).resolve().parent / "register.db"))
