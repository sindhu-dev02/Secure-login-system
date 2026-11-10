import hmac
import secrets
import time

import requests
from twilio.base.exceptions import TwilioException
from twilio.rest import Client


class SMSError(Exception):
    """A code could not be sent. The message is safe to show to the user."""


class ConsoleVerifier:
    """Development backend: prints the code to the terminal instead of texting it."""

    TTL = 10 * 60
    MAX_TRIES = 5

    def __init__(self):
        self._pending = {}

    def start(self, phone):
        if not phone:
            raise SMSError("There is no phone number on file for this account.")
        code = f"{secrets.randbelow(10**6):06d}"
        self._pending[phone] = [code, time.time() + self.TTL, 0]
        print(f"[sms:console] code for {phone}: {code}", flush=True)

    def check(self, phone, code):
        entry = self._pending.get(phone)
        if entry is None:
            return False
        expected, expires, tries = entry
        if time.time() > expires or tries >= self.MAX_TRIES:
            del self._pending[phone]
            return False
        entry[2] += 1
        if hmac.compare_digest(expected.encode(), code.encode()):
            del self._pending[phone]
            return True
        return False


class TwilioVerifier:
    def __init__(self, account_sid, auth_token, service_sid):
        self._service = Client(account_sid, auth_token).verify.v2.services(service_sid)

    def start(self, phone):
        if not phone:
            raise SMSError("There is no phone number on file for this account.")
        try:
            self._service.verifications.create(to=phone, channel="sms")
        except (TwilioException, requests.RequestException):
            raise SMSError("Couldn't send a code to that number. Try again in a minute.")

    def check(self, phone, code):
        try:
            result = self._service.verification_checks.create(to=phone, code=code)
        except (TwilioException, requests.RequestException):
            return False
        return result.status == "approved"


def build_verifier(cfg):
    if cfg.get("VERIFIER") is not None:
        return cfg["VERIFIER"]

    backend = cfg["SMS_BACKEND"]
    if backend == "console":
        return ConsoleVerifier()
    if backend == "twilio":
        keys = ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_VERIFY_SERVICE_SID")
        missing = [k for k in keys if not cfg.get(k)]
        if missing:
            raise RuntimeError("SMS_BACKEND=twilio but not set: " + ", ".join(missing))
        return TwilioVerifier(*(cfg[k] for k in keys))
    raise RuntimeError(f"Unknown SMS_BACKEND {backend!r} (use 'twilio' or 'console')")
