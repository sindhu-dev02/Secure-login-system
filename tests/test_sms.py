import pytest
from twilio.base.exceptions import TwilioRestException

import sms


class FakeService:
    """Mimics client.verify.v2.services(sid) closely enough to see how it is called."""

    def __init__(self, status="approved", raises=None):
        self.calls = []
        self.status = status
        self.raises = raises
        self.verifications = self
        self.verification_checks = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.raises:
            raise self.raises
        return type("Result", (), {"status": self.status})()


def build(monkeypatch, service):
    class FakeClient:
        def __init__(self, *_):
            self.verify = type("V", (), {"v2": type("V2", (), {"services": lambda _self, _sid: service})()})()

    monkeypatch.setattr(sms, "Client", FakeClient)
    return sms.TwilioVerifier("AC_test", "token", "VA_test")


def test_start_asks_twilio_to_text_the_number(monkeypatch):
    service = FakeService()
    build(monkeypatch, service).start("+15551234567")
    assert service.calls == [{"to": "+15551234567", "channel": "sms"}]


def test_check_uses_a_verification_check_not_a_new_verification(monkeypatch):
    # The original /twofactor route created a fresh verification here, so a code
    # could never be approved.
    service = FakeService(status="approved")
    assert build(monkeypatch, service).check("+15551234567", "123456") is True
    assert service.calls == [{"to": "+15551234567", "code": "123456"}]


def test_pending_status_is_not_a_pass(monkeypatch):
    assert build(monkeypatch, FakeService(status="pending")).check("+1555", "000000") is False


def test_twilio_errors_become_friendly_failures(monkeypatch):
    error = TwilioRestException(status=429, uri="/Verifications", msg="rate limited")
    verifier = build(monkeypatch, FakeService(raises=error))
    with pytest.raises(sms.SMSError):
        verifier.start("+15551234567")
    assert verifier.check("+15551234567", "123456") is False


def test_console_backend_is_single_use_and_limited():
    verifier = sms.ConsoleVerifier()
    verifier.start("+15551234567")
    code = verifier._pending["+15551234567"][0]
    assert verifier.check("+15551234567", "not-it") is False
    assert verifier.check("+15551234567", code) is True
    assert verifier.check("+15551234567", code) is False          # already used

    verifier.start("+15551234567")
    for _ in range(sms.ConsoleVerifier.MAX_TRIES):
        verifier.check("+15551234567", "000000")
    assert verifier.check("+15551234567", verifier._pending.get("+15551234567", ["x"])[0]) is False


def test_twilio_backend_needs_all_three_settings():
    cfg = {"SMS_BACKEND": "twilio", "TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "",
           "TWILIO_VERIFY_SERVICE_SID": ""}
    with pytest.raises(RuntimeError, match="TWILIO_AUTH_TOKEN"):
        sms.build_verifier(cfg)
