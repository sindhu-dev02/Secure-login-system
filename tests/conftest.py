import re

import pytest

import db
from app import create_app
from sms import SMSError

NAME = "ada_l"
PASSWORD = "analytical engine 1"
PHONE = "+15551234567"
CODE = "424242"


class FakeVerifier:
    """Stands in for Twilio: remembers who was texted, accepts one fixed code."""

    def __init__(self):
        self.sent = []
        self.broken = False

    def start(self, phone):
        if self.broken:
            raise SMSError("Couldn't send a code to that number. Try again in a minute.")
        self.sent.append(phone)

    def check(self, phone, code):
        return phone in self.sent and code == CODE


class Browser:
    """A test client that fetches the CSRF token the way a real page would."""

    def __init__(self, app):
        self.client = app.test_client()

    def get(self, path, **kwargs):
        return self.client.get(path, **kwargs)

    def post(self, path, data=None, page=None, **kwargs):
        html = self.client.get(page or path).data.decode()
        token = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
        return self.client.post(path, data={"csrf_token": token, **(data or {})}, **kwargs)

    def register(self, name=NAME, password=PASSWORD, phone=PHONE):
        return self.post(
            "/register",
            {"username": name, "password": password, "phone": phone},
            follow_redirects=True,
        )

    def password_step(self, name=NAME, password=PASSWORD):
        return self.post("/login", {"username": name, "password": password})

    def sign_in(self, name=NAME, password=PASSWORD, code=CODE):
        self.password_step(name, password)
        return self.post("/login/verify", {"code": code})


@pytest.fixture
def verifier():
    return FakeVerifier()


@pytest.fixture
def make_app(tmp_path, verifier):
    def factory(**overrides):
        settings = {
            "TESTING": True,
            "SECRET_KEY": "test-secret",
            "DATABASE": str(tmp_path / "test.db"),
            "BCRYPT_ROUNDS": 4,
            "VERIFIER": verifier,
        }
        settings.update(overrides)
        return create_app(settings)

    return factory


@pytest.fixture
def app(make_app):
    return make_app()


@pytest.fixture
def browser(app):
    return Browser(app)


@pytest.fixture
def new_browser(app):
    """Another device talking to the same app."""
    return lambda: Browser(app)


@pytest.fixture
def run_sql(app):
    def run(sql, params=()):
        with app.app_context():
            conn = db.get_db()
            conn.execute(sql, params)
            conn.commit()

    return run
