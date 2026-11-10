import re

from conftest import NAME, PASSWORD, PHONE


def test_post_without_a_csrf_token_is_refused(app):
    client = app.test_client()
    client.get("/login")
    r = client.post("/login", data={"username": NAME, "password": PASSWORD})
    assert r.status_code == 403


def test_post_with_someone_elses_token_is_refused(app):
    victim, attacker = app.test_client(), app.test_client()
    page = attacker.get("/login").data.decode()
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    victim.get("/login")
    r = victim.post("/login", data={"csrf_token": token, "username": NAME, "password": PASSWORD})
    assert r.status_code == 403


def test_every_form_carries_a_token(browser):
    browser.register()
    browser.sign_in()
    for path in ("/dashboard", "/account/password"):
        assert 'name="csrf_token"' in browser.get(path).data.decode()


def test_logout_is_post_only(browser):
    browser.register()
    browser.sign_in()
    assert browser.get("/logout").status_code == 405
    assert browser.get("/dashboard").status_code == 200


def test_security_headers(browser):
    r = browser.get("/login")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in r.headers["Content-Security-Policy"]
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"
    assert "Strict-Transport-Security" not in r.headers


def test_session_cookie_flags(browser):
    cookie = browser.get("/login").headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_secure_mode_uses_host_prefixed_cookie_and_hsts(make_app):
    app = make_app(SESSION_COOKIE_SECURE=True)
    r = app.test_client().get("/login", base_url="https://localhost")
    assert r.headers["Set-Cookie"].startswith("__Host-session=")
    assert "Secure" in r.headers["Set-Cookie"]
    assert "max-age" in r.headers["Strict-Transport-Security"]


def test_app_refuses_to_start_without_a_secret_key(make_app):
    import pytest
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        make_app(SECRET_KEY="")


def test_phone_number_is_masked_on_the_dashboard(browser):
    browser.register()
    browser.sign_in()
    body = browser.get("/dashboard").data.decode()
    assert PHONE not in body and PHONE[-4:] in body
