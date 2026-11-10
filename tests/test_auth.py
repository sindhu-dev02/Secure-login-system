import sqlite3

import bcrypt

from conftest import CODE, NAME, PASSWORD, PHONE


def text(response):
    return response.data.decode()


# --- registration ---------------------------------------------------------

def test_registration_rejects_weak_input_and_keeps_the_form(browser):
    r = browser.post("/register", {"username": "ada_l", "password": "short", "phone": "555"})
    body = text(r)
    assert r.status_code == 200
    assert "at least 10" in body and "country code" in body
    assert 'value="ada_l"' in body          # username survives the round trip


def test_usernames_are_unique_ignoring_case(browser):
    browser.register()
    r = browser.register(name=NAME.upper(), password="another long passphrase")
    assert "taken" in text(r)


def test_password_is_stored_as_a_bcrypt_hash(browser, app):
    browser.register()
    with sqlite3.connect(app.config["DATABASE"]) as conn:
        stored = conn.execute("SELECT passw FROM user").fetchone()[0]
    assert PASSWORD not in stored
    assert bcrypt.checkpw(PASSWORD.encode(), stored.encode())


# --- two-step login -------------------------------------------------------

def test_password_alone_does_not_log_you_in(browser, verifier):
    browser.register()
    r = browser.password_step()
    assert r.headers["Location"].endswith("/login/verify")
    assert verifier.sent == [PHONE]
    assert browser.get("/dashboard").status_code == 302


def test_password_and_code_log_you_in_then_out(browser):
    browser.register()
    r = browser.sign_in()
    assert r.headers["Location"].endswith("/dashboard")
    assert NAME in text(browser.get("/dashboard"))

    browser.post("/logout", page="/dashboard")
    assert browser.get("/dashboard").status_code == 302


def test_wrong_code_is_rejected(browser):
    browser.register()
    r = browser.sign_in(code="000000")
    assert r.status_code == 200 and "match" in text(r)
    assert browser.get("/dashboard").status_code == 302


def test_unknown_user_and_wrong_password_look_the_same(browser, verifier):
    browser.register()
    wrong = browser.password_step(password="not the password at all")
    unknown = browser.password_step(name="nobody_home")
    assert text(wrong).count("Wrong username or password") == 1
    assert text(wrong) == text(unknown).replace("nobody_home", NAME)
    assert verifier.sent == []


def test_sms_failure_is_reported_and_nothing_is_pending(browser, verifier):
    browser.register()
    verifier.broken = True
    r = browser.password_step()
    assert r.status_code == 200 and "Couldn" in text(r)
    assert browser.get("/login/verify").status_code == 302      # bounced to /login


def test_half_finished_login_expires(browser):
    browser.register()
    browser.password_step()
    with browser.client.session_transaction() as s:
        s["pending_at"] = 0
    r = browser.get("/login/verify", follow_redirects=True)
    assert "timed out" in text(r)


def test_resend_sends_another_code_and_is_limited(make_app, verifier):
    from conftest import Browser
    app = make_app(RATE_LIMITS={"login": (50, 60), "register": (50, 60), "verify": (50, 60),
                                "resend": (2, 60), "reset": (50, 60), "password": (50, 60)})
    b = Browser(app)
    b.register()
    b.password_step()
    for _ in range(3):
        b.post("/login/verify/resend", page="/login/verify")
    assert len(verifier.sent) == 3          # the login text plus two resends; the third resend is refused


# --- lockout --------------------------------------------------------------

def test_five_wrong_passwords_lock_the_account(browser, verifier, run_sql):
    browser.register()
    for _ in range(5):
        browser.password_step(password="guess guess guess")
    r = browser.password_step()                      # now the right password
    assert r.status_code == 200 and "Wrong username or password" in text(r)
    assert verifier.sent == []

    run_sql("UPDATE user SET locked_until = 1")      # pretend 15 minutes passed
    assert browser.password_step().headers["Location"].endswith("/login/verify")


def test_wrong_codes_count_toward_the_lock(browser):
    browser.register()
    browser.password_step()
    for _ in range(4):
        browser.post("/login/verify", {"code": "000000"})
    r = browser.post("/login/verify", {"code": "000000"}, follow_redirects=True)
    assert "locked" in text(r)
    assert browser.password_step().status_code == 200       # still refused, even with the right password


def test_success_resets_the_failure_count(browser, run_sql, app):
    browser.register()
    for _ in range(3):
        browser.password_step(password="guess guess guess")
    browser.sign_in()
    with sqlite3.connect(app.config["DATABASE"]) as conn:
        assert conn.execute("SELECT failed_attempts FROM user").fetchone()[0] == 0


# --- rate limiting --------------------------------------------------------

def test_login_requests_are_rate_limited(make_app):
    from conftest import Browser
    app = make_app(RATE_LIMITS={"login": (2, 60), "register": (50, 60), "verify": (50, 60),
                                "resend": (50, 60), "reset": (50, 60), "password": (50, 60)})
    b = Browser(app)
    statuses = [b.password_step(name="nobody_home").status_code for _ in range(4)]
    assert statuses == [200, 200, 429, 429]


# --- existing databases ---------------------------------------------------

def test_database_from_the_original_app_keeps_working(tmp_path, make_app, verifier):
    from conftest import Browser
    legacy = tmp_path / "legacy.db"
    with sqlite3.connect(legacy) as conn:
        conn.execute(
            "CREATE TABLE user (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "name TEXT, passw TEXT, number_phone VARCHAR)"
        )
        conn.execute(
            "INSERT INTO user (name, passw, number_phone) VALUES (?, ?, ?)",
            ("michele", bcrypt.hashpw(b"old password here", bcrypt.gensalt(4)).decode(), "+5511999990000"),
        )
    b = Browser(make_app(DATABASE=str(legacy)))
    b.password_step(name="Michele", password="old password here")
    r = b.post("/login/verify", {"code": CODE})
    assert r.headers["Location"].endswith("/dashboard")
