import re

from conftest import CODE, NAME, PASSWORD, PHONE

NEW = "a brand new passphrase 9"


def text(response):
    return response.data.decode()


# --- change password ------------------------------------------------------

def test_change_password_requires_login(browser):
    assert browser.get("/account/password").status_code == 302


def test_change_password_checks_the_current_one(browser):
    browser.register()
    browser.sign_in()
    r = browser.post("/account/password", {"current": "wrong", "new": NEW, "again": NEW})
    assert "current password is wrong" in text(r)


def test_change_password_applies_the_policy(browser):
    browser.register()
    browser.sign_in()
    cases = [
        (NEW, NEW + "x", "don"),          # mismatch ("don't match")
        (PASSWORD, PASSWORD, "same as the current"),
        ("short", "short", "at least 10"),
    ]
    for new, again, fragment in cases:
        r = browser.post("/account/password", {"current": PASSWORD, "new": new, "again": again})
        assert fragment in text(r)


def test_changing_the_password_signs_out_other_devices(browser, new_browser):
    browser.register()
    browser.sign_in()
    other = new_browser()
    other.sign_in()
    assert other.get("/dashboard").status_code == 200

    r = browser.post("/account/password", {"current": PASSWORD, "new": NEW, "again": NEW})
    assert r.headers["Location"].endswith("/dashboard")
    assert browser.get("/dashboard").status_code == 200       # this device stays in
    assert other.get("/dashboard").status_code == 302         # the other one is out

    fresh = new_browser()
    assert fresh.password_step(password=PASSWORD).status_code == 200          # old password is dead
    assert fresh.password_step(password=NEW).status_code == 302


# --- reset ----------------------------------------------------------------

def test_reset_by_sms(browser, new_browser, verifier):
    browser.register()
    stolen = new_browser()
    stolen.sign_in()                       # a device that is already signed in
    forgot = new_browser()                 # the owner, locked out and starting from scratch

    r = forgot.post("/reset", {"username": NAME.upper()})
    assert r.headers["Location"].endswith("/reset/confirm")
    assert len(verifier.sent) == 2                                    # sign-in code + reset code

    # wrong code is refused and leaves the password alone
    bad = forgot.post("/reset/confirm", {"code": "000000", "new": NEW, "again": NEW})
    assert bad.status_code == 200 and "accepted" in text(bad)
    assert forgot.password_step(password=PASSWORD).headers["Location"].endswith("/login/verify")

    fresh = new_browser()
    fresh.post("/reset", {"username": NAME})
    ok = fresh.post("/reset/confirm", {"code": CODE, "new": NEW, "again": NEW})
    assert ok.headers["Location"].endswith("/login")
    assert fresh.sign_in(password=NEW).headers["Location"].endswith("/dashboard")
    assert stolen.get("/dashboard").status_code == 302                # resetting signs everyone else out


def test_reset_policy_is_checked_before_the_code_is_spent(browser):
    browser.register()
    browser.post("/reset", {"username": NAME})
    r = browser.post("/reset/confirm", {"code": CODE, "new": "short", "again": "short"})
    assert "at least 10" in text(r)
    ok = browser.post("/reset/confirm", {"code": CODE, "new": NEW, "again": NEW})
    assert ok.headers["Location"].endswith("/login")


def test_reset_does_not_reveal_whether_a_user_exists(browser, new_browser, verifier):
    browser.register()
    real, ghost = new_browser(), new_browser()
    a = real.post("/reset", {"username": NAME}, follow_redirects=True)
    b = ghost.post("/reset", {"username": "nobody_home"}, follow_redirects=True)
    assert a.request.path == b.request.path == "/reset/confirm"
    without_token = lambda r: re.sub(r'name="csrf_token" value="[^"]+"', "", text(r))
    assert without_token(a) == without_token(b)       # same page, same message
    assert verifier.sent == [PHONE]       # only the real account was texted
    r = ghost.post("/reset/confirm", {"code": CODE, "new": NEW, "again": NEW})
    assert "accepted" in text(r)          # a ghost account can never succeed


def test_reset_clears_a_lockout(browser, run_sql):
    browser.register()
    for _ in range(5):
        browser.password_step(password="guess guess guess")
    browser.post("/reset", {"username": NAME})
    browser.post("/reset/confirm", {"code": CODE, "new": NEW, "again": NEW})
    assert browser.password_step(password=NEW).headers["Location"].endswith("/login/verify")


def test_five_wrong_reset_codes_end_the_attempt(browser):
    browser.register()
    browser.post("/reset", {"username": NAME})
    for _ in range(4):
        browser.post("/reset/confirm", {"code": "000000", "new": NEW, "again": NEW})
    r = browser.post("/reset/confirm", {"code": "000000", "new": NEW, "again": NEW}, follow_redirects=True)
    assert "Too many wrong codes" in text(r)
