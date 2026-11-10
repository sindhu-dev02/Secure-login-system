from conftest import NAME, PASSWORD


def dashboard(browser):
    return browser.get("/dashboard").data.decode()


def test_activity_shows_failures_and_sign_ins(browser):
    browser.register()
    browser.password_step(password="guess guess guess")
    browser.sign_in()
    page = dashboard(browser)
    assert "Account created" in page
    assert "Wrong password" in page
    assert "Signed in" in page


def test_lock_and_password_change_are_recorded(browser):
    browser.register()
    for _ in range(5):
        browser.password_step(password="guess guess guess")
    assert browser.password_step().status_code == 200       # locked

    # clear the lock the way a reset would, then sign in and change the password
    browser.post("/reset", {"username": NAME})
    browser.post("/reset/confirm", {"code": "424242", "new": "a brand new passphrase 9", "again": "a brand new passphrase 9"})
    browser.sign_in(password="a brand new passphrase 9")
    browser.post(
        "/account/password",
        {"current": "a brand new passphrase 9", "new": "yet another phrase 77", "again": "yet another phrase 77"},
        page="/account/password",
    )
    page = dashboard(browser)
    assert "Locked after repeated failures" in page
    assert "Password reset by SMS" in page
    assert "Password changed" in page


def test_activity_is_per_user(browser, new_browser):
    browser.register()
    browser.password_step(password="guess guess guess")

    other = new_browser()
    other.register(name="grace_h", password="hopper compiles things", phone="+15557654321")
    other.sign_in(name="grace_h", password="hopper compiles things")
    assert "Wrong password" not in dashboard(other)


def test_event_history_is_capped(app, browser):
    import events
    browser.register()
    with app.test_request_context():
        for _ in range(events.KEEP_PER_USER + 25):
            events.record(1, "login")
        count = events.get_db().execute("SELECT COUNT(*) FROM event WHERE user_id = 1").fetchone()[0]
    assert count == events.KEEP_PER_USER
