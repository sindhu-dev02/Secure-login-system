import functools
import time
from datetime import timedelta

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

import config
import db
import events
import hardening
import ratelimit
import sms
import users
import validators

# How long a half-finished login (password accepted, code not yet entered) stays valid.
SECOND_FACTOR_WINDOW = 10 * 60
MAX_CODE_TRIES = 5


def mask_phone(phone):
    if not phone:
        return "no phone on file"
    return phone[:2] + "•" * max(len(phone) - 6, 0) + phone[-4:]


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.SECRET_KEY,
        DATABASE=config.DATABASE,
        SMS_BACKEND=config.SMS_BACKEND,
        TWILIO_ACCOUNT_SID=config.TWILIO_ACCOUNT_SID,
        TWILIO_AUTH_TOKEN=config.TWILIO_AUTH_TOKEN,
        TWILIO_VERIFY_SERVICE_SID=config.TWILIO_VERIFY_SERVICE_SID,
        BCRYPT_ROUNDS=12,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=config.COOKIE_SECURE,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        # name: (hits allowed, window in seconds)
        RATE_LIMITS={
            "login": (10, 60),
            "register": (10, 600),
            "verify": (10, 600),
            "resend": (3, 600),
            "reset": (5, 600),
            "password": (5, 600),
        },
    )
    if test_config:
        app.config.update(test_config)

    if not app.config["SECRET_KEY"]:
        raise RuntimeError(
            "SECRET_KEY is not set. Generate one with "
            "`python -c \"import secrets; print(secrets.token_hex(32))\"` "
            "and put it in .env"
        )

    if app.config["SESSION_COOKIE_SECURE"]:
        # The __Host- prefix makes browsers reject the cookie unless it is Secure,
        # scoped to the exact host and set from "/".
        app.config["SESSION_COOKIE_NAME"] = "__Host-session"

    hardening.init_app(app)
    db.init_app(app)
    verifier = sms.build_verifier(app.config)
    limiters = {
        name: ratelimit.RateLimiter(*args) for name, args in app.config["RATE_LIMITS"].items()
    }

    def throttled(bucket, key):
        if limiters[bucket].allow(key):
            return False
        flash("Too many requests. Wait a few minutes and try again.", "error")
        return True

    @app.before_request
    def load_user():
        uid = session.get("uid")
        g.user = users.get_by_id(uid) if uid else None
        if g.user is not None and session.get("epoch") != g.user["session_epoch"]:
            g.user = None  # password changed since this session was issued
        if uid and g.user is None:
            session.clear()

    def login_required(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                flash("Sign in to see that page.", "error")
                return redirect(url_for("login"))
            return view(*args, **kwargs)

        return wrapped

    def send_code(user):
        try:
            verifier.start(user["number_phone"])
        except sms.SMSError as exc:
            flash(str(exc), "error")
            return False
        return True

    def pending_user():
        uid = session.get("pending_uid")
        if not uid:
            return None
        if time.time() - session.get("pending_at", 0) > SECOND_FACTOR_WINDOW:
            session.clear()
            flash("That sign-in attempt timed out. Please start again.", "error")
            return None
        return users.get_by_id(uid)

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if g.user else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            if throttled("register", request.remote_addr):
                return render_template("register.html", form=request.form), 429
            name = request.form.get("username", "").strip()
            passw = request.form.get("password", "")
            phone = validators.normalize_phone(request.form.get("phone", ""))
            problems = validators.check_registration(name, passw, phone)
            if problems:
                for message in problems:
                    flash(message, "error")
            else:
                try:
                    new_id = users.register_user(name, passw, phone)
                except users.DuplicateUser:
                    flash("That username is taken.", "error")
                else:
                    events.record(new_id, "registered")
                    flash("Account created. Sign in to continue.", "ok")
                    return redirect(url_for("login"))
        return render_template("register.html", form=request.form)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            if throttled("login", request.remote_addr):
                return render_template("login.html", form=request.form), 429
            name = request.form.get("username", "").strip()
            passw = request.form.get("password", "")
            user = users.verify_user(name, passw)
            if user is None:
                # Same text whether the name is unknown, the password is wrong or
                # the account is locked, so the form doesn't confirm which names exist.
                flash(
                    "Wrong username or password. After 5 failed attempts an account "
                    "is locked for 15 minutes.",
                    "error",
                )
            elif send_code(user):
                session.clear()
                session["pending_uid"] = user["id"]
                session["pending_at"] = time.time()
                session["code_tries"] = 0
                return redirect(url_for("verify"))
            return render_template("login.html", form=request.form)
        return render_template("login.html", form=request.form)

    @app.route("/login/verify", methods=["GET", "POST"])
    def verify():
        user = pending_user()
        if user is None:
            return redirect(url_for("login"))
        if users.is_locked(user):
            session.clear()
            flash("This account is locked for a while after too many failed attempts.", "error")
            return redirect(url_for("login"))

        if request.method == "POST":
            if throttled("verify", request.remote_addr):
                return render_template("verify.html", phone=mask_phone(user["number_phone"])), 429
            code = request.form.get("code", "").strip()
            session["code_tries"] = session.get("code_tries", 0) + 1
            if verifier.check(user["number_phone"], code):
                users.clear_failures(user["id"])
                events.record(user["id"], "login")
                session.clear()
                session["uid"] = user["id"]
                session["epoch"] = user["session_epoch"]
                session.permanent = True
                return redirect(url_for("dashboard"))
            locked = users.record_failure(user["id"], "code_failed")
            if locked or session["code_tries"] >= MAX_CODE_TRIES:
                session.clear()
                flash(
                    "Too many wrong codes. "
                    + ("The account is locked for 15 minutes." if locked
                       else "Sign in again to get a new one."),
                    "error",
                )
                return redirect(url_for("login"))
            flash("That code didn't match.", "error")

        return render_template("verify.html", phone=mask_phone(user["number_phone"]))

    @app.route("/login/verify/resend", methods=["POST"])
    def resend():
        user = pending_user()
        if user is None:
            return redirect(url_for("login"))
        if throttled("resend", user["id"]):
            return redirect(url_for("verify"))
        if send_code(user):
            flash("A new code is on its way.", "ok")
        return redirect(url_for("verify"))

    @app.route("/account/password", methods=["GET", "POST"])
    @login_required
    def change_password():
        if request.method == "POST":
            if throttled("password", g.user["id"]):
                return render_template("change_password.html"), 429
            current = request.form.get("current", "")
            new = request.form.get("new", "")
            again = request.form.get("again", "")
            problem = validators.check_password(new, g.user["name"])
            if not users.verify_hash_passw(current, g.user["passw"]):
                if users.record_failure(g.user["id"], "current_password_failed"):
                    flash("Too many wrong passwords. The account is locked for 15 minutes.", "error")
                else:
                    flash("The current password is wrong.", "error")
            elif new != again:
                flash("The two new passwords don't match.", "error")
            elif new == current:
                flash("The new password is the same as the current one.", "error")
            elif problem:
                flash(problem, "error")
            else:
                session["epoch"] = users.set_password(g.user["id"], new)
                events.record(g.user["id"], "password_changed")
                flash("Password changed. Any other signed-in devices were signed out.", "ok")
                return redirect(url_for("dashboard"))
        return render_template("change_password.html")

    @app.route("/reset", methods=["GET", "POST"])
    def reset_request():
        if g.user:
            return redirect(url_for("dashboard"))
        if request.method == "POST":
            if throttled("reset", request.remote_addr):
                return render_template("reset_request.html"), 429
            name = request.form.get("username", "").strip()
            user = users.get_by_name(name) if name else None
            session.clear()
            session["reset_at"] = time.time()
            session["reset_tries"] = 0
            session["reset_uid"] = user["id"] if user else 0
            if user and not throttled("resend", user["id"]):
                try:
                    verifier.start(user["number_phone"])
                except sms.SMSError:
                    pass  # said nothing on purpose; see the message below
            # Identical reply for unknown names, so this page can't be used to
            # find out who has an account.
            flash("If that account exists, a code is on its way to its phone.", "ok")
            return redirect(url_for("reset_confirm"))
        return render_template("reset_request.html")

    @app.route("/reset/confirm", methods=["GET", "POST"])
    def reset_confirm():
        if "reset_at" not in session:
            return redirect(url_for("reset_request"))
        if time.time() - session["reset_at"] > SECOND_FACTOR_WINDOW:
            session.clear()
            flash("That reset timed out. Please start again.", "error")
            return redirect(url_for("reset_request"))

        if request.method == "POST":
            if throttled("verify", request.remote_addr):
                return render_template("reset_confirm.html"), 429
            user = users.get_by_id(session["reset_uid"]) if session["reset_uid"] else None
            code = request.form.get("code", "").strip()
            new = request.form.get("new", "")
            again = request.form.get("again", "")

            problem = validators.check_password(new, user["name"] if user else "")
            if new != again:
                problem = "The two passwords don't match."
            if problem:
                flash(problem, "error")  # checked first so a typo doesn't burn the code
                return render_template("reset_confirm.html")

            session["reset_tries"] += 1
            if user and verifier.check(user["number_phone"], code):
                users.set_password(user["id"], new)
                events.record(user["id"], "password_reset")
                session.clear()
                flash("Password changed. Sign in with the new one.", "ok")
                return redirect(url_for("login"))
            if session["reset_tries"] >= MAX_CODE_TRIES:
                session.clear()
                flash("Too many wrong codes. Start the reset again.", "error")
                return redirect(url_for("reset_request"))
            flash("That code wasn't accepted.", "error")
        return render_template("reset_confirm.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("Signed out.", "ok")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template(
            "dashboard.html",
            phone=mask_phone(g.user["number_phone"]),
            activity=events.recent(g.user["id"]),
        )

    @app.errorhandler(403)
    def forbidden(_exc):
        return render_template(
            "error.html",
            heading="That form has expired",
            detail="Reload the page and try again. If it keeps happening, check that cookies are enabled.",
        ), 403

    @app.errorhandler(404)
    def not_found(_exc):
        return render_template(
            "error.html", heading="Page not found", detail="There is nothing at this address."
        ), 404

    return app


if __name__ == "__main__":
    create_app().run(debug=config.DEBUG)
