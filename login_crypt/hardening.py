import hmac
import secrets

from flask import abort, current_app, request, session
from markupsafe import Markup

CSRF_FIELD = "csrf_token"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self'",
    "form-action 'self'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
])


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_input():
    return Markup('<input type="hidden" name="{}" value="{}">').format(
        CSRF_FIELD, csrf_token()
    )


def check_csrf():
    if request.method in SAFE_METHODS:
        return
    sent = request.form.get(CSRF_FIELD, "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent.encode(), expected.encode()):
        abort(403)


def add_headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if current_app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if request.endpoint != "static":
        # Account pages shouldn't be reachable from the back button after sign out.
        response.headers["Cache-Control"] = "no-store"
    return response


def init_app(app):
    app.before_request(check_csrf)
    app.after_request(add_headers)
    app.jinja_env.globals["csrf_input"] = csrf_input
