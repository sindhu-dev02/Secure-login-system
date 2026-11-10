import sqlite3
import time

import bcrypt
from flask import current_app

import events
from db import get_db

LOCK_AFTER = 5            # consecutive failures
LOCK_SECONDS = 15 * 60

# bcrypt only looks at the first 72 bytes. Anything longer is rejected up front
# instead of being silently truncated.
MAX_PASSWORD_BYTES = 72

_dummy = None


def create_password_hash(passw):
    salt = bcrypt.gensalt(rounds=current_app.config["BCRYPT_ROUNDS"])
    return bcrypt.hashpw(passw.encode("utf-8"), salt).decode("utf-8")


def verify_hash_passw(passw, hash_passw):
    raw = passw.encode("utf-8")
    if len(raw) > MAX_PASSWORD_BYTES:
        return False
    return bcrypt.checkpw(raw, hash_passw.encode("utf-8"))


def _dummy_hash():
    global _dummy
    if _dummy is None:
        _dummy = create_password_hash("placeholder-never-matches")
    return _dummy


def get_by_id(user_id):
    return get_db().execute("SELECT * FROM user WHERE id = ?", (user_id,)).fetchone()


def get_by_name(name):
    return get_db().execute(
        "SELECT * FROM user WHERE name = ? COLLATE NOCASE", (name,)
    ).fetchone()


class DuplicateUser(Exception):
    pass


def register_user(name, passw, number_phone):
    if get_by_name(name):
        raise DuplicateUser(name)
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO user (name, passw, number_phone, created_at) "
            "VALUES (?, ?, ?, datetime('now'))",
            (name, create_password_hash(passw), number_phone),
        )
    except sqlite3.IntegrityError:
        raise DuplicateUser(name)
    conn.commit()
    return cur.lastrowid


def is_locked(user):
    return bool(user["locked_until"]) and user["locked_until"] > time.time()


def record_failure(user_id, kind="password_failed"):
    """Count a failed attempt; lock the account once the limit is hit.

    `kind` is the event type to log. Returns True if this failure locked the account.
    """
    events.record(user_id, kind)
    conn = get_db()
    conn.execute(
        "UPDATE user SET failed_attempts = failed_attempts + 1 WHERE id = ?", (user_id,)
    )
    count = conn.execute(
        "SELECT failed_attempts FROM user WHERE id = ?", (user_id,)
    ).fetchone()[0]
    locked = count >= LOCK_AFTER
    if locked:
        conn.execute(
            "UPDATE user SET failed_attempts = 0, locked_until = ? WHERE id = ?",
            (int(time.time()) + LOCK_SECONDS, user_id),
        )
    conn.commit()
    if locked:
        events.record(user_id, "locked")
    return locked


def set_password(user_id, new_password):
    """Store a new password and sign the account out everywhere.

    Sessions are cookies, so they can't be deleted server-side. Instead each
    one remembers the epoch it was issued under; bumping it here makes every
    older cookie stop matching. Returns the new epoch so the caller can keep
    its own session alive.
    """
    conn = get_db()
    conn.execute(
        "UPDATE user SET passw = ?, session_epoch = session_epoch + 1, "
        "failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (create_password_hash(new_password), user_id),
    )
    conn.commit()
    return conn.execute(
        "SELECT session_epoch FROM user WHERE id = ?", (user_id,)
    ).fetchone()[0]


def clear_failures(user_id):
    conn = get_db()
    conn.execute(
        "UPDATE user SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,)
    )
    conn.commit()


def verify_user(name, passw):
    """Return the user row if the credentials are right, otherwise None.

    A hash is checked even when the username doesn't exist, so response time
    doesn't reveal which usernames are registered. A locked account is refused
    even with the right password, and failed guesses keep counting toward the
    lock. Failures are only cleared once the whole login (password and code)
    has succeeded; see clear_failures().
    """
    user = get_by_name(name)
    stored = user["passw"] if user else _dummy_hash()
    matches = verify_hash_passw(passw, stored)
    if user is None or is_locked(user):
        return None
    if not matches:
        record_failure(user["id"])
        return None
    return user
