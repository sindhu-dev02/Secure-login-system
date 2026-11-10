from flask import has_request_context, request

from db import get_db

KEEP_PER_USER = 200

LABELS = {
    "registered": "Account created",
    "login": "Signed in",
    "password_failed": "Wrong password",
    "code_failed": "Wrong SMS code",
    "current_password_failed": "Wrong current password (change attempt)",
    "locked": "Locked after repeated failures",
    "password_changed": "Password changed",
    "password_reset": "Password reset by SMS",
}


def record(user_id, kind):
    ip = request.remote_addr if has_request_context() else None
    conn = get_db()
    conn.execute("INSERT INTO event (user_id, kind, ip) VALUES (?, ?, ?)", (user_id, kind, ip))
    conn.execute(
        "DELETE FROM event WHERE user_id = ? AND id NOT IN "
        "(SELECT id FROM event WHERE user_id = ? ORDER BY id DESC LIMIT ?)",
        (user_id, user_id, KEEP_PER_USER),
    )
    conn.commit()


def recent(user_id, limit=10):
    rows = get_db().execute(
        "SELECT kind, ip, at FROM event WHERE user_id = ? ORDER BY id DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()
    return [
        {"what": LABELS.get(row["kind"], row["kind"]), "ip": row["ip"] or "-", "at": row["at"][:16] + " UTC"}
        for row in rows
    ]
