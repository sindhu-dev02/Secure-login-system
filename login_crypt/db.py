import sqlite3
from contextlib import closing

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS user (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    passw        TEXT NOT NULL,
    number_phone TEXT,
    created_at   TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    INTEGER,
    session_epoch   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS event (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    ip      TEXT,
    at      TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS event_by_user ON event(user_id, id);
"""

# Columns added after the first release. Databases created by the original
# version of the app get these through _add_missing_columns().
LATER_COLUMNS = {
    "created_at": "TEXT",
    "failed_attempts": "INTEGER NOT NULL DEFAULT 0",
    "locked_until": "INTEGER",
    "session_epoch": "INTEGER NOT NULL DEFAULT 0",
}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def _add_missing_columns(conn):
    have = {row[1] for row in conn.execute("PRAGMA table_info(user)")}
    for column, decl in LATER_COLUMNS.items():
        if column not in have:
            conn.execute(f"ALTER TABLE user ADD COLUMN {column} {decl}")


def init_app(app):
    with closing(sqlite3.connect(app.config["DATABASE"])) as conn:
        conn.executescript(SCHEMA)
        _add_missing_columns(conn)
        try:
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS user_name_nocase "
                "ON user(name COLLATE NOCASE)"
            )
        except sqlite3.IntegrityError:
            # An old database that already has two accounts differing only by case.
            # register_user() still refuses new duplicates.
            pass
        conn.commit()
    app.teardown_appcontext(close_db)
