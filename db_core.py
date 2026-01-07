# db_core.py
import os
import sqlite3
from datetime import datetime, timezoneA

from flask import current_app, g
from werkzeug.security import generate_password_hash

import psycopg2
import psycopg2.extras


def row_get(row, key, default=None):
    """
    Works with:
    - sqlite3.Row (your local SQLite)
    - dict rows (Postgres RealDictCursor)
    - tuples/lists (fallback)
    """
    if row is None:
        return default

    # Postgres (RealDictCursor returns dict-like)
    if isinstance(row, dict):
        return row.get(key, default)

    # SQLite Row behaves like mapping
    try:
        return row[key]
    except Exception:
        pass

    # Fallback if row is tuple/list and key is int
    if isinstance(key, int) and isinstance(row, (tuple, list)) and 0 <= key < len(row):
        return row[key]

    return default

# ----------------------------
# Helpers
# ----------------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def using_postgres() -> bool:
    return bool(os.getenv("DATABASE_URL"))


def _sqlite_db_path() -> str:
    # Prefer Flask config, fallback to env var, fallback to app.db
    try:
        p = current_app.config.get("DATABASE")
        if p:
            return p
    except Exception:
        pass
    return os.path.abspath(os.getenv("DATABASE_PATH", "app.db"))


# ----------------------------
# DB Adapter (so your app can keep using db.execute/commit/close)
# ----------------------------
class DB:
    """
    Tiny adapter so the rest of your code can keep calling:
      db = get_db()
      db.execute(...)
      db.commit()
      db.close()

    It auto-converts:
      - SQLite placeholders '?' -> Postgres '%s'
      - INSERT OR IGNORE -> ON CONFLICT DO NOTHING (for your sections insert)
    """
    def __init__(self, kind: str, conn):
        self.kind = kind
        self.conn = conn

    def _fix_sql(self, sql: str) -> str:
        if self.kind == "postgres":
            # 1) placeholders
            sql = sql.replace("?", "%s")

            # 2) SQLite-only syntax you use for default sections
            if "INSERT OR IGNORE INTO sections" in sql:
                sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")
                sql = sql.strip().rstrip(";") + " ON CONFLICT (event_id, section_key) DO NOTHING"
        return sql

    def execute(self, sql: str, params=None):
        sql = self._fix_sql(sql)
        params = params or ()
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def _connect_sqlite() -> DB:
    path = _sqlite_db_path()
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return DB("sqlite", conn)


def _connect_postgres() -> DB:
    db_url = os.environ["DATABASE_URL"]

    # psycopg2 works with postgres:// or postgresql://
    # Use RealDictCursor so rows behave like dicts
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return DB("postgres", conn)


def get_db() -> DB:
    if not hasattr(g, "db") or g.db is None:
        g.db = _connect_postgres() if using_postgres() else _connect_sqlite()
    return g.db


def close_db(e=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
        g.db = None


# ----------------------------
# Schema creation
# ----------------------------
def _create_schema_sqlite(db: DB):
    # NOTE: SQLite uses INTEGER PRIMARY KEY AUTOINCREMENT
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT,
            start_time TEXT,
            end_time TEXT,
            created_by INTEGER,
            created_at TEXT NOT NULL,
            FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS rsvps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_email TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'going',
            created_at TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            section_content TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            UNIQUE(event_id, section_key),
            FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    db.commit()


def _create_schema_postgres(db: DB):
    # Postgres uses IDENTITY columns and proper types
    # Use IF NOT EXISTS so it can run multiple times safely
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT,
            start_time TEXT,
            end_time TEXT,
            created_by BIGINT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_events_user
                FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS rsvps (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            user_email TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'going',
            created_at TEXT NOT NULL,
            CONSTRAINT fk_rsvps_event
                FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS photos (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            filename TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            CONSTRAINT fk_photos_event
                FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS sections (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            section_key TEXT NOT NULL,
            section_title TEXT NOT NULL,
            section_content TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            CONSTRAINT uq_sections_event_key UNIQUE(event_id, section_key),
            CONSTRAINT fk_sections_event
                FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
        )
    """)

    db.commit()


def init_db():
    db = get_db()
    if db.kind == "postgres":
        _create_schema_postgres(db)
    else:
        _create_schema_sqlite(db)

    # After schema exists, ensure defaults
    ensure_default_admin()
    ensure_default_sections_for_all_events()


# ----------------------------
# Default admin + default sections
# ----------------------------
def ensure_default_admin():
    db = get_db()

    default_email = os.getenv("DEFAULT_ADMIN_EMAIL", "dehindeaba@gmail.com")
    default_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "Admin1234")

    # Check if exists
    cur = db.execute("SELECT id FROM users WHERE email=?", (default_email,))
    row = cur.fetchone()
    if row:
        return

    pwd_hash = generate_password_hash(default_password)
    db.execute(
        "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        (default_email, pwd_hash, "admin", now_iso())
    )
    db.commit()


def ensure_default_sections(event_id: int):
    """
    Adds basic sections for one event (if missing).
    Uses INSERT OR IGNORE (SQLite) which gets auto-converted for Postgres.
    """
    db = get_db()

    defaults = [
        ("agenda", "Agenda", ""),
        ("speakers", "Speakers", ""),
        ("notes", "Notes", "")
    ]

    for key, title, content in defaults:
        db.execute(
            "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (event_id, key, title, content, now_iso())
        )

    db.commit()


def ensure_default_sections_for_all_events():
    db = get_db()
    cur = db.execute("SELECT id FROM events", ())
    rows = cur.fetchall() or []
    for r in rows:
        # sqlite row is Row; postgres row is dict (RealDictCursor)
        event_id = r["id"] if isinstance(r, dict) else r["id"]
        ensure_default_sections(int(event_id))


# ----------------------------
# Flask integration
# ----------------------------
def init_app(app):
    # optional: let you override SQLite file via config
    app.config.setdefault("DATABASE", os.path.abspath(os.getenv("DATABASE_PATH", "app.db")))

    app.teardown_appcontext(close_db)

    # Create schema + defaults at startup (safe because IF NOT EXISTS)
    with app.app_context():
        init_db()
