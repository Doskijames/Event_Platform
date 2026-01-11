# db_core.py
"""
Database core + schema management (POSTGRES ONLY).

Key design:
- Application code calls get_db() and uses the returned adapter.
- Keep SQLite-style placeholders (?) in the app code; DB adapter converts to %s.
- Convert "INSERT OR IGNORE" -> "INSERT ... ON CONFLICT DO NOTHING"
"""

import os
from datetime import datetime, timezone

from flask import g
from werkzeug.security import generate_password_hash

import psycopg2
import psycopg2.extras


# ----------------------------
# Small helpers
# ----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def row_get(row, key, default=None):
    """Works with dict rows (psycopg2 RealDictCursor) and fallback indexable rows."""
    if row is None:
        return default
    if isinstance(row, dict):
        v = row.get(key, default)
        return default if v is None else v
    try:
        v = row[key]
        return default if v is None else v
    except Exception:
        return default


def _require_database_url() -> str:
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    if not db_url:
        raise RuntimeError(
            "DATABASE_URL is required for Postgres-only mode. "
            "Set DATABASE_URL to your Postgres connection string."
        )
    return db_url


# ----------------------------
# DB Adapter
# ----------------------------

class DB:
    """
    Adapter so the rest of your code can keep doing:

      db = get_db()
      cur = db.execute(...)
      rows = cur.fetchall()
      db.commit()

    Auto-converts:
      - '?' placeholders -> '%s'
      - 'INSERT OR IGNORE INTO' -> 'INSERT INTO ... ON CONFLICT DO NOTHING'
    """

    def __init__(self, conn):
        self.kind = "postgres"
        self.conn = conn

    def _fix_sql(self, sql: str) -> str:
        # 1) placeholders
        sql = sql.replace("?", "%s")

        # 2) INSERT OR IGNORE
        if "INSERT OR IGNORE INTO" in sql:
            sql = sql.replace("INSERT OR IGNORE INTO", "INSERT INTO")
            sql = sql.strip().rstrip(";")
            sql += " ON CONFLICT DO NOTHING"

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


def _connect_postgres() -> DB:
    db_url = _require_database_url()
    # RealDictCursor returns dict rows, which your row_get supports
    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    return DB(conn)


def get_db() -> DB:
    if not hasattr(g, "db") or g.db is None:
        g.db = _connect_postgres()
    return g.db


def close_db(e=None):
    db = getattr(g, "db", None)
    if db is not None:
        db.close()
        g.db = None


# ----------------------------
# Schema Introspection
# ----------------------------

def get_table_columns(db: DB, table_name: str) -> set[str]:
    cols: set[str] = set()
    cur = db.execute(
        """
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name=%s
        """,
        (table_name,),
    )
    rows = cur.fetchall() or []
    for r in rows:
        cols.add(r["column_name"] if isinstance(r, dict) else r[0])
    return cols


# ----------------------------
# Schema creation (Postgres)
# ----------------------------

def _create_schema_postgres(db: DB):
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,

            role TEXT DEFAULT 'user',
            is_verified INTEGER DEFAULT 0,

            failed_login_attempts INTEGER DEFAULT 0,
            is_locked INTEGER DEFAULT 0,

            otp_hash TEXT DEFAULT '',
            otp_expires_at TEXT DEFAULT '',
            otp_purpose TEXT DEFAULT 'verify',

            created_at TEXT DEFAULT ''
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            slug TEXT UNIQUE NOT NULL,

            name TEXT NOT NULL,
            date_iso TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,

            passcode TEXT NOT NULL,
            owner_user_id BIGINT,

            cover_image TEXT DEFAULT '',
            created_at TEXT DEFAULT '',

            CONSTRAINT fk_events_owner
              FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sections (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            section_key TEXT NOT NULL,

            title TEXT DEFAULT '',
            visible INTEGER DEFAULT 1,

            content TEXT DEFAULT '',
            draft_content TEXT DEFAULT '',

            image TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,

            CONSTRAINT uq_sections_event_key UNIQUE(event_id, section_key),
            CONSTRAINT fk_sections_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_questions (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            position INTEGER NOT NULL DEFAULT 1,
            question TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'main',
            type TEXT NOT NULL DEFAULT 'text',
            allow_multi INTEGER NOT NULL DEFAULT 0,
            options TEXT NOT NULL DEFAULT '[]',
            required INTEGER NOT NULL DEFAULT 1,
            show_if_question BIGINT,
            show_if_value TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_rsvp_questions_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_responses (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            user_id BIGINT,

            first_name TEXT NOT NULL DEFAULT '',
            last_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            whatsapp TEXT NOT NULL DEFAULT '',

            whatsapp_opt_in INTEGER NOT NULL DEFAULT 0,
            whatsapp_opt_in_at TEXT NOT NULL DEFAULT '',
            whatsapp_opt_in_source TEXT NOT NULL DEFAULT '',
            whatsapp_consent_version TEXT NOT NULL DEFAULT 'v1',

            answers TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT '',

            CONSTRAINT fk_rsvp_responses_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            CONSTRAINT fk_rsvp_responses_user
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS event_photos (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL,
            kind TEXT NOT NULL,
            file_name TEXT NOT NULL,
            uploader_user_id BIGINT,
            uploader_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_event_photos_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            CONSTRAINT fk_event_photos_user
              FOREIGN KEY(uploader_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS photos_day_settings (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL UNIQUE,
            token TEXT NOT NULL DEFAULT '',
            is_open INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_photos_day_settings_event
              FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_password_reset_otps_user
              FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT,
            event TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT '',
            CONSTRAINT fk_audit_logs_user
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.commit()


def init_db():
    db = get_db()
    _create_schema_postgres(db)
    ensure_default_admin()
    ensure_default_sections_for_all_events()


# ----------------------------
# Default admin
# ----------------------------

def ensure_default_admin():
    db = get_db()

    default_email = (os.getenv("DEFAULT_ADMIN_EMAIL") or "dehindeaba@gmail.com").strip()
    default_password = (os.getenv("DEFAULT_ADMIN_PASSWORD") or "Admin1234").strip()

    row = db.execute("SELECT id FROM users WHERE email=?", (default_email,)).fetchone()
    if row:
        return

    pwd_hash = generate_password_hash(default_password)

    db.execute(
        """
        INSERT INTO users
          (email, password_hash, role, is_verified, failed_login_attempts, is_locked,
           otp_hash, otp_expires_at, otp_purpose, created_at)
        VALUES
          (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            default_email,
            pwd_hash,
            "admin",
            1,
            0,
            0,
            "",
            "",
            "verify",
            now_iso(),
        ),
    )
    db.commit()


# ----------------------------
# Default sections
# ----------------------------

DEFAULT_SECTIONS = [
    ("home", "Home", 10, ""),
    ("story", "Our Story", 20, ""),
    ("meet-couple", "Meet the Couple", 30, ""),
    ("proposal", "The Proposal", 40, ""),
    ("tidbits", "Tidbits", 50, "[]"),
    ("qa", "Q&A", 60, "[]"),
    ("rsvp", "RSVP", 70, ""),
    ("photos", "Photos", 80, ""),
    ("photos-day", "Photos of the Day", 90, ""),
]


def ensure_default_sections(event_id: int):
    db = get_db()
    for (key, title, sort_order, initial_content) in DEFAULT_SECTIONS:
        db.execute(
            "INSERT OR IGNORE INTO sections "
            "(event_id, section_key, title, visible, content, draft_content, image, sort_order) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (int(event_id), key, title, 1, initial_content, initial_content, "", int(sort_order)),
        )
    db.commit()


def ensure_default_sections_for_all_events():
    db = get_db()
    try:
        rows = db.execute("SELECT id FROM events", ()).fetchall() or []
    except Exception:
        return

    for r in rows:
        event_id = row_get(r, "id")
        if event_id is not None:
            ensure_default_sections(int(event_id))


# ----------------------------
# Flask integration
# ----------------------------

def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
