# db_core.py
"""Database core + schema management.

Supports BOTH:
- SQLite (local dev / small deployments)
- Postgres (Render / production)

Key design:
- Application code should call get_db() and use the returned adapter.
- Do NOT open sqlite3 connections directly elsewhere (e.g. utils_core).
"""

import os
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g
from werkzeug.security import generate_password_hash

import psycopg2
import psycopg2.extras


# ----------------------------
# Small helpers
# ----------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def using_postgres() -> bool:
    # Render typically provides DATABASE_URL.
    return bool((os.getenv("DATABASE_URL") or "").strip())


def _sqlite_db_path() -> str:
    """Prefer Flask config, fallback to env var, fallback to app.db."""
    try:
        p = current_app.config.get("DATABASE")
        if p:
            return p
    except Exception:
        pass

    return os.path.abspath((os.getenv("DATABASE_PATH") or "app.db").strip())


def row_get(row, key, default=None):
    """Works with sqlite3.Row and dict rows (psycopg2 RealDictCursor)."""
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


# ----------------------------
# DB Adapter
# ----------------------------

class DB:
    """Adapter so the rest of your code can keep doing:

      db = get_db()
      cur = db.execute(...)
      rows = cur.fetchall()
      db.commit()

    Also auto-converts:
      - SQLite placeholders '?' -> Postgres '%s'
      - SQLite 'INSERT OR IGNORE' -> Postgres 'ON CONFLICT DO NOTHING'
    """

    def __init__(self, kind: str, conn):
        self.kind = kind
        self.conn = conn

    def _fix_sql(self, sql: str) -> str:
        if self.kind != "postgres":
            return sql

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
        try:
            cur.execute(sql, params)
        except Exception:
            # Important for Postgres: once a statement fails, the transaction is aborted
            # until a rollback is issued. Roll back so the connection can be reused safely.
            try:
                self.conn.rollback()
            except Exception:
                pass
            raise
        return cur

    def rollback(self):
        try:
            self.conn.rollback()
        except Exception:
            pass

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def _connect_sqlite() -> DB:
    path = _sqlite_db_path()
    # check_same_thread False helps in some hosting environments
    conn = sqlite3.connect(path, detect_types=sqlite3.PARSE_DECLTYPES, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return DB("sqlite", conn)


def _connect_postgres() -> DB:
    db_url = os.environ["DATABASE_URL"].strip()
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
# Schema Introspection
# ----------------------------

def get_table_columns(db: DB, table_name: str) -> set[str]:
    """Return a set of column names for a table (SQLite or Postgres)."""
    cols: set[str] = set()

    if db.kind == "postgres":
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

    cur = db.execute(f"PRAGMA table_info({table_name})")
    rows = cur.fetchall() or []
    for r in rows:
        cols.add(r["name"] if isinstance(r, dict) else r[1])
    return cols


# ----------------------------
# Schema creation
# ----------------------------

def _create_schema_sqlite(db: DB):
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT UNIQUE NOT NULL,

            name TEXT NOT NULL,
            date_iso TEXT NOT NULL,
            location TEXT NOT NULL,
            description TEXT NOT NULL,

            passcode TEXT NOT NULL,
            owner_user_id INTEGER,

            cover_image TEXT DEFAULT '',
            created_at TEXT DEFAULT '',

            FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS sections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            section_key TEXT NOT NULL,

            title TEXT DEFAULT '',
            visible INTEGER DEFAULT 1,

            content TEXT DEFAULT '',
            draft_content TEXT DEFAULT '',

            image TEXT DEFAULT '',
            sort_order INTEGER DEFAULT 0,

            UNIQUE(event_id, section_key),
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_questions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            position INTEGER NOT NULL DEFAULT 1,
            question TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'main',
            type TEXT NOT NULL DEFAULT 'text',
            allow_multi INTEGER NOT NULL DEFAULT 0,
            options TEXT NOT NULL DEFAULT '[]',
            required INTEGER NOT NULL DEFAULT 1,
            show_if_question INTEGER,
            show_if_value TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS rsvp_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            user_id INTEGER,

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

            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS event_photos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            kind TEXT NOT NULL,
            file_name TEXT NOT NULL,
            uploader_user_id INTEGER,
            uploader_name TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE,
            FOREIGN KEY(uploader_user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS photos_day_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,
            token TEXT NOT NULL DEFAULT '',
            is_open INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_hash TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    # Optional helper tables (used by some older auth/utils code). Safe to keep.
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            otp_code TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        """
    )

    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            event TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL
        );
        """
    )

    # Invite Designer (template + QR placement + QR styling)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS invite_designer (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,

            template_image TEXT DEFAULT '',
            logo_image TEXT DEFAULT '',

            module_color TEXT DEFAULT '#000000',
            eye_border_color TEXT DEFAULT '#000000',
            eye_center_color TEXT DEFAULT '#000000',

            qr_size_px INTEGER DEFAULT 200,

            stage_width INTEGER DEFAULT 0,
            stage_height INTEGER DEFAULT 0,

            qr_x_pct REAL DEFAULT 0,
            qr_y_pct REAL DEFAULT 0,
            qr_w_pct REAL DEFAULT 0,

            created_at TEXT DEFAULT '',
            updated_at TEXT DEFAULT '',

            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    # Bulk generation jobs (local storage retention)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS invite_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES events(id) ON DELETE CASCADE
        );
        """
    )

    db.commit()


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
        CREATE TABLE IF NOT EXISTS otps (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            user_id BIGINT NOT NULL,
            otp_code TEXT NOT NULL,
            purpose TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            CONSTRAINT fk_otps_user
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
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

    # Invite Designer (template + QR placement + QR styling)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS invite_designer (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,

            template_image TEXT DEFAULT '',
            logo_image TEXT DEFAULT '',

            module_color TEXT DEFAULT '#000000',
            eye_border_color TEXT DEFAULT '#000000',
            eye_center_color TEXT DEFAULT '#000000',

            qr_size_px INTEGER DEFAULT 200,

            stage_width INTEGER DEFAULT 0,
            stage_height INTEGER DEFAULT 0,

            qr_x_pct DOUBLE PRECISION DEFAULT 0,
            qr_y_pct DOUBLE PRECISION DEFAULT 0,
            qr_w_pct DOUBLE PRECISION DEFAULT 0,

            created_at TEXT DEFAULT '',
            updated_at TEXT DEFAULT ''
        );
        """
    )

    # Bulk generation jobs (local storage retention)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS invite_jobs (
            id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
            event_id BIGINT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
            file_path TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );
        """
    )

    db.commit()


def init_db():
    db = get_db()
    if db.kind == "postgres":
        _create_schema_postgres(db)
    else:
        _create_schema_sqlite(db)

    ensure_default_admin()
    ensure_default_sections_for_all_events()


# ----------------------------
# Default admin
# ----------------------------

def ensure_default_admin():
    db = get_db()

    default_email = (os.getenv("DEFAULT_ADMIN_EMAIL") or "dehindeaba@gmail.com").strip()
    default_password = (os.getenv("DEFAULT_ADMIN_PASSWORD") or "Admin1234").strip()

    cur = db.execute("SELECT id FROM users WHERE email=?", (default_email,))
    row = cur.fetchone()
    if row:
        return

    pwd_hash = generate_password_hash(default_password)
    cols = get_table_columns(db, "users")

    if "is_verified" in cols and "failed_login_attempts" in cols:
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
    else:
        db.execute(
            "INSERT INTO users (email, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (default_email, pwd_hash, "admin", now_iso()),
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
    ("invite-designer", "Invite Designer", 95, ""),
]


def ensure_default_sections(event_id: int):
    """Insert default sections for the event if missing."""
    db = get_db()
    cols = get_table_columns(db, "sections")

    if "title" in cols and "content" in cols and "section_key" in cols:
        for (key, title, sort_order, initial_content) in DEFAULT_SECTIONS:
            # Invite Designer is locked by default; platform admin must enable it.
            visible = 0 if key == "invite-designer" else 1
            content = initial_content
            draft_content = initial_content
            image = ""

            db.execute(
                "INSERT OR IGNORE INTO sections "
                "(event_id, section_key, title, visible, content, draft_content, image, sort_order) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (int(event_id), key, title, visible, content, draft_content, image, int(sort_order)),
            )

        db.commit()
        return

    # Very old schema fallback
    for (key, title, _, initial_content) in DEFAULT_SECTIONS:
        if "created_at" in cols:
            db.execute(
                "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (int(event_id), key, title, initial_content, now_iso()),
            )
        else:
            db.execute(
                "INSERT OR IGNORE INTO sections (event_id, section_key, section_title, section_content) "
                "VALUES (?, ?, ?, ?)",
                (int(event_id), key, title, initial_content),
            )

    db.commit()


def ensure_default_sections_for_all_events():
    db = get_db()
    # If events table doesn't exist yet (first boot mid-deploy), just skip.
    try:
        cur = db.execute("SELECT id FROM events", ())
        rows = cur.fetchall() or []
    except Exception:
        return

    for r in rows:
        event_id = row_get(r, "id")
        if event_id is None:
            continue
        ensure_default_sections(int(event_id))


# ----------------------------
# Flask integration
# ----------------------------

def init_app(app):
    # Optional: override SQLite file via config
    app.config.setdefault("DATABASE", os.path.abspath((os.getenv("DATABASE_PATH") or "app.db").strip()))
    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()
